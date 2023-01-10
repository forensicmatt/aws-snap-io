use std::io::{Read, Write, Seek, SeekFrom};
use std::fs::File;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use serde_json::{from_str, to_string};
use snafu::{OptionExt, ResultExt, Snafu};
#[cfg(any(target_os = "windows"))]
use crate::sparse::win::{set_sparse_run, make_file_sparse};
#[cfg(any(target_os = "linux"))]
use crate::sparse::nix::set_sparse_run;

/// Module that handles sparse caching (if supported) so that blocks do
/// not have to be read more than once.


#[derive(Debug, Snafu)]
pub struct Error(error::Error);
type Result<T> = std::result::Result<T, Error>;


/// Ensure the parent of a path exists
fn ensure_parent(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    let parent = path.parent()
        .context(error::NoParentSnafu{path: path.to_path_buf()})?;

    if !parent.exists() {
        std::fs::create_dir_all(parent)
            .with_context(|_|error::IoSnafu{})?
    }

    Ok(())
}

/// Given the name of a cache, generate the name of the associated index 
/// file. This contains the blocks that are contained within the cache.
fn index_file_name(path: impl AsRef<Path>) -> PathBuf {
    let cache_name = path
        .as_ref()
        .to_path_buf();
    let mut name = cache_name
        .file_name()
        .unwrap()
        .to_os_string();
    name.push(".indx");
    let mut index_fn = cache_name;
    index_fn.set_file_name(name);
    index_fn
}


/// Load a hashset from an index file
fn load_index_file(path: impl AsRef<Path>) -> Result<HashSet<i32>> {
    let path = path.as_ref();
    if path.exists() {
        let meta = path.metadata()
            .with_context(|_|error::IoSnafu{})?;
        
        if meta.len() > 0 {
            let mut file = std::fs::File::open(path)
                .with_context(|_|error::IoSnafu{})?;

            let mut data = String::new();
            file.read_to_string(&mut data)
                .with_context(|_|error::IoSnafu{})?;

            // Load the index set from disk
            let hashset: HashSet<u32> = from_str(data.as_str())
                .context(error::JsonSnafu{})?;

            // Convert u32s to i32s (we should never have negative block index)
            let hashset = hashset.iter()
                .map(|v|v.to_owned().try_into().unwrap())
                .collect();
            
            return Ok(hashset);
        }
    }
    
    Ok(HashSet::new())
}


/// Write an index map to disk
fn write_index_file(path: impl AsRef<Path>, set: &HashSet<i32>) -> Result<()> {
    let mut file = std::fs::File::create(path)
        .with_context(|_| error::IoSnafu{})?;

    let buffer = to_string(&set)
        .with_context(|_|error::JsonSnafu{})?;

    file.write_all(buffer.as_bytes())
        .with_context(|_| error::IoSnafu{})?;

    Ok(())
}


/// Check if file is sparse
fn is_sparse_file(file: &File) -> Result<bool> {
    #[cfg(any(target_os = "windows"))]
    {
        use std::os::windows::fs::MetadataExt;
        let meta = file.metadata()
            .context(error::IoSnafu{})?;
        let attributes = meta.file_attributes();
        Ok(attributes & 0x200 == 0x200)
    }
    #[cfg(not(target_os = "windows"))]
    {
        error::UnimplementedSnafu{message: "Unhandled sparse check."}.fail()?
    }
}


/// Check if file is sparse
fn make_sparse_file(file: &mut File) -> Result<()> {
    #[cfg(any(target_os = "windows"))]
    {
        make_file_sparse(file)
            .context(error::WindowsCoreSnafu{})?;
        Ok(())
    }
    #[cfg(any(target_os = "linux"))]
    {
        // For linux, we do not need to specficly set the file as sparce like windows
        Ok(())
    }
}


/// Ensure that a file is set as sparse
fn ensure_sparse(file: &mut File) -> Result<bool> {
    #[cfg(any(target_os = "windows"))]
    {
        if !is_sparse_file(file)? {
            make_sparse_file(file)?;
            return Ok(true)
        }
    }

    Ok(false)
}


/// A disk cache is "perferably" a sparse file that allows snapshot blocks to be
/// writen to disk and is checked before trying to downloading a block. The cache
/// uses a i32 (data type that AWS uses to store a block index) index to determine
/// if a give block has already been downloaded. This index is commited to disk every
/// n number of writes (see .with_commit_frequency()).
pub struct DiskCache {
    /// A cache file will have an associated cache file with it.
    cache_location: PathBuf,
    cache_handle: File,
    index_map: HashSet<i32>,
    commit_frequency: u32,
    block_write_count: u64
}
impl DiskCache {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let mut cache = DiskCache::uninit_cache(path)?;
        cache.load()?;
        Ok(cache)
    }

    pub fn with_commit_frequency(mut self, commit_frequency: u32) -> Self {
        self.commit_frequency = commit_frequency;
        self
    }

    /// Given an index and the block size, read a block from the cache
    pub fn read_block(&mut self, index: i32, block_size: usize) -> Result<Option<Vec<u8>>> {
        if self.index_map.contains(&index) {
            let offset = block_size as u64 * index as u64;

            // Seek to block offset
            self.cache_handle.seek(SeekFrom::Start(offset))
                .with_context(|_|error::IoSnafu{})?;
            
            // Buffer for the block data
            let mut buffer = vec![0; block_size];

            // Read from cache
            self.cache_handle.read_exact(&mut buffer)
                .with_context(|_|error::IoSnafu{})?;

            Ok(Some(buffer))
        } else {
            Ok(None)
        }
    }

    /// Write a block to the cache. If we have seen this block, ignore it.
    /// Return false if it has not been seen before, true if it has
    pub fn write_block(&mut self, index: i32, block: &[u8]) -> Result<bool> {
        if self.index_map.insert(index) {
            let block_size = block.len();
            let offset = block_size as u64 * index as u64;

            self.cache_handle.seek(SeekFrom::Start(offset))
                .with_context(|_|error::IoSnafu{})?;

            self.cache_handle.write(block)
                .with_context(|_|error::IoSnafu{})?;

            self.cache_handle.flush()
                .with_context(|_|error::IoSnafu{})?;

            self.block_write_count += 1;

            if self.block_write_count % self.commit_frequency as u64 == 0 {
                self.commit()?;
            }
    
            return Ok(false);
        }

        Ok(true)
    }

    /// Get the index location for this cache
    pub fn index_file_location(&self) -> PathBuf {
        index_file_name(&self.cache_location)
    }

    /// Get size of the cache file
    pub fn size(&self) -> Result<u64> {
        let meta = self.cache_handle.metadata()
            .with_context(|_|error::IoSnafu{})?;
        Ok(meta.len())
    }

    /// Set the size of the cache file
    pub fn set_size(&mut self, length: i64) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            set_sparse_run(
                &mut self.cache_handle,
                0,
                length
            ).with_context(|_|error::WindowsCoreSnafu{})?;
            self.cache_handle.flush().with_context(|_|error::IoSnafu{})?;
            Ok(())
        }
        #[cfg(target_os = "linux")]
        {
            set_sparse_run(
                &mut self.cache_handle,
                0,
                length
            ).with_context(|_|error::SetSparseSnafu{})?;
            self.cache_handle.flush().with_context(|_|error::IoSnafu{})?;
            Ok(())
        }
    }

    /// Commit the index mapping to disk
    pub fn commit(&self) -> Result<()> {
        let index_path = self.index_file_location();
        write_index_file(
            index_path, 
            &self.index_map
        )?;
        Ok(())
    }

    /// Load the index mapping from disk
    fn load(&mut self) -> Result<()> {
        let cache_path = self.index_file_location();
        if cache_path.exists() {
            let index_map = load_index_file(&cache_path)?;
            self.index_map = index_map;
        }
        Ok(())
    }

    /// Create a DiskCache that is unitialized which means
    /// no index had been loaded.
    fn uninit_cache(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref()
            .to_path_buf();

        // Ensure that the parent folder exists, because if the file does not exist
        // we create it
        ensure_parent(&path)?;

        // Open or create cache file
        let mut cache_handle = File::options()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .context(error::IoSnafu{})?;
        
        // Ensure that the cache handle is sparse
        ensure_sparse(&mut cache_handle)?;
        
        let index_path = index_file_name(&path);
        let index_map = load_index_file(index_path)?;

        Ok( Self {
            cache_location: path,
            cache_handle,
            index_map,
            commit_frequency: 10,
            block_write_count: 0
        })
    }
}


pub mod error {
    use snafu::Snafu;
    use std::path::PathBuf;
    use serde_json::Error as JsonError;

    #[derive(Debug, Snafu)]
    #[snafu(visibility(pub(super)))]
    pub(super) enum Error {
        #[snafu(display("{:?}", source))]
        Io {
            source: std::io::Error
        },

        #[snafu(display("{:?}", source))]
        Json {
            source: JsonError
        },

        #[snafu(display("{}", message))]
        Unimplemented {
            message: String
        },

        #[cfg(target_os = "windows")]
        #[snafu(display("{:?}", source))]
        WindowsCore {
            source: windows::core::Error
        },

        #[snafu(display("Unable to set sparse: {:?}", source))]
        SetSparse {
            source: std::io::Error
        },

        #[snafu(display("Path does not return a parent! {}", path.to_string_lossy()))]
        NoParent {
            path: PathBuf
        },
    }
}


#[cfg(test)]
mod test {
    use crate::cache::*;

    #[test]
    fn test_index_file_name() {
        let cache_name = "./this/is/a/cache";
        let index_name = index_file_name(cache_name);
        assert_eq!(Path::new("./this/is/a/cache.indx"), index_name);
    }

    #[test]
    fn test_cache_001() {
        let cache = "./cache/cache_test_001";
        let mut dc = DiskCache::from_path(cache)
            .expect("Could not create DiskCache");
            
        let block = vec![0xff_u8; 4096];
        dc.write_block(10, &block)
            .expect("Error writing block to cache!");

        dc.write_block(80, &block)
            .expect("Error writing block to cache!");

        let cached_block = dc.read_block(10, 4096)
            .expect("Invalid block size.")
            .expect("No cached data was found!");
        
        assert_eq!(block, cached_block);
        
        dc.commit()
            .expect("Error commiting DiskCache to disk.");
    }
}