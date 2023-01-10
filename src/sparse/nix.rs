use std::fs::File;
use std::io::{Seek, SeekFrom, Write};


/// Initialize a sparse data run
pub fn set_sparse_run(file: &mut File, offset: i64, length: i64) -> Result<(), std::io::Error> {
    // In linux all you need to do is seek to the end and write 1 byte because Seek is using
    // lseek under the hood. https://users.rust-lang.org/t/rust-create-sparse-file/57276/4
    file.seek(SeekFrom::Current((offset+length)-1))?;
    file.write_all(&[0])
}

/// Make a file sparse
pub fn make_file_sparse(_file: &mut File) -> Result<(), String> {
    // Nothing needs to be done on linux unlike Windows
    Ok(())
}
