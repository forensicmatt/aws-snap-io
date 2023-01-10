use std::io::{Read, Seek, SeekFrom};
use std::collections::BTreeMap;
use tokio::runtime::Handle;
use bytes::Bytes;
use snafu::{ensure, OptionExt, ResultExt, Snafu};
use sha2::{Digest, Sha256};
use aws_sdk_ec2::model::Filter;
use aws_sdk_ec2::model::Snapshot as Ec2Snapshot;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_ebs::Client as EbsClient;
use aws_sdk_ebs::model::Block;
use aws_types::SdkConfig;
use crate::cache::DiskCache;

const GIBIBYTE: u64 = 1_073_741_824;
type RtHandle = Box<Handle>;

/// Module that provides helpers for reading from AWS Snapshots. AwsSnapshot::from_snashot_id()
/// is a good entry point.
/// 
/// Many thanks to https://github.com/awslabs/coldsnap for providing an excelent base of
/// where to start with working with the AWS libs.


#[derive(Debug, Snafu)]
pub struct Error(error::Error);
type Result<T> = std::result::Result<T, Error>;


/// Create a cache of Snapshot blocks as seen in: https://docs.aws.amazon.com/ebs/latest/APIReference/API_Block.html
/// The cache is a BTreeMap of block index to Block object.
async fn load_blocks(
    ebs_client: &EbsClient,
    snapshot_id: &str
) -> Result<(BTreeMap<i32, Block>, i32)>{
    let mut cache = BTreeMap::new();
    let mut next_token = None;
    let mut block_size = None;

    let mut start_block = 0;

    loop {
        trace!("list_snapshot_blocks(start_block: {start_block}; max_results: 10000; next_token: {next_token:?})");
        
        // List snapshot blocks for this Snapshot
        let response = ebs_client
            .list_snapshot_blocks()
            .snapshot_id(snapshot_id)
            .set_next_token(next_token.clone())
            .starting_block_index(0)
            .max_results(10000)
            .send()
            .await
            .context(error::ListSnapshotBlocksSnafu { snapshot_id })?;

        if block_size.is_none() {
            // Get block size
            block_size = Some(response
                .block_size
                .context(error::FindBlockSizeSnafu { snapshot_id })?);
        }
        
        let token = match response
            .next_token() {
                Some(t) => t,
                // No more results
                None => break
            };
        
        // Set the next token
        next_token = Some(token.to_owned());

        let block_vec = response
            .blocks
            .unwrap_or_default();
        
        if block_vec.is_empty() {
            // No more blocks to list
            break;
        }

        start_block = (block_vec[0]).block_index
            .context(error::FindBlockIndexSnafu { snapshot_id })?;

        // Iterate the blocks in returned in this set.
        for block in &block_vec {
            // Get block index
            let index = block
                .block_index
                .context(error::FindBlockIndexSnafu { snapshot_id })?;

            // Insert block into cache and take ownership of block
            cache.insert(
                index,
                block.to_owned()
            );
        }
    }

    let block_size = block_size.context(error::BlockSizeNotFoundSnafu{})?;

    Ok((cache, block_size))
}


/// Retrieve the Snapshot with the given snapshot id.
/// The Snapshot returned refers to the Snapshot object seen here: 
/// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Snapshot.html
async fn get_snapshot_by_id(
    sdk_config: &SdkConfig,
    snapshot_id: &str
) -> Result<aws_sdk_ec2::model::Snapshot> {
    // Get client
    let ec2_client = Ec2Client::new(sdk_config);
    
    // Create a filter for the passed snapshot id
    let snapshot_filter = Filter::builder()
        .name("snapshot-id")
        .values(snapshot_id)
        .build();
    
    // Fetch the results from the DescribeSnapshots API with the
    // snapshot id filter applied
    let response = ec2_client
        .describe_snapshots()
        .owner_ids("self")
        .filters(snapshot_filter)
        .send()
        .await
        .context(error::DescribeSnapshotsSnafu { snapshot_id })?;
    
    // We should only have one snapshot if this was a valid snapshot id
    let snapshots = response
        .snapshots()
        // If we did not have any snapshots, our snapshot was not found
        // and we should return an error
        .context(error::SnapshotNotFoundSnafu { snapshot_id })?;

    if snapshots.is_empty() {
        // No snapshot found
        error::SnapshotNotFoundSnafu { snapshot_id }.fail()?
    } else if snapshots.len() > 1 {
        // Unhandled logic if we have multiple Snapshot objects for one 
        // snapshot id
        error::MultipleSnapshotsFoundSnafu { snapshot_id }.fail()?
    } else {
        let first_snap = snapshots[0].to_owned();
        Ok(first_snap)
    }
}


/// A cache result that will tell you if a block is contained in a cache
/// or within the range but N/A (empty) or outside the cache window.
#[derive(Clone)]
pub enum CacheResult<'c> {
    /// A Cache contains a block if it was returned by the `list_snapshot_blocks()` API
    /// because that block contains valid snapshot data.
    Block(&'c Block),
    /// An empty block is a block that is in a Cache's range, but the block itself was
    /// not returned by `list_snapshot_blocks()` because it does not contain data.
    EmptyBlock,
    /// Ouside result referes to a request that was outside of the Cache's range.
    Outside
}

/// A cache of Blocks for fetching tokens
pub struct BlockCache {
    /// Cache Map of block index to Block
    /// TODO: In the future, I think we could add a Null mapping for all blocks that
    /// contain no block data to save time if said block is requested. Even if it
    /// is outside the cache range. Why request something we already know is null?
    mapping: BTreeMap<i32, Block>,
    /// First block in this range
    first_block: i32,
    /// Last block in this range
    last_block: i32,
    /// Size of blocks
    block_size: i32,
}
impl BlockCache {
    /// Generate a BlockCache from an AwsSnapshot. Its important to keep
    /// in mind that list_snapshot_blocks() is not guaranteed to return a result for
    /// the start index requested, this the start_index requested is used as the 
    /// `first_block`. Snapshot blocks that have not been used are not available
    /// and thus are treated as blocks of 0x00s.
    pub async fn from_streamer(
        streamer: &AwsSnapshot
    ) -> Result<BlockCache> {
        // Get the snapshot id
        let snapshot_id = streamer.snapshot_id()?;

        // Get client
        let ebs_client = &streamer.ebs_client;

        let (mapping, block_size) = load_blocks(
            ebs_client,
            snapshot_id
        ).await?;

        let last_block = streamer.volume_size_as_bytes() / block_size as u64;
        let last_block = last_block
            .try_into()
            .with_context(|_| error::ConvertNumberSnafu {
                what: "last_block",
                number: last_block.to_string(),
                target: "i32",
            })?;

        trace!(
            "BlockCache {{
                Setting first block 0 and last block {last_block};
            }}"
        );

        Ok( BlockCache { 
            mapping,
            first_block: 0,
            last_block,
            block_size
        })
    }

    /// Fetch a Block in this cache.
    pub fn get_block(
        &self,
        block_index: i32
    ) -> CacheResult {
        if block_index < self.first_block {
            trace!("BlockCache.get_block({}) < first_block: {}", block_index, self.first_block);
            CacheResult::Outside
        } else if block_index > self.last_block {
            trace!("BlockCache.get_block({}) > last_block: {}", block_index, self.last_block);
            CacheResult::Outside
        } else if let Some(block) = self.mapping.get(&block_index) {
            CacheResult::Block(block)
        } else {
            CacheResult::EmptyBlock
        }
    }
}


/// AwsSnapshotStream is a helper struct that wraps a Boxed AwsSnapshot and 
/// a BlockCache.
/// TODO: In the future, a time limit should be added to the block cache so 
/// that tokens can be refreshed.
pub struct AwsSnapshotStream {
    /// The AwsSnapshot
    streamer: Box<AwsSnapshot>,
    /// BlockCache
    cache_map: BlockCache
}
impl AwsSnapshotStream {
    /// Create a AwsSnapshotStream from a AwsSnapshot reference
    async fn new(
        streamer: Box<AwsSnapshot>
    ) -> Result<AwsSnapshotStream> {
        let cache_map = streamer
            .get_block_cache()
            .await?;

        Ok( AwsSnapshotStream {
            streamer,
            cache_map
        })
    }

    /// Consume self into a AwsSnapshotStreamHandle
    pub fn into_handle(
        self,
        rt_handle: RtHandle,
        disk_cache: Option<DiskCache>
    ) -> AwsSnapshotStreamHandle {
        AwsSnapshotStreamHandle {
            stream: self,
            disk_cache,
            rt_handle,
            offset: 0
        }
    }

    /// Get the block size from the BlockCache because the AwsSnapshot doesn't
    /// inherently know the block size.
    pub fn block_size(&self) -> i32 {
        self.cache_map
            .block_size
    }

    /// Get the number of blocks that should exist for this Snapshot. We divide the
    /// volume size by the block size.
    pub fn block_count(&self) -> u64 {
        self.streamer
            .volume_size_as_bytes() / self.cache_map.block_size as u64
    }

    /// Get the Bytes of a block by index.
    pub async fn get_snapshot_block(&mut self, block_index: i32) -> Result<Bytes> {
        let ebs_client = &self.streamer.ebs_client;

        let snapshot_id = self.streamer.snapshot_id()?;
        let block_size = self.cache_map.block_size;
        loop {
            match self.cache_map.get_block(block_index) {
                CacheResult::Block(block) => {
                    // Get the token from this cached block
                    let block_token = block.block_token()
                        .context( error::MissingListBlockAttributeSnafu { 
                            attribute: "block_token",
                            snapshot_id,
                         })?;
                    
                    // Get this snapshot block from the token and index
                    trace!("[start] get_snapshot_block({block_index}, {block_token})");
                    let response = ebs_client
                        .get_snapshot_block()
                        .snapshot_id(snapshot_id)
                        .block_index(block_index)
                        .block_token(block_token)
                        .send()
                        .await
                        .context(error::GetSnapshotBlockSnafu {
                            snapshot_id,
                            block_index,
                        })?;
                    trace!("[finish] get_snapshot_block({block_index}, {block_token})");
                    
                    // Get the stream
                    trace!("[start] block_data.collect()");
                    let block_data_stream = response
                        .block_data
                        .collect()
                        .await
                        .context(error::ByteStreamCollectionSnafu { block_index })?;
                    trace!("[finish] block_data.collect()");
                    
                    // Get the Btyes for this data stream
                    let block_data = block_data_stream.into_bytes();

                    // Get the expected hash for validation
                    let checksum = response
                        .checksum
                        .context( error::MissingBlockDataPropertySnafu {
                            snapshot_id,
                            block_index,
                            property: "checksum",
                        })?;
                    
                    // Get the checksum algorithm
                    // As of right now, the only valid value for this field is SHA256 per:
                    // https://docs.aws.amazon.com/ebs/latest/APIReference/API_GetSnapshotBlock.html
                    let checksum_algorithm = response
                        .checksum_algorithm
                        .context(error::MissingBlockDataPropertySnafu {
                            snapshot_id,
                            block_index,
                            property: "checksum algorithm",
                        })?
                        .as_str()
                        .to_string();

                    // Validate SHA256 is used
                    ensure!(
                        checksum_algorithm == "SHA256",
                        error::UnhandledSnafu {
                            message: format!(
                                "Checksum algorithm {} is not supported!",
                                checksum_algorithm
                            )
                        }
                    );

                    // Check the sha256 value
                    let mut sha256 = Sha256::new();
                    sha256.update(&block_data);
                    let calculated_hash = base64::encode(sha256.finalize());
                    ensure!(
                        calculated_hash == checksum,
                        error::ChecksumSnafu {
                            checksum,
                            calculated_hash,
                            block_index
                        }
                    );

                    // Retrun the data
                    return Ok(block_data);
                },
                CacheResult::EmptyBlock => {
                    // This block is in our range, but is not listed, thus, its just an
                    // empty block.
                    let buffer = vec!(0; block_size as usize);
                    let bytes = Bytes::copy_from_slice(&buffer[..]);
                    return Ok(bytes);
                },
                CacheResult::Outside => {
                    error::UnhandledSnafu{message: "Cache should contain all blocks..."}.fail()?
                }
            }
        }
    }

    /// Given an offset, calculate the block index and relative starting offset.
    fn get_block_and_offset(&self, offset: u64) -> Result<(i32, u64)> {
        // Get block size
        let block_size = self.cache_map.block_size as u64;

        // Block index is the requested size devided by block size
        let block_index = offset / block_size;

        let i = i32::try_from(block_index)
            .context(error::ConvertNumberSnafu {
                what: "block index from offset",
                number: offset.to_string(),
                target: "i32",
            })?;
        
        // Get remainder which represents offset into block index
        let o = offset % block_size;

        Ok((i, o))
    }
}


/// AwsSnapshotStreamHandle implementes Read/Seek for AwsSnapshotStream. It can
/// optionally use a DiskCache to store blocks on disk so the same block never
/// has to be fetched twice. The struct must store its own Runtime handle as 
/// read/seeks are not async.
pub struct AwsSnapshotStreamHandle {
    stream: AwsSnapshotStream,
    // A DiskCache to use
    disk_cache: Option<DiskCache>,
    /// Because AwsSnapshotStream cannot be async, we need to store the
    /// Runtime Handle
    rt_handle: RtHandle,
    /// The current offset
    offset: u64,
}
impl AwsSnapshotStreamHandle {
    fn read_block(&mut self, block_index: i32) -> std::result::Result<Bytes, std::io::Error> {
        let runtime_handle = self.rt_handle.as_ref();

        let block_result = runtime_handle.block_on(
            self.stream.get_snapshot_block(block_index)
        );

        block_result
            .map_err(|e|std::io::Error::new(
                std::io::ErrorKind::Other, 
                format!("{:?}", e)
            ))
    }
}
impl Read for AwsSnapshotStreamHandle {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        _ = self.rt_handle.enter();
        let current_offset = self.offset;
        let buffer_size = buf.len();
        let block_size = self.stream.block_size();

        trace!("reading {buffer_size} bytes at offset {current_offset}");

        let mut bytes_written: usize = 0;
        loop {
            trace!("{bytes_written} out of {buffer_size} written");

            // Check if we have written all the blocks needed
            if bytes_written == buffer_size {
                break;
            }

            // Get the block index and offset that will need to be read from
            let (block_index, relative_offset) = self.stream
                .get_block_and_offset(self.offset)
                .map_err(|e|std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    format!("{:?}", e)
                ))?;
            
            // If a block is not cached, we want to add it
            let mut not_cached = false;
            let block: Bytes = if let Some(disk_cache) = self.disk_cache.as_mut() {
                let block = disk_cache.read_block(block_index, block_size as usize)
                    .context(error::DiskCacheReadSnafu {
                        block_index: block_index as u64,
                        block_size: block_size as u64,
                    })
                    .map_err(|e|std::io::Error::new(
                        std::io::ErrorKind::Other, 
                        format!("{:?}", e)
                    ))?;

                if let Some(block) = block.as_ref() {
                    trace!("block {block_index} loaded from cache.");
                    Bytes::from(block.to_owned())
                } else {
                    not_cached = true;
                    self.read_block(block_index)?
                }
            } else {
                not_cached = true;
                self.read_block(block_index)?
            };

            if not_cached {
                if let Some(disk_cache) = self.disk_cache.as_mut() {
                    disk_cache.write_block(block_index, &block)
                        .context(error::DiskCacheWriteSnafu {
                            block_index: block_index as u64
                        })
                        .map_err(|e|std::io::Error::new(
                            std::io::ErrorKind::Other, 
                            format!("{:?}", e)
                        ))?;
                }
            }

            let chunk = block.as_ref();
            if relative_offset as usize > chunk.len() {
                panic!("chunk_offset > chunk.len()");
            }

            let chunk = &chunk[relative_offset as usize..];
            let chunk_size = chunk.len();

            let remainder = buffer_size - bytes_written;
            let bytes_to_take = if remainder >= chunk_size {
                chunk_size
            } else {
                remainder
            };

            let buf_end_ofs = bytes_written + bytes_to_take;
            if bytes_written > buf_end_ofs {
                panic!("bytes_written > buf_end_ofs");
            }
            
            let _ = &buf[bytes_written..buf_end_ofs]
                .copy_from_slice(&chunk[
                    0..bytes_to_take
                ]);
                
            bytes_written += bytes_to_take;
            self.offset += bytes_to_take as u64;
        }

        Ok(bytes_written)
    }
}
impl Seek for AwsSnapshotStreamHandle {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64>{
        let volume_size = self.stream.streamer.volume_size_as_bytes();
        let block_size = self.stream.block_size() as u64;

        match pos {
            SeekFrom::Start(ofs) => {
                // Get the block index and offset into the block for the read
                let (blk_ind, blk_ofs) = self.stream.get_block_and_offset(ofs)
                    .expect("Error getting block/offset.");

                // This is the starting offset of the block
                let block_start_ofs = blk_ind as u64 * block_size;
                trace!(
                    "seeking to offset: {ofs}[
                        vol size: {volume_size}; 
                        blk indx: {blk_ind};
                        blk size: {block_size};
                        start of block: {block_start_ofs};
                        blk into offset: {blk_ofs}
                    ]"
                );

                if ofs > volume_size {
                    Err(
                        std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "Offset Start({ofs}) is greater than volume size {volume_size}"
                        )
                    ))
                } else {
                    self.offset = ofs;
                    Ok(ofs)
                }
            },
            SeekFrom::Current(o) => {
                let new_offset =  if o < 0 {
                    self.offset - u64::try_from(o.abs())
                        .map_err(|e|std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof, 
                            format!("{:?}", e))
                        )?
                } else {
                    self.offset + u64::try_from(o)
                        .map_err(|e|std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof, 
                        format!("{:?}", e))
                    )?
                };

                let (bind, bofs) = self.stream.get_block_and_offset(new_offset)
                    .expect("Error getting block/offset.");
                debug!("seeking: {} [vol size: {}; blk indx: {}; blk offset: {}]", new_offset, volume_size, bind, bofs);

                if new_offset > volume_size {
                    return Err(
                        std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "Offset Current({}) is greater than attr size. new_offset = {} + {} = {}, self.tsk_fs_attr.size() = {}",
                            o,
                            self.offset,
                            o,
                            new_offset,
                            volume_size
                        )
                    ));
                } else {
                    self.offset = new_offset;
                }

                Ok(self.offset)
            },
            SeekFrom::End(_o) => {
                unimplemented!("SeekFrom::End not yet implemented!");
            }
        }
    }
}


/// Struct that handles Snapshot operations
#[derive(Clone)]
pub struct AwsSnapshot {
    ebs_client: EbsClient,
    snapshot: Ec2Snapshot,
    max_results: i32
}
impl AwsSnapshot {
    /// Create a AwsSnapshot given the SDK Config and the Snapshot
    pub fn new(
        sdk_config: SdkConfig,
        snapshot: Ec2Snapshot
    ) -> Result<Self> {
        let ebs_client = EbsClient::new(&sdk_config);

        Ok( AwsSnapshot {
            ebs_client,
            snapshot,
            max_results: 10000
        })
    }

    /// Get the `snapshot_id` property from the underlaying Snapshot.
    pub fn snapshot_id(&self) -> Result<&str> {
        let id = self.snapshot
            .snapshot_id()
            .context(error::MissingSnapshotAttributeSnafu{ attribute: "snapshot_id" })?;
        Ok(id)
    }

    /// Get the AwsSnapshotStream for this streamer given a runtime handle. This is 
    /// required because Read/Seek does not handle async, thus, we need the Tokio
    /// Runtime handle for async calls.
    pub async fn into_stream(self) -> Result<AwsSnapshotStream> {
        AwsSnapshotStream::new(
            Box::new(self)
        ).await
    }

    /// Set the value to use for max blocks to fetch when using list_snapshot_blocks api
    /// call. The value must be between 100 and 10,000.
    pub fn set_max_results(mut self, max_results: i32) -> Result<Self> {
        // Double check we are using a valid number (otherwise `list_snapshot_blocks` will fail)
        ensure!(
            (100..=10000).contains(&max_results),
            error::InvalidValueSnafu { 
                name: "max_results",
                value: self.max_results.to_string(),
                comment: "`max_results` must be between 100 and 10000" 
        });

        self.max_results = max_results;
        Ok(self)
    }

    /// Get max_results and error if the value is not valid.
    pub fn max_results(&self) -> Result<i32> {
        ensure!(
            self.max_results >= 100 && self.max_results <= 10000, 
            error::InvalidValueSnafu { 
                name: "max_results",
                value: self.max_results.to_string(),
                comment: "max_results must be between 100 and 10000" 
        });

        Ok(self.max_results)
    }

    /// Get a BlockCache starting a given block index
    async fn get_block_cache(
        &self
    ) -> Result<BlockCache> {
        let block_cache = BlockCache::from_streamer(
            self
        ).await?;

        Ok(block_cache)
    }

    /// Get the snapshot's volume size as GB
    pub fn volume_size(&self) -> i32 {
        self.snapshot
            .volume_size()
            .expect("Volume size does not exist!")
    }

    /// Get the snapshot's volume size as bytes
    pub fn volume_size_as_bytes(&self) -> u64 {
        self.snapshot
            .volume_size()
            .expect("Volume size does not exist!") as u64 * GIBIBYTE
    }

    /// Create a AwsSnapshot from a given snapshot id. This is a good entry point function.
    /// See the `read_snapshot.rs` example tool for reference.
    pub async fn from_snashot_id(sdk_config: SdkConfig, snapshot_id: &str) -> Result<Self> {
        let snapshot = get_snapshot_by_id(
                &sdk_config,
                snapshot_id
            )
            .await?;

        Self::new(
            sdk_config,
            snapshot
        )
    }

    /// Consume the AwsSnapshot into a AwsSnapshotStreamHandle
    pub async fn into_handle(self, rt_handle: RtHandle, disk_cache: Option<DiskCache>) -> Result<AwsSnapshotStreamHandle> {
        let stream = self
            .into_stream()
            .await?;
        Ok(stream.into_handle(rt_handle, disk_cache))
    }
}


mod error {
    use snafu::Snafu;
    use aws_sdk_ec2::types::SdkError;
    use aws_sdk_ec2::error::DescribeSnapshotsError;
    use aws_sdk_ebs::error::{ListSnapshotBlocksError, GetSnapshotBlockError};
    use crate::cache::Error as CacheError;

    #[derive(Debug, Snafu)]
    #[snafu(visibility(pub(super)))]
    pub(super) enum Error {
        /// Unhandled.
        #[snafu(display("{}", message))]
        Unhandled {
            message: String
        },

        /// DiskCache read error.
        #[snafu(display(
            "Block size from ListSnapshotBlocks not found."
        ))]
        BlockSizeNotFound {},

        /// DiskCache read error.
        #[snafu(display(
            "There was an error reading block {} from the on disk cache [block_size: {}]. {:?}",
            block_index, block_size, source
        ))]
        DiskCacheRead {
            block_index: u64,
            block_size: u64,
            source: CacheError,
        },

        /// DiskCache write error.
        #[snafu(display(
            "There was an error writing block {} to the on disk cache. {:?}",
            block_index, source
        ))]
        DiskCacheWrite {
            block_index: u64,
            source: CacheError,
        },

        /// Snapshot does not contain a specific attribute.
        #[snafu(display("Snapshot is missing attribute: {}", attribute))]
        MissingSnapshotAttribute {
            attribute: String
        },

        /// Snapshot does not contain a specific attribute.
        #[snafu(display("Block from ListSnapshotBlocksOutput is missing attribute {} [snapshot id: {}]", attribute, snapshot_id))]
        MissingListBlockAttribute {
            attribute: String,
            snapshot_id: String
        },

        #[snafu(display("{}: '{}' is invalid! {}", name, value, comment))]
        InvalidValue {
            name: String,
            value: String,
            comment: String
        },

        #[snafu(display("Failed to describe snapshots '{}': {}", snapshot_id, source))]
        DescribeSnapshots {
            snapshot_id: String,
            source: SdkError<DescribeSnapshotsError>,
        },

        #[snafu(display(
            "Failed to get block {} for snapshot '{}': {}",
            block_index,
            snapshot_id,
            source
        ))]
        GetSnapshotBlock {
            snapshot_id: String,
            block_index: i64,
            source: aws_sdk_ebs::types::SdkError<GetSnapshotBlockError>,
        },

        #[snafu(display(
            "Could not collect byte stream for block {}",
            block_index
        ))]
        ByteStreamCollection {
            block_index: i32,
            source: aws_smithy_http::byte_stream::Error,
        },

        #[snafu(display("Failed to list snapshot blocks '{}': {}", snapshot_id, source))]
        ListSnapshotBlocks {
            snapshot_id: String,
            source: aws_sdk_ebs::types::SdkError<ListSnapshotBlocksError>,
        },

        #[snafu(display("Unhandled logic. Multiple snapshots found for: '{}'",  snapshot_id))]
        MultipleSnapshotsFound {
            snapshot_id: String
        },

        #[snafu(display("Failed to find snapshot '{}'",  snapshot_id))]
        SnapshotNotFound {
            snapshot_id: String
        },

        #[snafu(display("No blocks found in {} starting after block {}", snapshot_id, starting_index))]
        NoBlocksFound {
            snapshot_id: String,
            starting_index: i32,
        },

        #[snafu(display("Failed to find index for block in '{}'", snapshot_id))]
        FindBlockIndex { snapshot_id: String },

        #[snafu(display(
            "Failed to find {} for block {} in '{}'",
            property,
            block_index,
            snapshot_id
        ))]
        MissingBlockDataProperty {
            snapshot_id: String,
            block_index: i32,
            property: String,
        },

        #[snafu(display("Failed to find block size for '{}'", snapshot_id))]
        FindBlockSize { snapshot_id: String },

        #[snafu(display(
            "Expected checksum {} but got {} for block {}",
            checksum,
            calculated_hash,
            block_index
        ))]
        Checksum {
            checksum: String,
            calculated_hash: String,
            block_index: i64,
        },

        #[snafu(display(
            "Found unexpected data length {} for block {} in '{}'",
            data_length,
            block_index,
            snapshot_id
        ))]
        UnexpectedBlockDataLength {
            snapshot_id: String,
            block_index: i64,
            data_length: i64,
        },

        #[snafu(display(
            "Found unexpected checksum algorithm '{}' for block {} in '{}'",
            checksum_algorithm,
            block_index,
            snapshot_id
        ))]
        UnexpectedBlockChecksumAlgorithm {
            snapshot_id: String,
            block_index: i64,
            checksum_algorithm: String,
        },

        #[snafu(display("Failed to convert {} {} to {}: {}", what, number, target, source))]
        ConvertNumber {
            what: String,
            number: String,
            target: String,
            source: std::num::TryFromIntError,
        },

        #[snafu(display("AwsSnapshot for {} is missing a block cache while looking at block {}", snapshot_id, block_index))]
        MissingBlockCache {
            snapshot_id: String,
            block_index: i32
        },

        #[snafu(display("Index {} is out of range for BlockCache[{}-{}] {}", block_index, cache_start, cache_end, snapshot_id))]
        BlockOutsideCache {
            snapshot_id: String,
            cache_start: i32,
            cache_end: i32,
            block_index: i32
        },
    }
}