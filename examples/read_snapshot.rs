#[macro_use] extern crate log;
use std::str::FromStr;
use std::io::{Read, Seek, SeekFrom};
use chrono::Local;
use fern::Dispatch;
use log::LevelFilter;
use clap::Parser;
use tokio::runtime::Runtime;
use awssnapio::AwsSnapshot;
use snafu::{whatever, ResultExt};

static VERSION: &str = env!("CARGO_PKG_VERSION");


/// Test tool to read a number of bytes from a given offset in a snapshot. 
/// This requires that you have already setup your AWS credentials and region. 
/// This application is for testing and example only. Note this tool/lib does 
/// not support concurrent reads from a snapshot. Look at Coldsnap for that functionality.
#[derive(Parser, Debug)]
#[command(
    author = "Matthew Seyer",
    version=VERSION,
)]
struct App {
    /// The name of the snapshot to read from.
    #[arg(short, long, required=true)]
    snapshot: String,
    /// The offset in the snapshot to start reading from.
    #[arg(short, long, required=true)]
    offset: u64,
    /// The length in bytes to read.
    #[arg(short, long, required=true)]
    length: u64,
    /// The logging level to use.
    #[arg(long, default_value="Info", value_parser=["Off", "Error", "Warn", "Info", "Debug", "Trace"])]
    logging: String,
}
impl App {
    fn set_logging(&self) -> Result<(), snafu::Whatever> {
        let level = self.logging.as_str();

        let message_level = LevelFilter::from_str(level)
            .with_whatever_context(|e|format!("Could not set logging level: {e:?}"))?;

        // Create logging with debug level that prints to stderr
        // See https://docs.rs/fern/0.6.0/fern/#example-setup
        let result = Dispatch::new()
            .format(|out, message, record| {
                out.finish(format_args!(
                    "{}[{}][{}] {}",
                    Local::now().format("[%Y-%m-%d %H:%M:%S]"),
                    record.target(),
                    record.level(),
                    message
                ))
            })
            .level(message_level)
            .level_for("aws_smithy_http_tower", log::LevelFilter::Off)
            .level_for("aws_endpoint", log::LevelFilter::Off)
            .level_for("aws_config", log::LevelFilter::Off)
            .level_for("hyper", log::LevelFilter::Off)
            .chain(std::io::stderr())
            .apply();
        
        // Ensure that logger was dispatched
        match result {
            Ok(_) => trace!("Logging has been initialized!"),
            Err(error) => {
                whatever!("Error initializing fern logging: {}", error);
            }
        }

        Ok(())
    }
}


/// Function to encode bytes to hex string
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}


fn main() {
    let app: App = App::parse();
    app.set_logging()
        .expect("Error setting logging!");

    // Create a runtime to run the async code
    let runtime = Runtime::new().unwrap();
    // Box the runtime for passing to library
    let handle = Box::new(runtime.handle().to_owned());
    // Create the AWS SDK config
    let sdk_config = handle.block_on(aws_config::from_env()
        .load());

    let snapshot_id = app.snapshot;
    let offset = app.offset;
    let size = app.length;
    let mut buffer = vec![0; size as usize];

    // Get the snapshot handler
    let snapshot = handle.block_on(AwsSnapshot::from_snashot_id(
            sdk_config,
            snapshot_id.as_str()
        ))
        .expect("Error creating AwsSnapshotStreamer!");

    // Create the IO handle for the snapshot
    let mut snapshot_handle = runtime.block_on(
        snapshot.into_handle(handle, None))
        .expect("Error creating io handle from AwsSnapshot");
    
    // Seek to the offset
    let _result = snapshot_handle.seek(SeekFrom::Start(offset))
        .expect("Error seeking to offset!");
    
    // Read the bytes
    snapshot_handle.read_exact(&mut buffer)
        .expect("Error reading bytes from stream!");

    println!("{}", encode_hex(&buffer));
}