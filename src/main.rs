mod client;
mod server;

use log4rs::append::console::{ConsoleAppender, Target};
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;

use clap::{Parser, Subcommand};
use log::{LevelFilter, error};
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Location of log file (defaults to stderr)
    #[clap(value_parser, long = "log")]
    log_file: Option<PathBuf>,
    /// Log level, Default Warn
    #[clap(long)]
    log_level: Option<LevelFilter>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Server
    Server(server::Opt),
    /// Client
    Client(client::Opt),
}

fn main() -> ExitCode {
    let args = Cli::parse();

    let level = args.log_level.unwrap_or(LevelFilter::Warn);
    let config = match args.log_file {
        Some(log_file) => {
            let logfile = match FileAppender::builder()
                .encoder(Box::<PatternEncoder>::default())
                .build(&log_file)
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("failed to open log file {}: {}", log_file.display(), e);
                    return ExitCode::FAILURE;
                }
            };

            Config::builder()
                .appender(Appender::builder().build("logfile", Box::new(logfile)))
                .build(Root::builder().appender("logfile").build(level))
                .expect("valid file logger config")
        }
        None => {
            let stderr = ConsoleAppender::builder()
                .encoder(Box::<PatternEncoder>::default())
                .target(Target::Stderr)
                .build();
            Config::builder()
                .appender(Appender::builder().build("stderr", Box::new(stderr)))
                .build(Root::builder().appender("stderr").build(level))
                .expect("valid stderr logger config")
        }
    };

    log4rs::init_config(config).expect("initialize logger");

    let result = match args.command {
        Commands::Server(server) => server::run(server),
        Commands::Client(client) => client::run(client),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("Error: {:#?}", e);
            ExitCode::FAILURE
        }
    }
}
