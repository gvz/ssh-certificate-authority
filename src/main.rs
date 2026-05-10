//! # SSH Certificate Authority Server
//!
//! This is the main entry point for the SSH Certificate Authority server.
use clap::Parser;
use ssh_ca_server::{CliArgs, run_server};

/// The main function for the SSH Certificate Authority server.
///
/// This function parses the command-line arguments and calls the `run_server`
/// function to start the server.
#[tokio::main]
async fn main() {
    let args = CliArgs::parse();
    run_server(args).await;
}
