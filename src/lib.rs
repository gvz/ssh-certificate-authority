//! # SSH Certificate Authority Server
//!
//! This crate provides the core functionality for the SSH Certificate Authority server.
//! It includes the main server logic, command-line argument parsing,
//! and the coordination between the SSH server and the Certificate Authority (CA).


use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::Parser;
use log::{error, info};
use ssh_key::rand_core::{OsRng, RngCore};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::tempdir;

pub mod ssh_server;
use crate::ssh_server::SshCaServer;
pub use ssh_server::host_key_signer::validate_hostname;
pub use ssh_server::parse_exec_command;

mod identiy_handlers;

/// Certificate Authority module providing CA core logic, server, client, and configuration.
pub mod certificat_authority;

use crate::certificat_authority::{CertificateAuthority, ca_client::CaClient, ca_server::CaServer};

mod config;

/// Command-line arguments for the SSH Certificate Authority server.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct CliArgs {
    /// The path to the configuration file.
    #[arg(short = 'c', long)]
    config_file: String,
    /// Run in Certificate Authority (CA) mode.
    #[arg(short = 'a', long, default_value_t = false)]
    certificate_authority: bool,
    /// The path to the Unix socket for CA communication.
    #[arg(short = 's', long)]
    socket_path: Option<String>,
    /// Disable the automatic startup of the CA server.
    #[arg(long, default_value_t = false)]
    disable_ca: bool,
    /// Path to a file containing the IPC authentication token.
    /// In CA mode, the token is read and the file is immediately deleted.
    /// In SSH server mode, the token is generated and written to this file
    /// (or an auto-generated path) for the CA child process to consume.
    #[arg(long)]
    token_file: Option<String>,
}

/// Runs the SSH Certificate Authority server.
///
/// This function initializes the logger, reads the configuration, and starts
/// either the CA server or the SSH server based on the command-line arguments.
///
/// # Arguments
///
/// * `args` - The command-line arguments parsed by `clap`.
pub async fn run_server(args: CliArgs) {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    let config = match config::read_config(&args.config_file) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to read config file: {}", e);
            return;
        }
    };

    match args.certificate_authority {
        true => {
            info!("Starting CA server");
            let socket_path = match args.socket_path {
                Some(path) => path,
                None => panic!("in CA mode the socket path in mandatory"),
            };
            let token_file = match args.token_file {
                Some(path) => path,
                None => panic!("in CA mode the --token-file path is mandatory"),
            };
            // Read the shared authentication token and immediately delete the
            // file so that no other process can read it afterwards.
            let auth_token = match fs::read_to_string(&token_file) {
                Ok(token) => token,
                Err(e) => {
                    error!("Failed to read token file '{}': {}", token_file, e);
                    return;
                }
            };
            if let Err(e) = fs::remove_file(&token_file) {
                error!("Failed to delete token file '{}': {}", token_file, e);
                return;
            }
            let ca = CertificateAuthority::new(&config.ca).unwrap();
            let mut ca_server = CaServer::new(socket_path, ca, auth_token);
            ca_server.run().await.unwrap();
        }
        false => {
            info!("Starting SSH server");
            let socket_path = match args.socket_path {
                Some(path) => path,
                None => {
                    let socket_name = format!("ssh_ca.{}.sock", std::process::id());
                    let mut tmp_dir = tempdir().unwrap();
                    tmp_dir.disable_cleanup(true);
                    let mut socket_path = tmp_dir.path().to_path_buf();
                    socket_path.push(socket_name);
                    let path = socket_path.as_os_str().to_string_lossy();
                    path.to_string()
                }
            };
            // Obtain the IPC authentication token. If a token file was provided
            // (e.g. when the CA is managed externally), read the token from that
            // file. Otherwise, generate a fresh cryptographically random token.
            let auth_token = match args.token_file {
                Some(ref path) => match fs::read_to_string(path) {
                    Ok(token) => token,
                    Err(e) => {
                        error!("Failed to read token file '{}': {}", path, e);
                        return;
                    }
                },
                None => {
                    let mut token_bytes = [0u8; 32];
                    OsRng.fill_bytes(&mut token_bytes);
                    BASE64.encode(token_bytes)
                }
            };

            let ca_process = if !args.disable_ca {
                info!("spawning CA");

                // Write the token to a temporary file with restricted permissions
                // so that only the current user can read it. The CA process will
                // read and immediately delete this file on startup.
                let token_file_path = {
                    let mut p = std::path::PathBuf::from(&socket_path);
                    p.set_extension("token");
                    p
                };
                if let Err(e) = fs::write(&token_file_path, &auth_token) {
                    error!("Failed to write token file: {}", e);
                    return;
                }
                if let Err(e) =
                    fs::set_permissions(&token_file_path, fs::Permissions::from_mode(0o600))
                {
                    error!("Failed to set token file permissions: {}", e);
                    let _ = fs::remove_file(&token_file_path);
                    return;
                }

                let ca_process = match Command::new(env::current_exe().unwrap())
                    .arg("-c")
                    .arg(&args.config_file)
                    .arg("-a")
                    .arg("-s")
                    .arg(&socket_path)
                    .arg("--token-file")
                    .arg(token_file_path.to_str().unwrap())
                    .spawn()
                {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to spawn CA server process: {}", e);
                        let _ = fs::remove_file(&token_file_path);
                        return;
                    }
                };
                info!("spawned CA");

                Some(ca_process)
            } else {
                info!("skip spawning CA");
                None
            };

            // Wait for the CA server to start by checking for the socket file
            for _ in 0..10 {
                if std::path::Path::new(&socket_path).exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            if !std::path::Path::new(&socket_path).exists() {
                error!("CA server did not start in time");
                if let Some(mut ca) = ca_process {
                    let _ = ca.kill();
                }
                return;
            }

            let user_authenticators = identiy_handlers::setup_user_authenticators(
                config.identity_handlers.user_authenticators,
            )
            .unwrap();

            let ca_client = CaClient::new(socket_path.clone(), auth_token);

            let mut server = SshCaServer::new(config.ssh, ca_client, user_authenticators);
            info!("starting server");
            server.run().await;

            info!("Terminating CA process");
            if let Some(mut ca) = ca_process {
                let _ = ca.kill();
                let _ = ca.wait();
            }

            info!("Removing CA socket file: {}", socket_path);
            let _ = fs::remove_file(&socket_path);
        }
    }
}
