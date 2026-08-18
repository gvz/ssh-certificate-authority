//! # SSH Certificate Authority Server
//!
//! This module provides the core SSH server implementation.
//! It handles client connections, authentication, and the process of
//! receiving a public key, forwarding it to the CA for signing, and
//! returning the signed certificate to the user.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use log::{debug, error, info, warn};
use russh::{
    Channel, ChannelId, Error,
    keys::PublicKey,
    server::{Auth, ChannelOpenHandle, Handler, Msg, Server, Session},
};
use tokio::sync::Mutex;

use crate::certificat_authority::ca_client::CaClient;
use crate::certificat_authority::{CaRequest, CaResponse};
use crate::identiy_handlers::{Credential, UserAuthenticator};

pub(crate) mod config;
pub mod host_key_signer;
pub(crate) mod signing_common;
pub(crate) mod user_key_signer;

/// Validates that a username contains only safe characters.
///
/// Accepts `[a-zA-Z0-9._@-]`, 1–64 characters long. Rejects anything outside
/// this set to prevent TOML/template injection via the username in certificate
/// principal rendering.
pub fn validate_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'))
}

/// Parses a raw exec-request payload into a command name and remaining arguments.
///
/// The input bytes are first decoded as lossy UTF-8, then split on whitespace.
/// Returns the command name (or `""` if the payload is empty/whitespace-only) and
/// the remaining whitespace-separated tokens.
pub fn parse_exec_command(data: &[u8]) -> (String, Vec<String>) {
    let command = String::from_utf8_lossy(data).to_string();
    let mut parts = command.split_whitespace();
    let command_name = parts.next().unwrap_or("").to_string();
    let args: Vec<String> = parts.map(|s| s.to_string()).collect();
    (command_name, args)
}
use config::SshServerConfig;

/// The main SSH Certificate Authority server struct.
///
/// This struct holds the state for the SSH server, including connected clients,
/// the CA client, the server configuration, and the list of user authenticators.
#[derive(Clone)]
pub struct SshCaServer {
    clients: Arc<Mutex<HashMap<usize, (ChannelId, russh::server::Handle)>>>,
    client_ids: usize,
    ca_client: CaClient,
    config: SshServerConfig,
    user_authenticators: Vec<Box<dyn UserAuthenticator + Send + Sync>>,
}

/// The authentication method used by a client.
pub enum AuthMethod {
    /// Password-based authentication.
    Password,
    /// Public key-based authentication.
    PublicKey,
}

/// A handler for a single client connection.
///
/// This struct holds the state for a single client connection, including a
/// reference to the main server, the username (once authenticated), and a
/// unique ID for the connection.
pub struct ConnectionHandler {
    server: Arc<SshCaServer>,
    username: Option<String>,
    id: usize,
    auth_method: Option<AuthMethod>,
    public_key: Option<PublicKey>,
}

impl SshCaServer {
    /// Creates a new `SshCaServer`.
    ///
    /// # Arguments
    ///
    /// * `config` - The SSH server configuration.
    /// * `ca_client` - A client for communicating with the CA server.
    /// * `user_authenticators` - A list of authenticators to use for user authentication.
    pub fn new(
        config: SshServerConfig,
        ca_client: CaClient,
        user_authenticators: Vec<Box<dyn UserAuthenticator + Send + Sync>>,
    ) -> Self {
        SshCaServer {
            clients: Arc::new(Mutex::new(HashMap::new())),
            client_ids: 0,
            ca_client,
            config,
            user_authenticators,
        }
    }

    /// Runs the SSH server.
    ///
    /// This function loads the server's private key, configures the SSH server,
    /// and starts listening for incoming connections.
    pub async fn run(&mut self) {
        let server_private_key_path = PathBuf::from(&self.config.private_key);
        let server_private_key = russh::keys::load_secret_key(&server_private_key_path, None)
            .unwrap_or_else(|e| {
                error!("failed to load private keys: {}", e);
                panic!("failed")
            });

        let mut auth_methods = russh::MethodSet::empty();
        auth_methods.push(russh::MethodKind::Password);
        auth_methods.push(russh::MethodKind::PublicKey);

        let ssh_config = match &self.config.certificate {
            // build ssh server config to use public key
            None => russh::server::Config {
                inactivity_timeout: Some(std::time::Duration::from_secs(5)),
                auth_rejection_time: std::time::Duration::from_secs(3),
                auth_rejection_time_initial: None,
                // Counts rejected auth requests. OpenSSH always probes with the
                // "none" method first, which burns one rejection, so a value of
                // 1 locks out every real client. 3 leaves one genuine retry.
                max_auth_attempts: 3,
                methods: auth_methods,
                keys: vec![server_private_key],
                preferred: russh::Preferred {
                    ..russh::Preferred::default()
                },
                ..Default::default()
            },
            // build ssh server config to use certificate
            Some(server_certificate_path_str) => {
                let server_certificate_path = PathBuf::from(server_certificate_path_str);
                let server_certificate = russh::keys::load_openssh_certificate(
                    &server_certificate_path,
                )
                .unwrap_or_else(|e| {
                    error!("failed to load certificate: {}", e);
                    panic!("failed")
                });
                russh::server::Config {
                    inactivity_timeout: Some(std::time::Duration::from_secs(5)),
                    auth_rejection_time: std::time::Duration::from_secs(3),
                    auth_rejection_time_initial: None,
                    // See the comment on the non-certificate config above.
                    max_auth_attempts: 3,
                    methods: auth_methods,
                    keys: vec![server_private_key],
                    certificates: vec![server_certificate],
                    preferred: russh::Preferred {
                        ..russh::Preferred::default()
                    },
                    ..Default::default()
                }
            }
        };

        info!(
            "starting ssh server at {}:{}",
            &self.config.bind, self.config.port
        );
        let ssh_config = Arc::new(ssh_config);
        self.run_on_address(ssh_config, (self.config.bind.clone(), self.config.port))
            .await
            .unwrap();
    }
}

impl Server for SshCaServer {
    type Handler = ConnectionHandler;

    /// Creates a new `ConnectionHandler` for a new client connection.
    fn new_client(&mut self, socket_addr: Option<std::net::SocketAddr>) -> ConnectionHandler {
        self.client_ids += 1;
        let s = ConnectionHandler {
            id: self.client_ids,
            username: None,
            server: Arc::new(self.clone()),
            auth_method: None,
            public_key: None,
        };

        let client_address = match socket_addr {
            None => "Unknown".to_string(),
            Some(socket) => {
                let ip = socket.ip();
                let port = socket.port();
                format!("{}:{}", ip, port)
            }
        };
        debug!("new client: {}", client_address);
        s
    }

    /// Handles a session error.
    fn handle_session_error(&mut self, _error: <Self::Handler as russh::server::Handler>::Error) {
        error!("Session error: {:#?}", _error);
    }
}

impl Handler for ConnectionHandler {
    type Error = russh::Error;

    /// Authenticates a user with a password.
    ///
    /// This function iterates through the enabled authenticators and tries to
    /// authenticate the user with the given password.
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if !validate_username(user) {
            warn!("rejected login: username '{}' contains disallowed characters", user);
            return Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }
        #[cfg(feature = "test_auth")]
        {
            warn!("Test Authenticate: {}, {}", user, password);
            if user == "test" && password == "test" {
                warn!("Authenticate test user");
                self.username = Some(user.to_string());
                self.auth_method = Some(AuthMethod::Password);
                return Ok(Auth::Accept);
            } else {
                error!("Reject test user");
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }
        }
        #[allow(unreachable_code)]
        for authenticator in &self.server.user_authenticators {
            match authenticator.authenticate(user, Credential::Password(password)) {
                Ok(true) => {
                    debug!("login for user: {} ACCEPTED", user);
                    self.username = Some(user.to_string());
                    self.auth_method = Some(AuthMethod::Password);
                    return Ok(Auth::Accept);
                }
                Ok(false) => {
                    debug!("login for user: {} FAILED ", user);
                }
                Err(e) => {
                    warn!("pam auth error: {}", e);
                }
            }
        }
        Err(russh::Error::RequestDenied)
    }

    // Check if the key in authorized for this host
    //fn auth_publickey_offered(
    //    &mut self,
    //    user: &str,
    //    public_key: &PublicKey,
    //) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
    //}

    /// Authenticates a user or host via public key.
    ///
    /// Accepts the connection if the presented public key is found in the CA's
    /// host inventory. Russh verifies possession of the corresponding private key.
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        // Accept any host who's public key is in a host config
        // Russh verifies that the host is in possession of the private key
        info!("Public key authentication accepted for user/host: {}", user);
        let key_found = match self
            .server
            .ca_client
            .send_request(CaRequest::CheckPublicKey {
                public_key: ssh_key::PublicKey::from_openssh(&public_key.to_openssh().unwrap())
                    .unwrap(),
            })
            .await
        {
            Ok(CaResponse::KeyFound(found)) => found,
            Ok(CaResponse::Error(e)) => {
                let error_message = format!("CA server error: {}", e);
                error!("{}", &error_message);
                None
            }
            Err(e) => {
                let error_message = format!("Failed to send request to CA server: {}", e);
                error!("{}", &error_message);
                None
            }
            Ok(CaResponse::SignedCertificate(_)) => {
                panic!("Key check reploed with signed cert, which must not happen")
            }
        };
        if key_found.is_none() {
            // key not in any config, reject host
            return Ok(Auth::Reject {
                partial_success: false,
                proceed_with_methods: None,
            });
        }

        self.username = key_found;
        self.auth_method = Some(AuthMethod::PublicKey);
        self.public_key = Some(public_key.clone());
        Ok(Auth::Accept)
    }

    /// Handles a new session channel.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        {
            let mut clients = self.server.clients.lock().await;
            clients.insert(self.id, (channel.id(), session.handle()));
            debug!("new client connected");
        }
        reply.accept().await;
        Ok(())
    }

    /// Handles incoming channel data by delegating to the user key signing handler.
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        debug!("user key signing found");
        user_key_signer::handler_sign_user_key(self, channel, data, session).await
    }

    /// Handles an exec request on the channel.
    ///
    /// Dispatches recognized commands (e.g. `sign_host_key`) to the appropriate
    /// handler and disconnects the client for unknown commands.
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let (command_name, _args) = parse_exec_command(data);
        let pub_key = match self.public_key.clone() {
            None => return Err(Error::RequestDenied),
            Some(pubkey) => pubkey.to_openssh()?,
        };

        let hostname = match self.username.clone() {
            Some(hostname) => hostname,
            None => return Err(Error::RequestDenied),
        };
        let args: Vec<&str> = vec![&hostname, &pub_key];

        match command_name.as_str() {
            "sign_host_key" => {
                debug!("found host key signing command");
                host_key_signer::handle_sign_host_key(self, channel, args, session).await
            }
            _ => {
                let error_message = format!("Unknown command: {}", command_name);
                error!("{}", &error_message);
                let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
                Ok(())
            }
        }
    }
}

impl Drop for ConnectionHandler {
    /// Removes the client from the server's list of clients when the connection is dropped.
    fn drop(&mut self) {
        let id = self.id;
        let clients = self.server.clients.clone();
        tokio::spawn(async move {
            let mut clients = clients.lock().await;
            clients.remove(&id);
        });
    }
}
