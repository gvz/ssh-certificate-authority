use std::sync::Arc;

use log::{debug, error};
use russh::{
    Channel,
    keys::PrivateKey,
    server::{Auth, ChannelOpenHandle, Handler, Msg, Server, Session},
};

#[derive(Debug, Clone)]
pub struct SshServerConfig {
    /// The address to bind the SSH server to.
    pub bind: String,
    /// The port to bind the SSH server to.
    pub port: u16,
    /// The path to the server's private key.
    pub private_key: PrivateKey,
}

#[derive(Clone)]
pub struct TestSshServer {
    client_ids: usize,
    config: SshServerConfig,
}
#[allow(dead_code)]
pub struct ConnectionHandler {
    server: Arc<TestSshServer>,
    username: Option<String>,
    id: usize,
    auth_method: Option<AuthMethod>,
}
#[allow(dead_code)]
pub enum AuthMethod {
    Password,
    PublicKey,
}
impl TestSshServer {
    pub fn new(config: SshServerConfig) -> Self {
        TestSshServer {
            client_ids: 0,
            config,
        }
    }

    pub async fn run(&mut self) {
        let mut auth_methods = russh::MethodSet::empty();
        auth_methods.push(russh::MethodKind::Password);
        auth_methods.push(russh::MethodKind::PublicKey);

        let ssh_config = russh::server::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
            auth_rejection_time: std::time::Duration::from_secs(3),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            max_auth_attempts: 1,
            methods: auth_methods,
            keys: vec![self.config.private_key.clone()],
            preferred: russh::Preferred {
                ..russh::Preferred::default()
            },
            ..Default::default()
        };
        let ssh_config = Arc::new(ssh_config);
        self.run_on_address(ssh_config, (self.config.bind.clone(), self.config.port))
            .await
            .unwrap();
    }
}
impl Server for TestSshServer {
    type Handler = ConnectionHandler;

    /// Creates a new `ConnectionHandler` for a new client connection.
    fn new_client(&mut self, socket_addr: Option<std::net::SocketAddr>) -> ConnectionHandler {
        self.client_ids += 1;
        let s = ConnectionHandler {
            id: self.client_ids,
            username: None,
            server: Arc::new(self.clone()),
            auth_method: None,
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
    #[allow(unused_variables)]
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        error!("test server does not implement authentication");
        Err(russh::Error::RequestDenied)
    }

    /// Handles a new session channel.
    #[allow(unused_variables)]
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
}
