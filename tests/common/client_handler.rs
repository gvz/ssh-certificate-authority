use log::info;
use russh::client::Handler;
use ssh_key::Certificate;

#[derive(Clone)]
pub(crate) struct ClientHandler;

impl Handler for ClientHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::cert::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Always accept the server's key (not safe for production!)
        Ok(true)
    }

    async fn data(
        &mut self,
        _channel: russh::ChannelId,
        data: &[u8],
        _extended: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        let openssh_cert = String::from_utf8_lossy(data).to_string();
        info!("got certificate: {}", openssh_cert);
        let _cert = Certificate::from_openssh(&openssh_cert).unwrap();

        Ok(())
    }
}
