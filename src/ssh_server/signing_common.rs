//! Common helpers shared by host and user key signing handlers.

use log::error;
use russh::{ChannelId, server::Session};
use ssh_key::{PublicKey, certificate::Certificate};

use crate::certificat_authority::{CaRequest, CaResponse, key_from_openssh};
use crate::certificat_authority::ca_client::CaClient;

/// Parses an OpenSSH public key string, disconnecting the session on failure.
///
/// Returns `None` (after disconnecting) if parsing fails, or `Some(key)` on success.
pub fn parse_openssh_key(raw: &str, session: &mut Session) -> Option<PublicKey> {
    match key_from_openssh(raw) {
        Ok(key) => Some(key),
        Err(e) => {
            let msg = format!("failed to read openssh public key: {}", e);
            error!("{}", msg);
            let _ = session.disconnect(russh::Disconnect::ByApplication, &msg, "en");
            None
        }
    }
}

/// Sends a signing request to the CA, disconnecting the session on failure.
///
/// Returns `None` (after disconnecting) on any CA error, or `Some(cert)` on success.
pub async fn send_sign_request(
    ca_client: &CaClient,
    request: CaRequest,
    session: &mut Session,
) -> Option<Certificate> {
    match ca_client.send_request(request).await {
        Ok(CaResponse::SignedCertificate(cert)) => Some(cert),
        Ok(CaResponse::Error(e)) => {
            let msg = format!("CA server error: {}", e);
            error!("{}", msg);
            let _ = session.disconnect(russh::Disconnect::ByApplication, &msg, "en");
            None
        }
        Err(e) => {
            let msg = format!("Failed to send request to CA server: {}", e);
            error!("{}", msg);
            let _ = session.disconnect(russh::Disconnect::ByApplication, &msg, "en");
            None
        }
        Ok(CaResponse::KeyFound(_)) => {
            panic!("Signing request replied with KeyFound, which must not happen")
        }
    }
}

/// Converts a certificate to OpenSSH format, sends it to the client, and closes the channel.
///
/// Disconnects the session if conversion fails.
pub fn send_cert_and_close(cert: Certificate, channel: ChannelId, session: &mut Session) -> Option<()> {
    let openssh_cert = match cert.to_openssh() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("failed to convert cert to openssh format: {}", e);
            error!("{}", msg);
            let _ = session.disconnect(russh::Disconnect::ByApplication, &msg, "en");
            return None;
        }
    };
    let _ = session.data(channel, openssh_cert);
    let _ = session.exit_status_request(channel, 0);
    let _ = session.eof(channel);
    let _ = session.close(channel);
    Some(())
}
