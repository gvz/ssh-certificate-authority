use anyhow::Result;
use log::{error, info};
use russh::ChannelId;
use russh::client::{self, Config};
use russh::server::Session;
use tokio::sync;

use crate::certificat_authority::key_from_openssh;
use crate::certificat_authority::{CaRequest, CaResponse};
use crate::ssh_server::{AuthMethod, ConnectionHandler};

/// Handles a user key signing request.
///
/// Reads the public key from the channel data, sends it to the CA for signing,
/// and returns the signed certificate to the client. Only password-authenticated
/// users may request user certificates; public-key-authenticated clients are rejected.
pub async fn handler_sign_user_key(
    handler: &mut ConnectionHandler,
    channel: ChannelId,
    data: &[u8],
    session: &mut Session,
) -> Result<(), russh::Error> {
    let username = handler.username.clone().expect("user not set");
    if let Some(AuthMethod::PublicKey) = handler.auth_method {
        let error_message =
            format!("Public key authenticated users can only request host certificates.");
        error!("{}", &error_message);
        let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
        return Ok(());
    }
    let openssh_key = String::from_utf8_lossy(data).to_string();
    let public_key = match key_from_openssh(&openssh_key) {
        Err(e) => {
            let error_message = format!("failed to read openssh public key: {}", e);
            error!("{}", &error_message);
            let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
            return Ok(());
        }
        Ok(key) => key,
    };

    info!(
        "user {} requested signing of key: {}",
        username, openssh_key
    );
    let cert = match handler
        .server
        .ca_client
        .send_request(CaRequest::SignCertificate {
            user: username.clone(),
            public_key: public_key.clone(),
        })
        .await
    {
        Ok(CaResponse::SignedCertificate(cert)) => cert,
        Ok(CaResponse::Error(e)) => {
            let error_message = format!("CA server error: {}", e);
            error!("{}", &error_message);
            let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
            return Ok(());
        }
        Err(e) => {
            let error_message = format!("Failed to send request to CA server: {}", e);
            error!("{}", &error_message);
            let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
            return Ok(());
        }
        Ok(CaResponse::KeyFound(_)) => {
            panic!("Signing request replied with KeyFound, which must not happen")
        }
    };
    let openssh_cert = match cert.to_openssh() {
        Ok(cert) => cert,
        Err(e) => {
            let error_message = format!("failed to convert cert to openssh format: {}", e);
            error!("{}", &error_message);
            let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
            return Ok(());
        }
    };

    //send data back and close connection
    let _ = session.data(channel, openssh_cert);
    let _ = session.exit_status_request(channel, 0);
    let _ = session.eof(channel);
    let _ = session.close(channel);
    Ok(())
}
