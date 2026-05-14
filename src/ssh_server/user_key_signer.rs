use log::{error, info};
use russh::ChannelId;
use russh::server::Session;

use crate::certificat_authority::CaRequest;
use crate::ssh_server::{AuthMethod, ConnectionHandler};
use crate::ssh_server::signing_common::{parse_openssh_key, send_cert_and_close, send_sign_request};

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
        let error_message = "Public key authenticated users can only request host certificates.";
        error!("{}", error_message);
        let _ = session.disconnect(russh::Disconnect::ByApplication, error_message, "en");
        return Ok(());
    }
    let openssh_key = String::from_utf8_lossy(data).to_string();
    let Some(public_key) = parse_openssh_key(&openssh_key, session) else {
        return Ok(());
    };

    info!("user {} requested signing of key: {}", username, openssh_key);

    let Some(cert) = send_sign_request(
        &handler.server.ca_client,
        CaRequest::SignCertificate {
            user: username.clone(),
            public_key: public_key.clone(),
        },
        session,
    )
    .await
    else {
        return Ok(());
    };

    send_cert_and_close(cert, channel, session);
    Ok(())
}
