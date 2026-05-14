//! # Host Key Signer
//!
//! This module handles the `sign_host_key` command, which is used to sign host keys.
use crate::certificat_authority::CaRequest;
use crate::ssh_server::ConnectionHandler;
use crate::ssh_server::signing_common::{parse_openssh_key, send_cert_and_close, send_sign_request};
#[cfg(feature = "test_auth")]
use log::warn;
use log::{error, info};
use russh::ChannelId;
use russh::server::Session;

/// Validates that a hostname is safe for use as a filesystem path component.
///
/// Rejects empty strings, path separators (`/`, `\`), parent-directory
/// references (`..`), and embedded NUL bytes. This is defense-in-depth
/// before the CA's own path-traversal checks.
pub fn validate_hostname(host_name: &str) -> Result<(), String> {
    if host_name.is_empty()
        || host_name.contains('/')
        || host_name.contains('\\')
        || host_name.contains("..")
        || host_name.contains('\0')
    {
        return Err(format!("invalid host name: '{}'", host_name));
    }
    Ok(())
}

/// Handles the `sign_host_key` command.
///
/// This function takes the public key from the command arguments, sends it to the CA to be signed,
/// and returns the signed certificate to the user.
///
/// # Arguments
///
/// * `handler` - The connection handler.
/// * `channel` - The channel ID.
/// * `args` - The command arguments.
/// * `session` - The SSH session.
pub async fn handle_sign_host_key(
    handler: &mut ConnectionHandler,
    channel: ChannelId,
    args: Vec<&str>,
    session: &mut Session,
) -> Result<(), russh::Error> {
    if args.len() < 2 {
        let error_message = "Usage: sign_host_key <host_name> <public_key>";
        error!("{}: {:?}", &error_message, args);
        let _ = session.disconnect(russh::Disconnect::ByApplication, error_message, "en");
        return Ok(());
    }
    let host_name = args[0].to_string();

    // Early validation: reject hostnames containing path traversal characters
    // before they reach the CA. This is defense in depth — the CA also validates
    // that resolved paths stay within the inventory directory.
    if let Err(error_message) = validate_hostname(&host_name) {
        error!("{}", &error_message);
        let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
        return Ok(());
    }

    let ssh_key = args[1..].join(" ");
    let Some(public_key) = parse_openssh_key(&ssh_key, session) else {
        return Ok(());
    };

    #[cfg(feature = "test_auth")]
    warn!("test host verification");

    info!(
        "host {} requested signing of host key for host: {}",
        handler.username.as_ref().unwrap(),
        host_name
    );

    let Some(cert) = send_sign_request(
        &handler.server.ca_client,
        CaRequest::SignHostCertificate {
            host_name: host_name.clone(),
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
