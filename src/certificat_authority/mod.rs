//! # Certificate Authority
//!
//! This module provides the core functionality for the Certificate Authority (CA).
//! It is responsible for signing SSH certificates based on user requests.
use std::fs::File;
use std::io::Read;

use anyhow::Result;
#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use ssh_key::rand_core::{OsRng, RngCore};
use ssh_key::{
    PublicKey,
    certificate::{Builder as CertBuilder, CertType, Certificate},
    private::PrivateKey,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum size (in bytes) for a single IPC message on the Unix socket.
/// Both client and server enforce this limit to prevent OOM denial of service.
/// 64 KiB is generous for any legitimate request (SSH public keys + JSON
/// envelope are typically well under 16 KiB).
pub const MAX_MESSAGE_SIZE: u32 = 65_536;

/// Client for communicating with the CA server over a Unix socket.
pub mod ca_client;
/// CA server that listens for signing requests on a Unix socket.
pub mod ca_server;
/// Configuration types for the Certificate Authority.
pub mod config;
mod host_config_reader;
mod user_defaults_reader;

/// Errors that can occur during CA operations.
#[derive(Debug, Error)]
pub enum CaError {
    /// The public key presented by the host does not match the one in its configuration.
    #[error("wrong public key for host: {0}")]
    WrongPublicKey(String),
}

/// Represents the Certificate Authority.
pub struct CertificateAuthority {
    private_key: PrivateKey,
    config: config::Ca,
}

impl CertificateAuthority {
    /// Creates a new `CertificateAuthority` instance.
    ///
    /// # Arguments
    ///
    /// * `ca_config` - The configuration for the CA.
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `CertificateAuthority` instance or an error.
    pub fn new(ca_config: &config::Ca) -> Result<Self> {
        let mut key_file = File::open(ca_config.ca_key.clone())?;
        let mut key_buffer = Zeroizing::new(Vec::new());
        key_file.read_to_end(&mut key_buffer)?;

        let private_key = PrivateKey::from_openssh(key_buffer)?;
        Ok(CertificateAuthority {
            private_key,
            config: ca_config.clone(),
        })
    }

    /// Signs an SSH public key and returns a certificate.
    ///
    /// # Arguments
    ///
    /// * `user` - The username associated with the public key.
    /// * `public_key` - The public key to be signed.
    ///
    /// # Returns
    ///
    /// A `Result` containing the signed `Certificate` or an error.
    pub fn sign_certificate(&self, user: &str, public_key: &PublicKey) -> Result<Certificate> {
        // Initialize certificate builder
        info!(
            "signing {} for {}",
            public_key
                .to_openssh()
                .unwrap_or_else(|_| "broken public key".to_string()),
            user
        );
        let user_defaults = user_defaults_reader::read_user_defaults(user, &self.config)?;
        let valid_after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + (user_defaults.validity_in_days as u64 * 86400_u64);
        let mut cert_builder =
            CertBuilder::new_with_random_nonce(&mut OsRng, public_key, valid_after, valid_before)?;
        cert_builder.serial(OsRng.next_u64())?;
        cert_builder.key_id(&format!("user-{}-{}", user, valid_after))?;
        cert_builder.cert_type(CertType::User)?;
        for principal in user_defaults.principals {
            debug!("adding principal: {}", principal);
            let _ = cert_builder.valid_principal(principal); // Unix username or hostname
        }

        cert_builder.comment(public_key.comment())?; // Comment (typically an email address)
        for extension in user_defaults.extensions {
            cert_builder.extension(extension, "")?;
        }

        // Sign and return the `Certificate` for `subject_public_key`
        let cert = match cert_builder.sign(&self.private_key) {
            Ok(cert) => cert,
            Err(e) => {
                error!("signing failed: {}", e);
                return Err(e.into());
            }
        };
        Ok(cert)
    }

    /// Checks whether the given public key belongs to a known host.
    ///
    /// Returns `Some(host_name)` if a matching host configuration is found,
    /// or `None` otherwise.
    pub fn check_public_key(&self, public_key: &str) -> Option<String> {
        match host_config_reader::find_config_by_public_key(public_key, &self.config) {
            Some((host_name, _)) => Some(host_name),
            None => None,
        }
    }

    /// Signs an SSH public key and returns a certificate.
    ///
    /// # Arguments
    ///
    /// * `host_name` - The hostname associated with the public key.
    /// * `public_key` - The public key to be signed.
    ///
    /// # Returns
    ///
    /// A `Result` containing the signed `Certificate` or an error.
    pub fn sign_host_certificate(
        &self,
        host_name: &str,
        public_key: &PublicKey,
    ) -> Result<Certificate> {
        // Initialize certificate builder
        info!(
            "signing {} for {}",
            public_key
                .to_openssh()
                .unwrap_or_else(|_| "broken public key".to_string()),
            host_name
        );
        let host_config = host_config_reader::read_host_config(host_name, &self.config)?;
        let config_pub_key = PublicKey::from_openssh(&host_config.public_key).map_err(|e| {
            error!("Failed to parse config public key: {}", e);
            CaError::WrongPublicKey(host_name.to_string())
        })?;

        if config_pub_key.key_data() != public_key.key_data() {
            error!("Key Mismatch for host {}", host_name);
            error!("Config Key: {}", config_pub_key.to_openssh().unwrap());
            error!("Client Key: {}", public_key.to_openssh().unwrap());
            return Err(CaError::WrongPublicKey(host_name.to_string()).into());
        }
        let valid_after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + (host_config.validity_in_days as u64 * 86400_u64);
        let mut cert_builder =
            CertBuilder::new_with_random_nonce(&mut OsRng, public_key, valid_after, valid_before)?;
        cert_builder.serial(OsRng.next_u64())?;
        cert_builder.key_id(&format!("host-{}-{}", host_name, valid_after))?;
        cert_builder.cert_type(CertType::Host)?;
        for principal in host_config.hostnames {
            debug!("adding principal: {}", principal);
            let _ = cert_builder.valid_principal(principal); // Unix username or hostname
        }

        cert_builder.comment(public_key.comment())?; // Comment (typically an email address)
        for extension in host_config.extensions {
            cert_builder.extension(extension, "")?;
        }

        // Sign and return the `Certificate` for `subject_public_key`
        let cert = match cert_builder.sign(&self.private_key) {
            Ok(cert) => cert,
            Err(e) => {
                error!("signing failed: {}", e);
                return Err(e.into());
            }
        };
        Ok(cert)
    }
}

/// Parses an OpenSSH public key string into a `PublicKey` object.
///
/// # Arguments
///
/// * `openssh_key` - The OpenSSH public key string.
///
/// # Returns
///
/// A `Result` containing the `PublicKey` or an error.
pub fn key_from_openssh(openssh_key: &str) -> Result<PublicKey> {
    Ok(PublicKey::from_openssh(openssh_key)?)
}

/// Represents a request to the Certificate Authority.
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum CaRequest {
    /// A request to sign a certificate.
    SignCertificate {
        user: String,
        #[cfg_attr(feature = "arbitrary", arbitrary(with = arbitrary_public_key))]
        public_key: PublicKey,
    },
    /// A request to check whether a public key belongs to a known host.
    CheckPublicKey {
        #[cfg_attr(feature = "arbitrary", arbitrary(with = arbitrary_public_key))]
        public_key: PublicKey,
    },
    /// A request to sign a host certificate.
    SignHostCertificate {
        host_name: String,
        #[cfg_attr(feature = "arbitrary", arbitrary(with = arbitrary_public_key))]
        public_key: PublicKey,
    },
}
#[cfg(feature = "arbitrary")]
pub fn arbitrary_public_key(u: &mut Unstructured) -> arbitrary::Result<PublicKey> {
    let key_bytes: [u8; 32] = u.arbitrary()?;
    // Construct a valid Ed25519 verifying key from the raw bytes.
    // `from_bytes` rejects points that are not on the curve, which is
    // the correct behaviour — the fuzzer will simply try another input.
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| arbitrary::Error::IncorrectFormat)?;
    let ed25519_pub = ssh_key::public::Ed25519PublicKey::from(verifying_key);
    Ok(PublicKey::from(ssh_key::public::KeyData::Ed25519(
        ed25519_pub,
    )))
}

/// Represents a response from the Certificate Authority.
#[derive(Serialize, Deserialize, Debug)]
pub enum CaResponse {
    /// A successfully signed certificate.
    SignedCertificate(Certificate),
    /// An error that occurred during processing.
    Error(String),
    /// is the key valid
    KeyFound(Option<String>),
}

/// An authenticated wrapper around [`CaRequest`] that provides bearer-token
/// authentication and monotonic-counter replay protection for the IPC channel.
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthenticatedRequest {
    /// Shared secret token generated at startup and exchanged via a temporary file.
    pub token: String,
    /// Strictly increasing counter — the server rejects any value ≤ the last accepted one.
    pub counter: u64,
    /// The inner CA request to execute after authentication succeeds.
    pub request: CaRequest,
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    use ssh_key::{Algorithm, private::PrivateKey};
    use tempfile::NamedTempFile;

    #[test]
    fn sign_certificate() {
        env_logger::init();

        // Generate the certificate authority's private key
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let mut ca_key_file = NamedTempFile::new().unwrap();
        ca_key_file.write_all(ca_key_openssh.as_bytes()).unwrap();
        ca_key_file.flush().unwrap();
        let ca_key_path = ca_key_file.path();

        // Generate a "subject" key to be signed by the certificate authority.
        // Normally a user or host would do this locally and give the certificate
        // authority the public key.
        let subject_private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let subject_public_key = subject_private_key.public_key();

        let ca_config = config::Ca {
            user_list_file: PathBuf::from("./config/user.toml"),
            ca_key: ca_key_path.to_path_buf(),
            default_user_template: PathBuf::from("./config/user_default.toml"),
            host_inventory: PathBuf::from("./config/hosts/"),
        };

        let authority = CertificateAuthority {
            private_key: ca_key,
            config: ca_config,
        };

        let cert = authority
            .sign_certificate("test", subject_public_key)
            .unwrap();

        println!("cert: {:?}", cert.extensions());
    }

    /// Tests that `sign_certificate` creates a certificate with correct principals.
    #[test]
    fn test_sign_certificate_principals() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create CA key
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let ca_key_path = base_path.join("ca_key");
        std::fs::write(&ca_key_path, ca_key_openssh.as_bytes()).unwrap();

        // Create user list
        let user_list = r#"[users]"#;
        let user_list_path = base_path.join("user.toml");
        std::fs::write(&user_list_path, user_list).unwrap();

        // Create user template with specific principals
        let user_template = r#"
validity_in_days = 1
principals = ["{{ user_name }}", "admin"]
extensions = ["permit-pty", "permit-port-forwarding"]
"#;
        let user_template_path = base_path.join("user_default.toml");
        std::fs::write(&user_template_path, user_template).unwrap();

        let ca_config = config::Ca {
            user_list_file: user_list_path,
            ca_key: ca_key_path,
            default_user_template: user_template_path,
            host_inventory: base_path.join("hosts"),
        };

        let authority = CertificateAuthority::new(&ca_config).unwrap();
        let subject_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let subject_public_key = subject_key.public_key();

        let cert = authority
            .sign_certificate("testuser", subject_public_key)
            .unwrap();

        // Verify certificate properties
        assert_eq!(cert.cert_type(), CertType::User);
        assert!(cert.key_id().starts_with("user-testuser-"));

        // Verify principals
        let principals: Vec<&str> = cert
            .valid_principals()
            .into_iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(principals.len(), 2);
        assert!(principals.contains(&"testuser"));
        assert!(principals.contains(&"admin"));

        // Verify extensions
        let extensions: Vec<(&str, &str)> = cert
            .extensions()
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert!(extensions.iter().any(|(k, _)| *k == "permit-pty"));
        assert!(
            extensions
                .iter()
                .any(|(k, _)| *k == "permit-port-forwarding")
        );
    }

    /// Tests that `sign_certificate` creates certificates with correct validity period.
    #[test]
    fn test_sign_certificate_validity() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create CA key
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let ca_key_path = base_path.join("ca_key");
        std::fs::write(&ca_key_path, ca_key_openssh.as_bytes()).unwrap();

        // Create user list
        let user_list = r#"[users]"#;
        let user_list_path = base_path.join("user.toml");
        std::fs::write(&user_list_path, user_list).unwrap();

        // Create user template with 7 days validity
        let user_template = r#"
validity_in_days = 7
principals = ["{{ user_name }}"]
extensions = []
"#;
        let user_template_path = base_path.join("user_default.toml");
        std::fs::write(&user_template_path, user_template).unwrap();

        let ca_config = config::Ca {
            user_list_file: user_list_path,
            ca_key: ca_key_path,
            default_user_template: user_template_path,
            host_inventory: base_path.join("hosts"),
        };

        let authority = CertificateAuthority::new(&ca_config).unwrap();
        let subject_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let subject_public_key = subject_key.public_key();

        let before_signing = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cert = authority
            .sign_certificate("testuser", subject_public_key)
            .unwrap();

        let after_signing = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Valid after should be around the current time
        assert!(cert.valid_after() >= before_signing);
        assert!(cert.valid_after() <= after_signing);

        // Valid before should be 7 days (604800 seconds) after valid_after
        let expected_duration = 7 * 86400;
        let actual_duration = cert.valid_before() - cert.valid_after();
        assert_eq!(actual_duration, expected_duration);
    }

    /// Tests that `check_public_key` returns the correct hostname for a known key.
    #[test]
    fn test_check_public_key_found() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create CA key
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let ca_key_path = base_path.join("ca_key");
        std::fs::write(&ca_key_path, ca_key_openssh.as_bytes()).unwrap();

        // Create host inventory
        let host_inventory = base_path.join("hosts");
        std::fs::create_dir(&host_inventory).unwrap();

        // Create a host config with a known key
        let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let host_public_key_str = host_key.public_key().to_openssh().unwrap();

        let host_config = format!(
            r#"
public_key = "{}"
validity_in_days = 30
hostnames = ["myserver.example.com"]
extensions = []
"#,
            host_public_key_str
        );

        std::fs::write(host_inventory.join("myserver.toml"), host_config).unwrap();

        let ca_config = config::Ca {
            user_list_file: base_path.join("user.toml"),
            ca_key: ca_key_path,
            default_user_template: base_path.join("user_default.toml"),
            host_inventory,
        };

        let authority = CertificateAuthority::new(&ca_config).unwrap();

        // Extract just the key type and data (first two fields)
        let key_parts: Vec<&str> = host_public_key_str.split_whitespace().collect();
        let search_key = format!("{} {}", key_parts[0], key_parts[1]);

        let result = authority.check_public_key(&search_key);
        assert_eq!(result, Some("myserver".to_string()));
    }

    /// Tests that `check_public_key` returns None for an unknown key.
    #[test]
    fn test_check_public_key_not_found() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create CA key
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let ca_key_path = base_path.join("ca_key");
        std::fs::write(&ca_key_path, ca_key_openssh.as_bytes()).unwrap();

        // Create empty host inventory
        let host_inventory = base_path.join("hosts");
        std::fs::create_dir(&host_inventory).unwrap();

        let ca_config = config::Ca {
            user_list_file: base_path.join("user.toml"),
            ca_key: ca_key_path,
            default_user_template: base_path.join("user_default.toml"),
            host_inventory,
        };

        let authority = CertificateAuthority::new(&ca_config).unwrap();

        // Search for a key that doesn't exist
        let unknown_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let unknown_public_key_str = unknown_key.public_key().to_openssh().unwrap();
        let key_parts: Vec<&str> = unknown_public_key_str.split_whitespace().collect();
        let search_key = format!("{} {}", key_parts[0], key_parts[1]);

        let result = authority.check_public_key(&search_key);
        assert_eq!(result, None);
    }
}
