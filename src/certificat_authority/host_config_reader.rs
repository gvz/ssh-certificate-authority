//! # Host Defaults Reader
//!
//! This module is responsible for reading and parsing host-specific certificate templates.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Result, anyhow};
use glob::glob;
use log::{debug, error, warn};
use serde::Deserialize;
use ssh_key::PublicKey;

use crate::certificat_authority::config;

/// Verifies that `candidate` is contained within `base_dir` after canonicalization.
///
/// Both paths are canonicalized to resolve symlinks and `..` components, then
/// `candidate` is checked to be a child of `base_dir`. Returns an error if
/// canonicalization fails or the candidate escapes the base directory.
fn ensure_path_within_directory(candidate: &Path, base_dir: &Path) -> Result<std::path::PathBuf> {
    let canonical_base = base_dir.canonicalize().map_err(|e| {
        error!(
            "failed to canonicalize base directory {:?}: {}",
            base_dir, e
        );
        anyhow!("failed to resolve inventory directory: {}", e)
    })?;
    let canonical_candidate = candidate.canonicalize().map_err(|e| {
        error!(
            "failed to canonicalize candidate path {:?}: {}",
            candidate, e
        );
        anyhow!("failed to resolve host config path: {}", e)
    })?;
    if !canonical_candidate.starts_with(&canonical_base) {
        error!(
            "path traversal detected: {:?} is not within {:?}",
            canonical_candidate, canonical_base
        );
        return Err(anyhow!("path traversal detected in host name"));
    }
    Ok(canonical_candidate)
}

/// Represents the host-specific certificate parameters.
#[derive(Deserialize, Debug)]
pub struct HostConfig {
    /// Hosts public key
    pub public_key: String,
    /// The validity period of the certificate in days.
    pub validity_in_days: u16,
    /// A list of principals (e.g., hostnames) to be included in the certificate.
    pub hostnames: Vec<String>,
    /// A list of extensions to be included in the certificate.
    pub extensions: Vec<String>,
}

/// Reads and parses the host-specific certificate template for a given host.
///
/// # Arguments
///
/// * `host_name` - The hostname for which to read the defaults.
/// * `config` - The CA configuration containing the path to the host template.
///
/// # Returns
///
/// A `Result` containing the `HostConfig` for the host or an error.
pub fn read_host_config(host_name: &str, config: &config::Ca) -> Result<HostConfig> {
    let mut host_inventory_path = config.host_inventory.clone();
    host_inventory_path.push(format!("{}.toml", host_name));

    // Verify the resolved path stays within the host inventory directory
    let safe_path = ensure_path_within_directory(&host_inventory_path, &config.host_inventory)?;

    let host_config = read_config(safe_path.to_str().unwrap())?;
    Ok(host_config)
}

/// Searches the host inventory for a configuration whose public key matches the given key.
///
/// Returns `Some((host_name, config))` if a match is found, or `None` otherwise.
pub fn find_config_by_public_key(
    public_key: &str,
    config: &config::Ca,
) -> Option<(String, HostConfig)> {
    // Parse the search key once up front; reject malformed input early.
    let search_key = match PublicKey::from_openssh(public_key) {
        Ok(k) => k,
        Err(e) => {
            warn!("malformed search public key: {}", e);
            return None;
        }
    };

    // Canonicalize the inventory path before constructing the glob pattern
    // to prevent unsanitized config paths from affecting glob behavior
    let canonical_inventory = match config.host_inventory.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            error!(
                "failed to canonicalize host inventory path {:?}: {}",
                config.host_inventory, e
            );
            return None;
        }
    };
    for file in glob(&format!(
        "{}/**/*.toml",
        canonical_inventory.to_str().unwrap()
    ))
    .unwrap()
    .flatten()
    {
        // Verify each glob result stays within the inventory directory
        // (defense against symlink attacks within the inventory)
        let canonical_file = match file.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                warn!("skipping unresolvable path {:?}: {}", file, e);
                continue;
            }
        };
        if !canonical_file.starts_with(&canonical_inventory) {
            warn!(
                "skipping file outside inventory directory: {:?}",
                canonical_file
            );
            continue;
        }
        debug!("checking for public key in {}", file.to_str().unwrap());
        let host_config = match read_config(file.to_str().unwrap()) {
            Err(e) => {
                error!(
                    "skipping unreadable host config {:?}: {} — fix or remove this file to avoid auth disruption",
                    file, e
                );
                continue;
            }
            Ok(conf) => conf,
        };
        let config_pub_key = match PublicKey::from_openssh(&host_config.public_key) {
            Ok(k) => k,
            Err(e) => {
                warn!("skipping malformed key in config {:?}: {}", file, e);
                continue;
            }
        };
        if config_pub_key.key_data() != search_key.key_data() {
            debug!(
                "host key not matching for {}",
                host_config.hostnames.first().map(|s| s.as_str()).unwrap_or("<unknown>")
            );
            continue;
        }
        debug!(
            "host for public key found: {}",
            host_config.hostnames.first().map(|s| s.as_str()).unwrap_or("<unknown>")
        );
        let file_stem = file.file_stem().unwrap().to_str().unwrap().to_string();
        return Some((file_stem, host_config));
    }
    None
}

fn read_config(file: &str) -> Result<HostConfig> {
    let mut config_file = match File::open(&file).map_err(|e| {
        error!("failed to open host inventory, {:?}: {}", &file, e);
        e
    }) {
        Err(e) => {
            error!("failed to read {}: {}", file, e);
            return Err(e.into());
        }
        Ok(config_file) => config_file,
    };
    let mut config_text = String::new();
    let _ = match config_file.read_to_string(&mut config_text).map_err(|e| {
        error!("failed to read host template, {:?}: {}", &file, e);
        e
    }) {
        Err(e) => {
            error!("failed to read to string {}: {}", config_text, e);
            return Err(e.into());
        }
        Ok(_) => {}
    };
    let config: HostConfig = toml::from_str(&config_text)?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    /// Tests that `ensure_path_within_directory` accepts a valid path within the base directory.
    #[test]
    fn test_ensure_path_within_directory_valid() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create a file within the base directory
        let valid_file = base_path.join("valid.toml");
        fs::write(&valid_file, "test").unwrap();

        let result = ensure_path_within_directory(&valid_file, base_path);
        assert!(result.is_ok(), "Valid path should be accepted");
        assert_eq!(result.unwrap(), valid_file.canonicalize().unwrap());
    }

    /// Tests that `ensure_path_within_directory` rejects path traversal attempts using `..`
    #[test]
    fn test_ensure_path_within_directory_rejects_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create a file outside the base directory
        let parent_dir = base_path.parent().unwrap();
        let outside_file = parent_dir.join("outside.toml");
        fs::write(&outside_file, "test").unwrap();

        // Try to access it using .. from within base_path
        let traversal_path = base_path.join("..").join("outside.toml");

        let result = ensure_path_within_directory(&traversal_path, base_path);
        assert!(result.is_err(), "Path traversal should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("path traversal"),
            "Error should mention path traversal"
        );
    }

    /// Tests that `ensure_path_within_directory` rejects absolute paths outside the base directory.
    #[test]
    fn test_ensure_path_within_directory_rejects_absolute_outside() {
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();

        let base_path = temp_dir1.path();
        let outside_file = temp_dir2.path().join("outside.toml");
        fs::write(&outside_file, "test").unwrap();

        let result = ensure_path_within_directory(&outside_file, base_path);
        assert!(
            result.is_err(),
            "Absolute path outside base should be rejected"
        );
        assert!(
            result.unwrap_err().to_string().contains("path traversal"),
            "Error should mention path traversal"
        );
    }

    /// Tests that `ensure_path_within_directory` handles symlinks correctly.
    /// A symlink pointing outside the base directory should be rejected.
    #[test]
    #[cfg(unix)]
    fn test_ensure_path_within_directory_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create a file outside the base directory
        let parent_dir = base_path.parent().unwrap();
        let outside_file = parent_dir.join("outside.toml");
        fs::write(&outside_file, "test").unwrap();

        // Create a symlink inside base_path that points to the outside file
        let symlink_path = base_path.join("symlink.toml");
        symlink(&outside_file, &symlink_path).unwrap();

        let result = ensure_path_within_directory(&symlink_path, base_path);
        assert!(result.is_err(), "Symlink escape should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("path traversal"),
            "Error should mention path traversal"
        );
    }

    /// Tests that `ensure_path_within_directory` handles nested directories correctly.
    #[test]
    fn test_ensure_path_within_directory_nested_valid() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create a nested directory structure
        let nested_dir = base_path.join("subdir1").join("subdir2");
        fs::create_dir_all(&nested_dir).unwrap();

        let nested_file = nested_dir.join("nested.toml");
        fs::write(&nested_file, "test").unwrap();

        let result = ensure_path_within_directory(&nested_file, base_path);
        assert!(result.is_ok(), "Nested valid path should be accepted");
        assert_eq!(result.unwrap(), nested_file.canonicalize().unwrap());
    }

    /// Tests `find_config_by_public_key` with a matching key.
    #[test]
    fn test_find_config_by_public_key_match() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create a host config file with a known public key
        let test_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGPvWF5WtFPlxWSSr4xSg5sAR7Wdp5zZd7hqmZvC4Fkj";
        let host_config = format!(
            r#"
public_key = "{} comment"
validity_in_days = 30
hostnames = ["testhost.example.com"]
extensions = []
"#,
            test_key
        );

        let config_file = base_path.join("testhost.toml");
        let mut file = fs::File::create(&config_file).unwrap();
        file.write_all(host_config.as_bytes()).unwrap();

        let ca_config = config::Ca {
            user_list_file: base_path.join("user.toml"),
            ca_key: base_path.join("ca_key"),
            default_user_template: base_path.join("user_default.toml"),
            host_inventory: base_path.to_path_buf(),
        };

        let result = find_config_by_public_key(test_key, &ca_config);
        assert!(result.is_some(), "Should find matching host config");

        let (hostname, config) = result.unwrap();
        assert_eq!(hostname, "testhost");
        assert_eq!(config.validity_in_days, 30);
        assert_eq!(config.hostnames, vec!["testhost.example.com"]);
    }

    /// Tests `find_config_by_public_key` with a non-matching key.
    #[test]
    fn test_find_config_by_public_key_no_match() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create a host config file with a different public key
        let stored_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGPvWF5WtFPlxWSSr4xSg5sAR7Wdp5zZd7hqmZvC4Fkj";
        let search_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDifferentKeyDataHereXXXXXXXXXXXXXXXXXXXXX";

        let host_config = format!(
            r#"
public_key = "{} comment"
validity_in_days = 30
hostnames = ["testhost.example.com"]
extensions = []
"#,
            stored_key
        );

        let config_file = base_path.join("testhost.toml");
        let mut file = fs::File::create(&config_file).unwrap();
        file.write_all(host_config.as_bytes()).unwrap();

        let ca_config = config::Ca {
            user_list_file: base_path.join("user.toml"),
            ca_key: base_path.join("ca_key"),
            default_user_template: base_path.join("user_default.toml"),
            host_inventory: base_path.to_path_buf(),
        };

        let result = find_config_by_public_key(search_key, &ca_config);
        assert!(result.is_none(), "Should not find non-matching key");
    }

    /// Tests `find_config_by_public_key` with a malformed key in config.
    #[test]
    fn test_find_config_by_public_key_malformed_key() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create a host config file with a malformed public key (missing key data)
        let host_config = r#"
public_key = "ssh-ed25519"
validity_in_days = 30
hostnames = ["testhost.example.com"]
extensions = []
"#;

        let config_file = base_path.join("testhost.toml");
        let mut file = fs::File::create(&config_file).unwrap();
        file.write_all(host_config.as_bytes()).unwrap();

        let ca_config = config::Ca {
            user_list_file: base_path.join("user.toml"),
            ca_key: base_path.join("ca_key"),
            default_user_template: base_path.join("user_default.toml"),
            host_inventory: base_path.to_path_buf(),
        };

        let search_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGPvWF5WtFPlxWSSr4xSg5sAR7Wdp5zZd7hqmZvC4Fkj";

        // Should handle malformed key gracefully and not find a match
        let result = find_config_by_public_key(search_key, &ca_config);
        assert!(result.is_none(), "Should not match malformed key");
    }
}
