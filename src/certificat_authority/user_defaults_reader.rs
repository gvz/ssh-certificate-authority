//! # User Defaults Reader
//!
//! This module is responsible for reading and parsing user-specific certificate templates.
//! It uses a combination of TOML and Jinja2 templates to allow for dynamic generation
//! of certificate parameters based on the user.
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use log::{debug, error};
use minijinja::{Environment, context};
use serde::Deserialize;

use crate::certificat_authority::config;

/// Maximum allowed size for a user certificate template file in bytes.
/// Templates are small TOML files; 64 KiB is generous. This limit
/// defends against adversarial template content that could trigger
/// unbounded memory allocation during minijinja compilation.
const MAX_TEMPLATE_SIZE: usize = 64 * 1024;

/// Represents the user-specific certificate parameters.
#[derive(Deserialize, Debug)]
pub struct UserDefaults {
    /// The validity period of the certificate in days.
    pub validity_in_days: u16,
    /// A list of principals (e.g., usernames) to be included in the certificate.
    pub principals: Vec<String>,
    /// A list of extensions to be included in the certificate.
    pub extensions: Vec<String>,
}
#[derive(Deserialize, Debug)]
struct UserList {
    pub users: HashMap<String, PathBuf>,
}

/// Reads and parses the user-specific certificate template for a given user.
///
/// It first reads the user list file to find the template for the specified user.
/// If no specific template is found, it uses the default template.
/// It then uses Jinja2 to render the template with the username and parses the
/// result as a `UserDefaults` struct.
///
/// # Arguments
///
/// * `user` - The username for which to read the defaults.
/// * `config` - The CA configuration containing the paths to the user list and default template.
///
/// # Returns
///
/// A `Result` containing the `UserDefaults` for the user or an error.
pub fn read_user_defaults(user: &str, config: &config::Ca) -> Result<UserDefaults> {
    let user_file_map: UserList = super::read_toml_file(&config.user_list_file)?;

    // use specified config for user or defaut if user has no defaults defined
    let template_path = match user_file_map.users.get(user) {
        Some(path) => {
            debug!("user specific template: {:?}", path);
            if path.is_relative() {
                let user_file_path = config.user_list_file.to_path_buf();
                let template_path = match user_file_path.parent() {
                    None => panic!("user list file does not have parent: {:?}", user_file_path),
                    Some(path) => path,
                };
                template_path.join(path)
            } else {
                path.to_path_buf()
            }
        }
        None => config.default_user_template.clone(),
    };

    let mut template_file = File::open(&template_path).map_err(|e| {
        error!("failed to open user template, {:?}: {}", &template_path, e);
        e
    })?;
    let mut template_text = String::new();
    let _ = template_file
        .read_to_string(&mut template_text)
        .map_err(|e| {
            error!("failed to read user template, {:?}: {}", &template_path, e);
            e
        })?;

    if template_text.len() > MAX_TEMPLATE_SIZE {
        error!(
            "user template exceeds maximum size ({} bytes): {:?}",
            template_text.len(),
            &template_path
        );
        anyhow::bail!(
            "user template {:?} exceeds maximum allowed size of {} bytes",
            &template_path,
            MAX_TEMPLATE_SIZE
        );
    }

    let mut jinja_env = Environment::new();
    jinja_env.add_template(user, &template_text)?;
    let user_template = jinja_env.get_template(user)?;
    let user_defaults = user_template.render(context!(user_name => user))?;

    let template: UserDefaults = toml::from_str(&user_defaults)?;

    Ok(template)
}

#[cfg(test)]
mod test {
    use super::*;
    use ssh_key::Algorithm;
    use ssh_key::private::PrivateKey;
    use ssh_key::rand_core::OsRng;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn read_user_defaults_test() {
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let mut ca_key_file = NamedTempFile::new().unwrap();
        ca_key_file.write_all(ca_key_openssh.as_bytes()).unwrap();
        ca_key_file.flush().unwrap();
        let ca_key_path = ca_key_file.path();
        let ca_config = config::Ca {
            user_list_file: PathBuf::from("./config/user.toml"),
            default_user_template: PathBuf::from("./config/user_default.toml"),
            ca_key: ca_key_path.to_path_buf(),
            host_inventory: PathBuf::from("./config/hosts"),
        };
        let config = read_user_defaults("test", &ca_config).unwrap();
        println!("{:?}", config.validity_in_days);
    }

    /// Tests that Jinja2 template rendering correctly substitutes the username.
    #[test]
    fn test_template_rendering_username_substitution() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create CA key
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let ca_key_path = base_path.join("ca_key");
        std::fs::write(&ca_key_path, ca_key_openssh.as_bytes()).unwrap();

        // Create user list without specific user
        let user_list = r#"[users]"#;
        let user_list_path = base_path.join("user.toml");
        std::fs::write(&user_list_path, user_list).unwrap();

        // Create template that uses username variable
        let user_template = r#"
validity_in_days = 1
principals = ["{{ user_name }}", "{{ user_name }}-admin"]
extensions = ["permit-pty"]
"#;
        let user_template_path = base_path.join("user_default.toml");
        std::fs::write(&user_template_path, user_template).unwrap();

        let ca_config = config::Ca {
            user_list_file: user_list_path,
            ca_key: ca_key_path,
            default_user_template: user_template_path,
            host_inventory: base_path.join("hosts"),
        };

        let result = read_user_defaults("alice", &ca_config).unwrap();

        assert_eq!(result.principals.len(), 2);
        assert_eq!(result.principals[0], "alice");
        assert_eq!(result.principals[1], "alice-admin");
        assert_eq!(result.validity_in_days, 1);
        assert_eq!(result.extensions, vec!["permit-pty"]);
    }

    /// Tests that user-specific templates override the default template.
    #[test]
    fn test_user_specific_template_override() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create CA key
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let ca_key_path = base_path.join("ca_key");
        std::fs::write(&ca_key_path, ca_key_openssh.as_bytes()).unwrap();

        // Create user-specific template
        let admin_template = r#"
validity_in_days = 30
principals = ["{{ user_name }}", "root", "admin"]
extensions = ["permit-pty", "permit-port-forwarding", "permit-agent-forwarding"]
"#;
        let admin_template_path = base_path.join("admin_template.toml");
        std::fs::write(&admin_template_path, admin_template).unwrap();

        // Create user list with specific user pointing to custom template
        let user_list = r#"
[users]
admin = "admin_template.toml"
"#;
        let user_list_path = base_path.join("user.toml");
        std::fs::write(&user_list_path, user_list).unwrap();

        // Create default template (different from admin template)
        let default_template = r#"
validity_in_days = 1
principals = ["{{ user_name }}"]
extensions = ["permit-pty"]
"#;
        let default_template_path = base_path.join("user_default.toml");
        std::fs::write(&default_template_path, default_template).unwrap();

        let ca_config = config::Ca {
            user_list_file: user_list_path,
            ca_key: ca_key_path,
            default_user_template: default_template_path,
            host_inventory: base_path.join("hosts"),
        };

        // Test admin user (should use custom template)
        let admin_result = read_user_defaults("admin", &ca_config).unwrap();
        assert_eq!(admin_result.validity_in_days, 30);
        assert_eq!(admin_result.principals.len(), 3);
        assert_eq!(admin_result.principals[0], "admin");
        assert_eq!(admin_result.principals[1], "root");
        assert_eq!(admin_result.principals[2], "admin");
        assert_eq!(admin_result.extensions.len(), 3);

        // Test regular user (should use default template)
        let regular_result = read_user_defaults("regularuser", &ca_config).unwrap();
        assert_eq!(regular_result.validity_in_days, 1);
        assert_eq!(regular_result.principals.len(), 1);
        assert_eq!(regular_result.principals[0], "regularuser");
        assert_eq!(regular_result.extensions, vec!["permit-pty"]);
    }

    /// Tests that relative paths in user list are resolved correctly.
    #[test]
    fn test_relative_path_resolution() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create CA key
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let ca_key_path = base_path.join("ca_key");
        std::fs::write(&ca_key_path, ca_key_openssh.as_bytes()).unwrap();

        // Create subdirectory for templates
        let templates_dir = base_path.join("templates");
        std::fs::create_dir(&templates_dir).unwrap();

        // Create user-specific template in subdirectory
        let user_template = r#"
validity_in_days = 5
principals = ["{{ user_name }}"]
extensions = []
"#;
        let user_template_path = templates_dir.join("special.toml");
        std::fs::write(&user_template_path, user_template).unwrap();

        // Create user list with relative path
        let user_list = r#"
[users]
special = "templates/special.toml"
"#;
        let user_list_path = base_path.join("user.toml");
        std::fs::write(&user_list_path, user_list).unwrap();

        // Create default template
        let default_template = r#"
validity_in_days = 1
principals = ["{{ user_name }}"]
extensions = []
"#;
        let default_template_path = base_path.join("user_default.toml");
        std::fs::write(&default_template_path, default_template).unwrap();

        let ca_config = config::Ca {
            user_list_file: user_list_path,
            ca_key: ca_key_path,
            default_user_template: default_template_path,
            host_inventory: base_path.join("hosts"),
        };

        let result = read_user_defaults("special", &ca_config).unwrap();
        assert_eq!(result.validity_in_days, 5);
    }

    /// Tests that template parsing handles empty extensions list.
    #[test]
    fn test_empty_extensions() {
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

        // Create template with empty extensions
        let user_template = r#"
validity_in_days = 1
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

        let result = read_user_defaults("testuser", &ca_config).unwrap();
        assert_eq!(result.extensions.len(), 0);
    }
}
