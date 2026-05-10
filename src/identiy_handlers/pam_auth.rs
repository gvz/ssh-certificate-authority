use anyhow::Result;
use log::warn;
use nix::unistd::User;
use pam::Client;

use crate::identiy_handlers::{Credential, Error, UserAuthenticator};

/// A `UserAuthenticator` that uses PAM to authenticate users.
#[derive(Clone)]
pub(super) struct PamAuthenticator {}
impl UserAuthenticator for PamAuthenticator {
    fn authenticate(&self, username: &str, credential: Credential) -> Result<bool> {
        match credential {
            Credential::Password(password) => pam_authenticate_user(username, password),
        }
    }
    fn clone_box(&self) -> Box<dyn UserAuthenticator + Send + Sync> {
        Box::new(self.clone())
    }
}

/// Authenticates a user using PAM.
///
/// # Arguments
///
/// * `user` - The username to authenticate.
/// * `password` - The password to use for authentication.
///
/// # Returns
///
/// A `Result` containing `true` if the user is authenticated, `false` otherwise, or an error.
pub fn pam_authenticate_user(user: &str, password: &str) -> Result<bool> {
    if user == "root" {
        warn!("forbidden user was provided: {}", user);
        return Err(Error::ForbiddenUser(user.to_string()).into());
    }
    if let Ok(Some(u)) = User::from_name(user) {
        if u.uid.as_raw() < 1000 {
            warn!("system account login attempt blocked: {}", user);
            return Err(Error::ForbiddenUser(user.to_string()).into());
        }
    }

    let mut auth = Client::with_password("login")?;
    auth.conversation_mut().set_credentials(user, password);

    auth.authenticate()?;
    Ok(true)
}
