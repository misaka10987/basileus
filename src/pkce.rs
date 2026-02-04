use std::{collections::HashMap, fmt::Display, sync::Mutex};

use base64::{Engine, prelude::BASE64_URL_SAFE};
use sha2::{Digest, Sha256};

use crate::{
    Basileus,
    err::{BeginPkceError, VerifyPkceError},
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pkce {
    /// Base64URL-encoded [code challenge](https://datatracker.ietf.org/doc/html/rfc7636#section-4.2).
    pub code_challenge: String,
    /// The code challenge method, **must** be "S256".
    pub code_challenge_method: String,
}

impl Pkce {
    pub fn new(code_challenge: String) -> Self {
        Self {
            code_challenge,
            code_challenge_method: "S256".into(),
        }
    }
}

impl Display for Pkce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PKCE {}:{}",
            self.code_challenge_method, self.code_challenge
        )
    }
}

pub struct PkceModule {
    /// Map from PKCE challenges to their beloinging users.
    pending: Mutex<HashMap<Pkce, String>>,
}

impl PkceModule {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }
}

impl Basileus {
    pub async fn begin_pkce(
        &self,
        user: &str,
        pass: &str,
        pkce: Pkce,
    ) -> Result<(), BeginPkceError> {
        if !self.verify_pass(user, pass).await? {
            return Err(BeginPkceError::Unauthorized);
        }
        if pkce.code_challenge_method != "S256" {
            return Err(BeginPkceError::UnsupportedMethod);
        }
        self.pkce.pending.lock().unwrap().insert(pkce, user.into());
        Ok(())
    }

    pub fn verify_pkce(&self, code_verifier: &str) -> Result<String, VerifyPkceError> {
        let hash = Sha256::digest(code_verifier);
        let code_challenge = BASE64_URL_SAFE.encode(hash);
        let pkce = Pkce::new(code_challenge);

        let mut pending = self.pkce.pending.lock().unwrap();

        if let Some(user) = pending.remove(&pkce) {
            Ok(user)
        } else {
            Err(VerifyPkceError::InvalidVerifier)
        }
    }
}
