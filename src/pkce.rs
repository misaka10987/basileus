use std::{collections::HashMap, fmt::Display, sync::Mutex, time::Instant};

use base64::{Engine, prelude::BASE64_URL_SAFE};
use sha2::{Digest, Sha256};

use crate::{
    Basileus,
    err::{PkceAuthError, PkceTokenError},
};

/// A client PKCE code challenge, as defined in [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636#section-4.2).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CodeChallenge {
    /// Base64URL-encoded [code challenge](https://datatracker.ietf.org/doc/html/rfc7636#section-4.2).
    #[cfg_attr(feature = "serde", serde(rename = "code_challenge"))]
    pub challenge: String,
    /// The code challenge method, **must** be "S256".
    #[cfg_attr(feature = "serde", serde(rename = "code_challenge_method"))]
    pub method: String,
}

impl CodeChallenge {
    /// Create a new `CodeChallenge` object with specified base64URL-encoded code challenge.
    pub fn new(challenge: String) -> Self {
        Self {
            challenge,
            method: "S256".into(),
        }
    }

    /// Verify the `code_verifier` by checking if the hash matches the stored `code_challenge`.
    pub fn verify(&self, code_verifier: &str) -> bool {
        let hash = Sha256::digest(code_verifier);
        let encoded = BASE64_URL_SAFE.encode(hash);
        self.challenge == encoded
    }
}

impl Display for CodeChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.method, self.challenge)
    }
}

/// A pending PKCE authentication request.
pub struct Pkce {
    /// The authorized user name.
    pub user: String,
    /// The associated code challenge from the PKCE authorization request.
    pub code_challenge: CodeChallenge,
    /// Time of creation.
    pub begin: Instant,
}

impl Pkce {
    /// Create a new `Pkce` object with specified authorized user and code challenge.
    pub fn new(user: String, code_challenge: CodeChallenge) -> Self {
        Self {
            user,
            code_challenge,
            begin: Instant::now(),
        }
    }

    /// Check if the PKCE request is still valid.
    /// Expiry time is set to 10 minutes (600 seconds).
    pub fn valid(&self) -> bool {
        self.begin.elapsed().as_secs() <= 600
    }
}

pub struct PkceModule {
    /// Map from PKCE challenges to their beloinging users.
    pending: Mutex<HashMap<String, Pkce>>,
}

impl PkceModule {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }
}

impl Basileus {
    /// Handle a PKCE authorization request.
    ///
    /// If the authorization is successful, returns a base64URL-encoded [authorization code](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2).
    pub async fn pkce_auth_req(
        &self,
        user: &str,
        pass: &str,
        code_challenge: CodeChallenge,
    ) -> Result<String, PkceAuthError> {
        if !self.verify_pass(user, pass).await? {
            return Err(PkceAuthError::Unauthorized);
        }
        if code_challenge.method != "S256" {
            return Err(PkceAuthError::UnsupportedMethod);
        }

        let auth_code = Sha256::digest(format!("{user}, {code_challenge}"));
        let auth_code = BASE64_URL_SAFE.encode(auth_code);

        let pkce = Pkce::new(user.into(), code_challenge);
        self.pkce
            .pending
            .lock()
            .unwrap()
            .insert(auth_code.clone(), pkce);
        Ok(auth_code)
    }

    /// Handle a PKCE access token request.
    ///
    /// A successful request requires a valid previously issued authorization code (through [`Self::pkce_auth_req`]) and a matching code verifier.
    ///
    /// Returns the token if successful.
    pub fn pkce_token_req(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<String, PkceTokenError> {
        let pkce = match self.pkce.pending.lock().unwrap().remove(code) {
            Some(pkce) => pkce,
            None => return Err(PkceTokenError::InvalidCode),
        };
        if !pkce.valid() {
            return Err(PkceTokenError::ExpiredCode);
        }
        if !pkce.code_challenge.verify(code_verifier) {
            return Err(PkceTokenError::InvalidVerifier);
        }
        let token = self.issue_token(&pkce.user);
        Ok(token)
    }
}
