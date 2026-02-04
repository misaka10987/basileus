use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, SystemTime},
};

use crate::{Basileus, rand_buf};
use base64::{Engine, prelude::BASE64_STANDARD};

use tracing::{debug, trace};

pub struct TokenModule {
    store: RwLock<HashMap<String, (String, SystemTime)>>,
}

impl TokenModule {
    pub fn new() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }
}

impl Basileus {
    /// Issue a new token to the specified user.
    pub fn issue_token(&self, user: &str) -> String {
        let buf = rand_buf::<64>();
        let token = BASE64_STANDARD.encode(buf);
        self.token
            .store
            .write()
            .unwrap()
            .insert(token.clone(), (user.to_owned(), SystemTime::now()));
        debug!("issued token '{}**' for '{user}'", &token[0..4]);
        token
    }

    /// Invalidate a token.
    pub fn invalidate_token(&self, token: &str) {
        self.token.store.write().unwrap().remove(token);
        trace!("invalidated token '{}'", token);
    }

    /// Invalidate all tokens related to `user`.
    pub fn invalidate_user_token(&self, user: &str) {
        self.token
            .store
            .write()
            .unwrap()
            .retain(|_, (u, _)| u != user);
        trace!("invalidated user session '{user}'")
    }

    /// Make all tokens older than `duration` expire.
    pub fn expire_token(&self, duration: Duration) {
        let mut token = self.token.store.write().unwrap();
        let prev = token.len();
        token.retain(|_, (_, time)| {
            SystemTime::now()
                .duration_since(*time)
                .is_ok_and(|d| d < duration)
        });
        let diff = prev - token.len();
        trace!("expired {diff} tokens");
    }

    /// Verify token, return the user it belongs to if successful.
    pub fn verify_token(&self, token: &str) -> Option<String> {
        let map = self.token.store.read().unwrap();
        let res = map.get(token).map(|(user, _)| user.clone());
        if let Some(user) = &res {
            trace!("authorized {user} by token")
        }
        res
    }
}
