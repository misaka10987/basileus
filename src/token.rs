use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, SystemTime},
};

use crate::rand_buf;
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

pub trait TokenManage {
    /// Issue a new token to the specified user.
    fn issue_token(&self, user: &str) -> String;
    /// Invalidate a token.
    fn invalidate_token(&self, token: &str);
    /// Invalidate all tokens related to `user`.
    fn invalidate_user_token(&self, user: &str);
    /// Make all tokens older than `duration` expire.
    fn expire_token(&self, duration: Duration);
    /// Verify token, return the user it belongs to if successful.
    fn verify_token(&self, token: &str) -> Option<String>;
}

impl<T> TokenManage for T
where
    T: AsRef<TokenModule>,
{
    fn issue_token(&self, user: &str) -> String {
        let buf = rand_buf::<64>();
        let token = BASE64_STANDARD.encode(buf);
        self.as_ref()
            .store
            .write()
            .unwrap()
            .insert(token.clone(), (user.to_owned(), SystemTime::now()));
        debug!("issued token '{}**' for '{user}'", &token[0..4]);
        token
    }

    fn invalidate_token(&self, token: &str) {
        self.as_ref().store.write().unwrap().remove(token);
        trace!("invalidated token '{}'", token);
    }

    fn invalidate_user_token(&self, user: &str) {
        self.as_ref()
            .store
            .write()
            .unwrap()
            .retain(|_, (u, _)| u != user);
        trace!("invalidated user session '{user}'")
    }

    fn expire_token(&self, duration: Duration) {
        let mut token = self.as_ref().store.write().unwrap();
        let prev = token.len();
        token.retain(|_, (_, time)| {
            SystemTime::now()
                .duration_since(*time)
                .is_ok_and(|d| d < duration)
        });
        let diff = prev - token.len();
        trace!("expired {diff} tokens");
    }

    fn verify_token(&self, token: &str) -> Option<String> {
        let map = self.as_ref().store.read().unwrap();
        let res = map.get(token).map(|(user, _)| user.clone());
        if let Some(user) = &res {
            trace!("authorized {user} by token")
        }
        res
    }
}
