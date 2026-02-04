pub mod err;
pub mod pass;
pub mod perm;
pub mod pkce;
pub mod prelude;
pub mod token;
pub mod user;

use std::path::PathBuf;

use sqlx::{SqlitePool, query, sqlite::SqliteConnectOptions};

use token::TokenModule;
use tracing::{info, trace};

pub use prelude::*;

use crate::pkce::PkceModule;

fn rand_buf<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).unwrap();
    buf
}

/// Configuration for [`Basileus`].
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Config {
    /// Path to the SQLite storage.
    pub db_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: "./basileus.db".into(),
        }
    }
}

/// Entry point for the library.
pub struct Basileus {
    /// Configurations.
    pub cfg: Config,
    /// Database connection.
    db: SqlitePool,
    /// Token management module.
    token: TokenModule,
    pkce: PkceModule,
}

/// Initialize the database.
pub const DB_INIT: &str = r#"
CREATE TABLE IF NOT EXISTS pubkey (
    user TEXT NOT NULL PRIMARY KEY,
    key BLOB NOT NULL,
    FOREIGN KEY (user) REFERENCES user(user) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pubkey_user ON pubkey (user);
CREATE TABLE IF NOT EXISTS token (
    user TEXT NOT NULL PRIMARY KEY,
    token TEXT,
    FOREIGN KEY (user) REFERENCES user(user) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_token_user ON token (user);
"#;

impl Basileus {
    /// Initialize the library, creating the database if missing.
    pub async fn new(cfg: Config) -> Result<Self, sqlx::error::Error> {
        let opt = SqliteConnectOptions::default()
            .filename(&cfg.db_path)
            .create_if_missing(true);
        let db = SqlitePool::connect_with(opt).await?;
        info!("connected to {:?}", cfg.db_path);
        query(user::DB_INIT).execute(&db).await?;
        query(pass::DB_INIT).execute(&db).await?;
        query(perm::DB_INIT).execute(&db).await?;
        query(DB_INIT).execute(&db).await?;
        trace!("database initialized");
        Ok(Self {
            cfg,
            db,
            token: TokenModule::new(),
            pkce: PkceModule::new(),
        })
    }

    /// Count the number of users.
    pub async fn user_cnt(&self) -> Result<i64, sqlx::error::Error> {
        let (cnt,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM user")
            .fetch_one(&self.db)
            .await?;
        Ok(cnt)
    }
}
