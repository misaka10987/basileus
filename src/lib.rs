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

use crate::pkce::{PkceConfig, PkceModule};

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
    #[cfg_attr(feature = "serde", serde(rename = "database-path"))]
    pub db: PathBuf,
    /// PKCE configuration.
    #[cfg_attr(feature = "serde", serde(rename = "pkce"))]
    #[cfg_attr(feature = "serde", serde(default))]
    pub pkce: PkceConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db: "./basileus.db".into(),
            pkce: Default::default(),
        }
    }
}

/// Entry point for the library.
pub struct Basileus {
    /// Configurations.
    pub config: Config,
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
    pub async fn new(config: Config) -> Result<Self, sqlx::error::Error> {
        let opt = SqliteConnectOptions::default()
            .filename(&config.db)
            .create_if_missing(true);
        let db = SqlitePool::connect_with(opt).await?;
        info!("connected to {:?}", config.db);
        query(user::DB_INIT).execute(&db).await?;
        query(pass::DB_INIT).execute(&db).await?;
        query(perm::DB_INIT).execute(&db).await?;
        query(DB_INIT).execute(&db).await?;
        trace!("database initialized");
        let pkce = PkceModule::new(config.pkce.clone());
        Ok(Self {
            config,
            db,
            token: TokenModule::new(),
            pkce,
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
