use crate::{Basileus, err::DeletePassError, rand_buf};

use super::err::{UpdatePassError, VerifyPassError};
use sqlx::{query, query_as};

use tracing::{info, trace};

pub const DB_INIT: &str = r#"
CREATE TABLE IF NOT EXISTS pass (
    user TEXT NOT NULL PRIMARY KEY,
    phc TEXT NOT NULL,
    FOREIGN KEY (user) REFERENCES user(user) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pass_user ON pass (user);
"#;

impl Basileus {
    /// Whether a user has defined a password for authorization.
    pub async fn exist_pass(&self, user: &str) -> Result<bool, sqlx::error::Error> {
        let query = query_as("SELECT EXISTS(SELECT 1 FROM pass WHERE user = ?)").bind(user);
        let (res,): (i32,) = query.fetch_one(&self.db).await?;
        Ok(res == 1)
    }

    /// Update password for specified user.
    pub async fn update_pass(&self, user: &str, pass: &str) -> Result<(), UpdatePassError> {
        if !self.exist_user(user).await? {
            return Err(UpdatePassError::UserNotExist(user.into()));
        }
        let hashed = argon2::hash_encoded(pass.as_bytes(), &rand_buf::<64>(), &Default::default())?;
        let query = query("INSERT OR REPLACE INTO pass (user, phc) VALUES (?, ?);")
            .bind(user)
            .bind(hashed);
        query.execute(&self.db).await?;
        info!("updated password for {user}");
        Ok(())
    }

    /// Verify given password for user.
    pub async fn verify_pass(&self, user: &str, pass: &str) -> Result<bool, VerifyPassError> {
        if !self.exist_user(user).await? {
            return Err(VerifyPassError::UserNotExist(user.into()));
        }
        if !self.exist_pass(user).await? {
            return Err(VerifyPassError::PassUndefined(user.into()));
        }
        let query = query_as("SELECT phc FROM pass WHERE user = ?").bind(user);
        let (phc,): (String,) = query.fetch_one(&self.db).await?;
        let res = argon2::verify_encoded(&phc, pass.as_bytes())?;
        trace!("authorized {user} by password");
        Ok(res)
    }

    /// Delete a user's password.
    pub async fn delete_pass(&self, user: &str) -> Result<(), DeletePassError> {
        if !self.exist_user(user).await? {
            return Err(DeletePassError::UserNotExist(user.into()));
        }
        if !self.exist_pass(user).await? {
            return Err(DeletePassError::UserNotExist(user.into()));
        }
        let query = query("DELETE FROM pass WHERE user = ?").bind(user);
        query.execute(&self.db).await?;
        Ok(())
    }
}
