use crate::Basileus;

use super::err::{CreateUserError, DeleteUserError};
use sqlx::{query, query_as};

use tracing::info;

pub fn check_username(user: &str) -> bool {
    if user.is_empty() {
        return false;
    }
    user.chars()
        .all(|c| c.is_ascii_graphic() && !c.is_whitespace())
}

pub const DB_INIT: &str = r#"
CREATE TABLE IF NOT EXISTS user (
    user TEXT NOT NULL PRIMARY KEY
);
CREATE INDEX IF NOT EXISTS idx_user_user ON user (user);
"#;

impl Basileus {
    /// Check whether a user currently exists.
    pub async fn exist_user(&self, user: &str) -> Result<bool, sqlx::error::Error> {
        let query = query_as("SELECT EXISTS(SELECT 1 FROM user WHERE user = ?)").bind(user);
        let (res,): (i32,) = query.fetch_one(&self.db).await?;
        Ok(res == 1)
    }

    /// Create a new user.
    pub async fn create_user(&self, user: &str) -> Result<(), CreateUserError> {
        if self.exist_user(user).await? {
            return Err(CreateUserError::UserAlreadyExist(user.into()));
        }
        if !check_username(user) {
            return Err(CreateUserError::InvalidName(user.into()));
        }
        let q = query("INSERT INTO user (user) VALUES (?);").bind(user);
        q.execute(&self.db).await?;
        info!("created user {user}");
        Ok(())
    }

    /// Delete a user.
    pub async fn delete_user(&self, user: &str) -> Result<(), DeleteUserError> {
        if !self.exist_user(user).await? {
            return Err(DeleteUserError::UserNotExist(user.into()));
        }
        let query = query("DELETE FROM user WHERE user = ?").bind(user);
        query.execute(&self.db).await?;
        info!("deleted user {user}");
        Ok(())
    }
}
