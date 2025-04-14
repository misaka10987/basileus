use super::err::{CreateUserError, DeleteUserError};
use sqlx::{SqlitePool, query, query_as};

use tracing::info;

pub const ROOT_USER: &str = "root";

pub fn check_username(user: &str) -> bool {
    if user == ROOT_USER {
        return false;
    }
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

#[allow(async_fn_in_trait)]
pub trait UserManage {
    /// Check whether a user currently exists.
    async fn exist_user(&self, user: &str) -> Result<bool, sqlx::error::Error>;

    /// Create a new user.
    async fn create_user(&self, user: &str) -> Result<(), CreateUserError>;

    /// Delete a user.
    async fn delete_user(&self, user: &str) -> Result<(), DeleteUserError>;
}

impl<T> UserManage for T
where
    T: AsRef<SqlitePool>,
{
    async fn exist_user(&self, user: &str) -> Result<bool, sqlx::error::Error> {
        let query = query_as("SELECT EXISTS(SELECT 1 FROM user WHERE user = ?)").bind(user);
        let (res,): (i32,) = query.fetch_one(self.as_ref()).await?;
        Ok(res == 1)
    }

    async fn create_user(&self, user: &str) -> Result<(), CreateUserError> {
        if self.exist_user(user).await? {
            return Err(CreateUserError::UserAlreadyExist(user.into()));
        }
        if !check_username(user) {
            return Err(CreateUserError::InvalidName(user.into()));
        }
        let q = query("INSERT INTO user (user) VALUES (?);").bind(user);
        q.execute(self.as_ref()).await?;
        info!("created user {user}");
        Ok(())
    }

    async fn delete_user(&self, user: &str) -> Result<(), DeleteUserError> {
        if !self.exist_user(user).await? {
            return Err(DeleteUserError::UserNotExist(user.into()));
        }
        let query = query("DELETE FROM user WHERE user = ?").bind(user);
        query.execute(self.as_ref()).await?;
        info!("deleted user {user}");
        Ok(())
    }
}
