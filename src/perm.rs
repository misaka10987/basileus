use crate::{
    err::{CheckPermError, GetPermError, GivePermError, RevokePermError, SetPermError},
    user::UserManage,
};
use sqlx::{SqlitePool, query, query_as};
use std::{
    collections::HashSet,
    convert::Infallible,
    ops::{Add, Deref, DerefMut, Mul, Sub},
    str::FromStr,
};

pub const DB_INIT: &str = r#"
CREATE TABLE IF NOT EXISTS perm (
    user TEXT NOT NULL PRIMARY KEY,
    grp TEXT,
    FOREIGN KEY (user) REFERENCES user(user) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_perm_user ON perm (user);
CREATE TRIGGER IF NOT EXISTS after_user_insert
AFTER INSERT ON user
FOR EACH ROW
BEGIN
    INSERT OR IGNORE INTO perm (user, grp)
    VALUES (NEW.user, '');
END;
"#;

/// Denotes a permission level.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Perm(pub HashSet<String>);

impl Deref for Perm {
    type Target = HashSet<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Perm {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialOrd for Perm {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.is_subset(other) {
            Some(std::cmp::Ordering::Less)
        } else if self == other {
            Some(std::cmp::Ordering::Equal)
        } else {
            Some(std::cmp::Ordering::Greater)
        }
    }
}

impl Ord for Perm {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl Add for &Perm {
    type Output = Perm;

    fn add(self, rhs: Self) -> Self::Output {
        Perm(self.union(&rhs).cloned().collect())
    }
}

impl Sub for &Perm {
    type Output = Perm;

    fn sub(self, rhs: Self) -> Self::Output {
        Perm(self.difference(&rhs).cloned().collect())
    }
}

impl Mul for &Perm {
    type Output = Perm;

    fn mul(self, rhs: Self) -> Self::Output {
        Perm(self.intersection(&rhs).cloned().collect())
    }
}

impl From<String> for Perm {
    fn from(value: String) -> Self {
        value.as_str().into()
    }
}

impl From<&String> for Perm {
    fn from(value: &String) -> Self {
        value.as_str().into()
    }
}

impl From<&str> for Perm {
    fn from(value: &str) -> Self {
        let grp: HashSet<_> = value.split_whitespace().map(|x| x.into()).collect();
        Self(grp)
    }
}

impl FromStr for Perm {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(s.into())
    }
}

impl ToString for Perm {
    fn to_string(&self) -> String {
        let mut buf = String::new();
        for grp in self.iter() {
            buf.push_str(grp);
            buf.push(' ');
        }
        buf
    }
}

#[allow(async_fn_in_trait)]
pub trait PermManage {
    /// Get permissions the user holds, i.e. group names.
    async fn get_perm(&self, user: &str) -> Result<Perm, GetPermError>;
    /// Check if the user has specified permission.
    async fn check_perm(&self, user: &str, perm: &Perm) -> Result<bool, CheckPermError>;
    /// Sets a user's permission.
    async fn set_perm(&self, user: &str, perm: &Perm) -> Result<(), SetPermError>;
    /// Gives new permissions to specified user.
    async fn give_perm(&self, user: &str, perm: &Perm) -> Result<(), GivePermError>;
    /// Revoke a user's certain permissions.
    /// This does not result in an error if the permission does not currently exist.
    async fn revoke_perm(&self, user: &str, perm: &Perm) -> Result<(), RevokePermError>;
}

impl<T> PermManage for T
where
    T: AsRef<SqlitePool> + UserManage,
{
    async fn get_perm(&self, user: &str) -> Result<Perm, GetPermError> {
        if !self.exist_user(user).await? {
            return Err(GetPermError::UserNotExist(user.into()));
        }
        let query = query_as("SELECT grp FROM perm WHERE user = ?").bind(user);
        let (res,): (String,) = query.fetch_one(self.as_ref()).await?;
        let perm = res.into();
        Ok(perm)
    }

    async fn check_perm(&self, user: &str, req: &Perm) -> Result<bool, CheckPermError> {
        if !self.exist_user(user).await? {
            return Err(CheckPermError::UserNotExist(user.into()));
        }
        let perm = self.get_perm(user).await?;
        Ok(perm >= *req)
    }

    async fn set_perm(&self, user: &str, perm: &Perm) -> Result<(), SetPermError> {
        if !self.exist_user(user).await? {
            return Err(SetPermError::UserNotExist(user.into()));
        }
        let grp = perm.to_string();
        let query = query("INSERT OR REPLACE INTO perm (user, grp) VALUES (?, ?);")
            .bind(user)
            .bind(grp);
        query.execute(self.as_ref()).await?;
        Ok(())
    }

    async fn give_perm(&self, user: &str, perm: &Perm) -> Result<(), GivePermError> {
        if !self.exist_user(user).await? {
            return Err(GivePermError::UserNotExist(user.into()));
        }
        let prev = self.get_perm(user).await?;
        let sum = &prev + perm;
        self.set_perm(user, &sum).await?;
        Ok(())
    }

    async fn revoke_perm(&self, user: &str, perm: &Perm) -> Result<(), RevokePermError> {
        if !self.exist_user(user).await? {
            return Err(RevokePermError::UserNotExist(user.into()));
        }
        let prev = self.get_perm(user).await?;
        let diff = &prev - perm;
        self.set_perm(user, &diff).await?;
        Ok(())
    }
}
