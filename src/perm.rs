use crate::{
    Basileus,
    err::{CheckPermError, GetPermError, GivePermError, RevokePermError, SetPermError},
};
use sqlx::{query, query_as};
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

/// Denotes a specific set of permissions.
///
/// A **"permission"** is a string excluding whitespace representing a certain privilege to a resource or action,
/// some examples of which include "read", "write", and "admin".
/// This is similar to user groups in Unix-like systems.
///
/// The set of permissions is a collection of such strings and is string-representable as whitespace-separated values.
/// It is implemented as a wrapper over `HashSet<String>`,
/// and supports set operations such as union, intersection, and difference (using arithmetic operators `+`, `*`, and `-` respectively).
///
/// # Comparison
///
/// The comparison operators are defined as set relations as follows:
///
/// - `==` : equality of two permission sets
/// - `<`  : proper subset
/// - `<=` : subset
/// - `>`  : proper superset
/// - `>=` : superset
///
/// Note that this is therefore a partial order because sets may be incomparable.
///
/// This can be used to check if a user has sufficient permissions for a certain action.
/// E.g., if `user_perm >= required_perm`, then the user has enough permissions to perform the action requiring `required_perm`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Perm(HashSet<String>);

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
        if self == other {
            Some(std::cmp::Ordering::Equal)
        } else if self.is_subset(other) {
            Some(std::cmp::Ordering::Less)
        } else if self.is_superset(other) {
            Some(std::cmp::Ordering::Greater)
        } else {
            None
        }
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
        let grp: HashSet<_> = value
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .map(|x| x.into())
            .collect();
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

impl Basileus {
    /// Get permissions the user holds, i.e. group names.
    pub async fn get_perm(&self, user: &str) -> Result<Perm, GetPermError> {
        if !self.exist_user(user).await? {
            return Err(GetPermError::UserNotExist(user.into()));
        }
        let query = query_as("SELECT grp FROM perm WHERE user = ?").bind(user);
        let (res,): (String,) = query.fetch_one(&self.db).await?;
        let perm = res.into();
        Ok(perm)
    }

    /// Check if the user has specified permission.
    pub async fn check_perm(&self, user: &str, req: &Perm) -> Result<bool, CheckPermError> {
        if !self.exist_user(user).await? {
            return Err(CheckPermError::UserNotExist(user.into()));
        }
        let perm = self.get_perm(user).await?;
        Ok(perm >= *req)
    }

    /// Sets a user's permission.
    pub async fn set_perm(&self, user: &str, perm: &Perm) -> Result<(), SetPermError> {
        if !self.exist_user(user).await? {
            return Err(SetPermError::UserNotExist(user.into()));
        }
        let grp = perm.to_string();
        let query = query("INSERT OR REPLACE INTO perm (user, grp) VALUES (?, ?);")
            .bind(user)
            .bind(grp);
        query.execute(&self.db).await?;
        Ok(())
    }

    /// Gives new permissions to specified user.
    pub async fn give_perm(&self, user: &str, perm: &Perm) -> Result<(), GivePermError> {
        if !self.exist_user(user).await? {
            return Err(GivePermError::UserNotExist(user.into()));
        }
        let prev = self.get_perm(user).await?;
        let sum = &prev + perm;
        self.set_perm(user, &sum).await?;
        Ok(())
    }

    /// Revoke a user's certain permissions.
    /// This does not result in an error if the permission does not currently exist.
    pub async fn revoke_perm(&self, user: &str, perm: &Perm) -> Result<(), RevokePermError> {
        if !self.exist_user(user).await? {
            return Err(RevokePermError::UserNotExist(user.into()));
        }
        let prev = self.get_perm(user).await?;
        let diff = &prev - perm;
        self.set_perm(user, &diff).await?;
        Ok(())
    }
}
