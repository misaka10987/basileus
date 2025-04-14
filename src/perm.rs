use crate::{
    ROOT_USER,
    err::{CheckPermError, GetPermError, GivePermError, RevokePermError, SetPermError},
    user::UserManage,
};
use sqlx::{SqlitePool, query, query_as};
use std::{
    collections::HashSet,
    convert::Infallible,
    ops::{Add, Mul, Sub},
    str::FromStr,
    sync::LazyLock,
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
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Perm {
    /// Root permission.
    Root,
    /// Set of group ids.
    Group(HashSet<String>),
}

impl Perm {
    /// Whether it has root permission.
    pub fn is_root(&self) -> bool {
        match self {
            Self::Root => true,
            _ => false,
        }
    }

    /// Inherit permission from another entity. Root permission can **NOT** be inherited.
    pub fn inherit(&self, from: Perm) -> Self {
        match (self, from) {
            (Self::Root, _) => Self::Root,
            (Self::Group(lhs), Perm::Root) => Self::Group(lhs.clone()),
            (Self::Group(lhs), Perm::Group(rhs)) => Self::Group(lhs.union(&rhs).cloned().collect()),
        }
    }

    /// Count of groups.
    pub fn grp_cnt(&self) -> usize {
        match self {
            Perm::Root => 0,
            Perm::Group(hash_set) => hash_set.len(),
        }
    }

    pub fn grps(&self) -> &HashSet<String> {
        static ROOT_GRP: LazyLock<HashSet<String>> = LazyLock::new(|| HashSet::new());
        match self {
            Perm::Root => &ROOT_GRP,
            Perm::Group(hash_set) => hash_set,
        }
    }
}

impl PartialEq for Perm {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Root, Self::Root) => true,
            (Self::Group(l0), Self::Group(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl Eq for Perm {}

impl PartialOrd for Perm {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (Self::Root, Self::Root) => Some(std::cmp::Ordering::Equal),
            (Self::Root, Self::Group(_)) => Some(std::cmp::Ordering::Greater),
            (Self::Group(_), Self::Root) => Some(std::cmp::Ordering::Less),
            (Self::Group(lhs), Self::Group(rhs)) => {
                if lhs == rhs {
                    return Some(std::cmp::Ordering::Equal);
                } else if lhs.is_subset(rhs) {
                    Some(std::cmp::Ordering::Less)
                } else {
                    Some(std::cmp::Ordering::Greater)
                }
            }
        }
    }
}

impl Ord for Perm {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl Add for Perm {
    type Output = Perm;

    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::Group(lhs), Self::Group(rhs)) => Self::Group(lhs.union(&rhs).cloned().collect()),
            _ => Self::Root,
        }
    }
}

impl Sub for Perm {
    type Output = Perm;

    fn sub(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (_, Self::Root) => Self::Group(HashSet::new()),
            (Self::Root, Self::Group(_)) => Self::Root,
            (Self::Group(lhs), Self::Group(rhs)) => {
                Self::Group(lhs.difference(&rhs).cloned().collect())
            }
        }
    }
}

impl Mul for Perm {
    type Output = Perm;

    fn mul(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::Root, Self::Root) => Self::Root,
            (Self::Root, Self::Group(rhs)) => Self::Group(rhs),
            (Self::Group(lhs), Self::Root) => Self::Group(lhs),
            (Self::Group(lhs), Self::Group(rhs)) => {
                Self::Group(lhs.intersection(&rhs).cloned().collect())
            }
        }
    }
}

impl FromStr for Perm {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let grp: HashSet<_> = s.split_whitespace().map(|x| x.into()).collect();
        if grp.contains(ROOT_USER) {
            return Ok(Self::Root);
        }
        Ok(Self::Group(grp))
    }
}

impl ToString for Perm {
    fn to_string(&self) -> String {
        match self {
            Perm::Root => ROOT_USER.into(),
            Perm::Group(grp) => {
                let mut buf = String::new();
                for grp in grp {
                    buf.push_str(grp);
                    buf.push(' ');
                }
                buf
            }
        }
    }
}

#[allow(async_fn_in_trait)]
pub trait PermManage {
    /// Get the "direct" permission the user holds, i.e. those directly defined by the user, not inherited.
    async fn get_direct_perm(&self, user: &str) -> Result<Perm, GetPermError>;
    /// Get all permission the user holds. This operation is expensive, consider using [`PermManage::get_direct_perm`].
    async fn get_all_perm(&self, user: &str) -> Result<Perm, GetPermError>;
    /// Check if the user has specified permission.
    async fn check_perm(&self, user: &str, perm: Perm) -> Result<bool, CheckPermError>;
    /// Sets a user's permission.
    async fn set_perm(&self, user: &str, perm: Perm) -> Result<(), SetPermError>;
    /// Gives new permissions to specified user.
    async fn give_perm(&self, user: &str, perm: Perm) -> Result<(), GivePermError>;
    /// Revoke a user's certain permissions.
    /// This does not result in an error if the permission does not currently exist.
    async fn revoke_perm(&self, user: &str, perm: Perm) -> Result<(), RevokePermError>;
}

impl<T> PermManage for T
where
    T: AsRef<SqlitePool> + UserManage,
{
    async fn get_direct_perm(&self, user: &str) -> Result<Perm, GetPermError> {
        if user == ROOT_USER {
            return Ok(Perm::Root);
        }
        if !self.exist_user(user).await? {
            return Err(GetPermError::UserNotExist(user.into()));
        }
        let query = query_as("SELECT grp FROM perm WHERE user = ?").bind(user);
        let (res,): (String,) = query.fetch_one(self.as_ref()).await?;
        let perm = Perm::from_str(&res).unwrap() + Perm::Group(HashSet::from([user.into()]));
        Ok(perm)
    }

    async fn get_all_perm(&self, user: &str) -> Result<Perm, GetPermError> {
        let mut perm = self.get_direct_perm(user).await?;
        if perm.is_root() {
            return Ok(Perm::Root);
        }
        loop {
            let mut parent = perm.clone();
            for grp in perm.grps() {
                let new = self.get_direct_perm(grp).await?;
                parent = parent.inherit(new);
            }
            if parent.grp_cnt() == perm.grp_cnt() {
                break Ok(parent);
            }
            perm = parent;
        }
    }

    async fn check_perm(&self, user: &str, req: Perm) -> Result<bool, CheckPermError> {
        if user == ROOT_USER {
            return Ok(true);
        }
        if !self.exist_user(user).await? {
            return Err(CheckPermError::UserNotExist(user.into()));
        }
        let perm = self.get_direct_perm(user).await?;
        if perm >= req {
            return Ok(true);
        }
        let perm = self.get_all_perm(user).await?;
        Ok(perm >= req)
    }

    async fn set_perm(&self, user: &str, perm: Perm) -> Result<(), SetPermError> {
        if !self.exist_user(user).await? {
            return Err(SetPermError::UserNotExist(user.into()));
        }
        let grp = (perm - Perm::Group(HashSet::from([user.into()]))).to_string();
        let query = query("INSERT OR REPLACE INTO perm (user, grp) VALUES (?, ?);")
            .bind(user)
            .bind(grp);
        query.execute(self.as_ref()).await?;
        Ok(())
    }

    async fn give_perm(&self, user: &str, perm: Perm) -> Result<(), GivePermError> {
        if !self.exist_user(user).await? {
            return Err(GivePermError::UserNotExist(user.into()));
        }
        let prev = self.get_direct_perm(user).await?;
        let sum = prev + perm;
        self.set_perm(user, sum).await?;
        Ok(())
    }

    async fn revoke_perm(&self, user: &str, perm: Perm) -> Result<(), RevokePermError> {
        if !self.exist_user(user).await? {
            return Err(RevokePermError::UserNotExist(user.into()));
        }
        let prev = self.get_direct_perm(user).await?;
        let diff = prev - perm;
        self.set_perm(user, diff).await?;
        Ok(())
    }
}
