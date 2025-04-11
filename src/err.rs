use thiserror::Error;

#[derive(Debug, Error)]
pub enum CreateUserError {
    #[error(transparent)]
    SQL(#[from] sqlx::error::Error),
    #[error("user '{0}' already exists")]
    UserAlreadyExist(String),
}

#[derive(Debug, Error)]
pub enum UpdatePassError {
    #[error(transparent)]
    Argon2(#[from] argon2::Error),
    #[error(transparent)]
    SQL(#[from] sqlx::error::Error),
    #[error("user '{0}' does not exist")]
    UserNotExist(String),
}

#[derive(Debug, Error)]
pub enum VerifyPassError {
    #[error(transparent)]
    Argon2(#[from] argon2::Error),
    #[error(transparent)]
    SQL(#[from] sqlx::error::Error),
    #[error("user '{0}' does not exist")]
    UserNotExist(String),
    #[error("user '{0}' has not yet defined password authorization")]
    PassUndefined(String),
}

#[derive(Debug, Error)]
pub enum DeleteUserError {
    #[error(transparent)]
    SQL(#[from] sqlx::error::Error),
    #[error("user '{0}' does not exist")]
    UserNotExist(String),
}

#[derive(Debug, Error)]
pub enum DeletePassError {
    #[error(transparent)]
    SQL(#[from] sqlx::error::Error),
    #[error("user '{0}' does not exist")]
    UserNotExist(String),
    #[error("user '{0}' has not yet defined password authorization")]
    PassUndefined(String),
}

#[derive(Debug, Error)]
pub enum GetPermError {
    #[error(transparent)]
    SQL(#[from] sqlx::error::Error),
    #[error("user '{0}' does not exist")]
    UserNotExist(String),
}

#[derive(Debug, Error)]
pub enum GivePermError {
    #[error(transparent)]
    SQL(#[from] sqlx::error::Error),
    #[error("user '{0}' does not exist")]
    UserNotExist(String),
    #[error(transparent)]
    GetDirectPerm(#[from] GetPermError),
    #[error(transparent)]
    SetPerm(#[from] SetPermError),
}

#[derive(Debug, Error)]
pub enum SetPermError {
    #[error(transparent)]
    SQL(#[from] sqlx::error::Error),
    #[error("user '{0}' does not exist")]
    UserNotExist(String),
}

#[derive(Debug, Error)]
pub enum RevokePermError {
    #[error(transparent)]
    SQL(#[from] sqlx::error::Error),
    #[error("user '{0}' does not exist")]
    UserNotExist(String),
    #[error(transparent)]
    GetPerm(#[from] GetPermError),
    #[error(transparent)]
    SetPerm(#[from] SetPermError),
}

#[derive(Debug, Error)]
pub enum CheckPermError {
    #[error(transparent)]
    SQL(#[from] sqlx::error::Error),
    #[error("user '{0}' does not exist")]
    UserNotExist(String),
    #[error(transparent)]
    GetDirectPerm(#[from] GetPermError),
    #[error(transparent)]
    SetPerm(#[from] SetPermError),
}
