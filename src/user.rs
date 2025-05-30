pub(crate) mod postgres;

use async_trait::async_trait;
use secrecy::SecretString;

use crate::{
    strategy::password::Strategy,
    username::{Username, UsernameType},
};

#[nova::newtype(serde, sqlx, copy, new)]
pub type UserId = uuid::Uuid;

pub type PgUsers<S, U> = postgres::Backend<S, U>;

#[derive(Debug)]
pub struct NewUser<U: UsernameType> {
    pub username: Username<U>,
    pub password: SecretString,
    pub meta: serde_json::Value,
    pub id: Option<UserId>,
}

impl<U: UsernameType> NewUser<U> {
    pub fn new(username: &str, password: &str) -> Result<Self, U::Err> {
        Ok(Self {
            username: username.parse()?,
            password: SecretString::new(password.into()),
            meta: Default::default(),
            id: None,
        })
    }

    pub fn with_id(id: UserId, username: &str, password: &str) -> Result<Self, U::Err> {
        Ok(Self {
            username: username.parse()?,
            password: SecretString::new(password.into()),
            meta: Default::default(),
            id: Some(id),
        })
    }
}

#[derive(Debug)]
pub struct User<U: UsernameType> {
    pub id: UserId,
    pub username: Username<U>,
    pub password_hash: SecretString,
    pub meta: serde_json::Value,
}

impl<U: UsernameType> User<U> {
    pub fn new(
        id: UserId,
        username: &str,
        password_hash: String,
        meta: Option<serde_json::Value>,
    ) -> Result<Self, U::TryIntoError> {
        let username: Username<U> = username.parse()?;

        Ok(Self {
            id,
            username,
            password_hash: SecretString::new(password_hash.into()),
            meta: meta.unwrap_or(serde_json::Value::Null),
        })
    }
}

#[async_trait]
pub trait UserBackend<S: Strategy, U: UsernameType> {
    type Error: std::error::Error;

    async fn create_user(&self, user: NewUser<U>) -> Result<User<U>, Self::Error>;
    async fn find_user_by_id(&self, id: UserId) -> Result<User<U>, Self::Error>;
    async fn find_user_by_username(&self, name: &str) -> Result<User<U>, Self::Error>;
    async fn list_users(&self) -> Result<Vec<User<U>>, Self::Error>;
    fn verify_password(&self, user: &User<U>, password: &str) -> Result<(), Self::Error>;
    async fn change_password(&self, user: &User<U>, new_password: &str) -> Result<(), Self::Error>;
}

#[async_trait]
pub trait UserBackendTransactional<'a, S: Strategy, U: UsernameType, UT>:
    UserBackend<S, U>
{
    type Tx: 'a;

    async fn create_user_transaction(
        &'a self,
        tx: &mut Self::Tx,
        user: NewUser<U>,
    ) -> Result<User<U>, Self::Error>;
}
