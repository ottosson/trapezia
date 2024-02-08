use std::{convert::TryFrom, fmt::Display};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub mod memory;
pub mod redis;

#[nova::newtype(sqlx, serde, copy)]
pub type PasswordResetId = uuid::Uuid;

impl PasswordResetId {
    pub fn new() -> Self {
        PasswordResetId(uuid::Uuid::new_v4())
    }
}

impl Default for PasswordResetId {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait SessionBackend: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;
    type Session;
    type SessionData;

    async fn new_session(
        &self,
        data: Self::SessionData,
        expires_at: DateTime<Utc>,
    ) -> Result<Self::Session, Self::Error>;
    async fn session(
        &self,
        id: SessionId,
        extend_expiry: Option<DateTime<Utc>>,
    ) -> Result<Self::Session, Self::Error>;
    async fn clear_stale_sessions(&self) -> Result<(), Self::Error>;
    async fn expire(&self, session: SessionId) -> Result<(), Self::Error>;
}

#[nova::newtype(sqlx, serde, copy)]
pub type SessionId = uuid::Uuid;

impl SessionId {
    pub fn new() -> Self {
        SessionId(uuid::Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&**self, f)
    }
}

impl TryFrom<&str> for SessionId {
    type Error = uuid::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let uuid = uuid::Uuid::parse_str(value)?;
        Ok(Self(uuid))
    }
}

impl From<Uuid> for SessionId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl TryFrom<String> for SessionId {
    type Error = uuid::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        <SessionId as TryFrom<&str>>::try_from(&value)
    }
}
