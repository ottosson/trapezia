use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{de::DeserializeOwned, Serialize};

use crate::{session::SessionBackend, PREFIX};

#[async_trait]
pub trait SendEmail {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn send_email(&self, to_email: &str, url: &str) -> Result<(), Self::Error>;
}

pub struct MagicLinkStrategy<M: SendEmail, S: MagicLinkSession> {
    mailer: M,
    session_backend: S,
    url_prefix: String,
    link_expiry: Duration,
    session_expiry: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum Error<M: SendEmail, S: MagicLinkSession> {
    #[error("An error occurred sending magic link email")]
    Email(#[source] M::Error),
    #[error("An error occurred with the session backend")]
    SessionBackend(#[source] S::Error),
}

impl<M: SendEmail, S: MagicLinkSession> MagicLinkStrategy<M, S> {
    pub async fn send_email(
        &self,
        user_id: &S::UserId,
        to_email: &str,
        url: &str,
    ) -> Result<(), Error<M, S>> {
        let link_expires_at = Utc::now() + self.link_expiry;
        let magic_link = self
            .session_backend
            .generate_magic_link(user_id, link_expires_at)
            .await
            .map_err(Error::SessionBackend)?;
        let url = format!("{}{}", self.url_prefix, magic_link.token);
        self.mailer
            .send_email(to_email, &url)
            .await
            .map_err(Error::Email)?;
        Ok(())
    }

    pub async fn verify_token(&self, token: &str) -> Result<S::UserId, S::Error> {
        self.session_backend.verify_magic_link(token).await
    }

    pub async fn create_session(&self, token: &str) -> Result<S::Session, S::Error> {
        let session_expires_at = Utc::now() + self.session_expiry;
        self.session_backend
            .consume_magic_link(token, session_expires_at)
            .await
    }
}

pub struct MagicLink {
    pub token: String,
}

impl MagicLink {
    pub fn new() -> Self {
        Self {
            token: uuid::Uuid::new_v4().as_simple().to_string(),
        }
    }
}

impl Default for MagicLink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait MagicLinkSession: SessionBackend {
    async fn generate_magic_link(
        &self,
        id: &Self::UserId,
        expires_at: DateTime<Utc>,
    ) -> Result<MagicLink, Self::Error>;

    async fn verify_magic_link(&self, token: &str) -> Result<Self::UserId, Self::Error>;

    async fn consume_magic_link(
        &self,
        token: &str,
        session_expires_at: DateTime<Utc>,
    ) -> Result<Self::Session, Self::Error>;
}

#[async_trait]
impl<U> MagicLinkSession for crate::session::redis::Backend<U>
where
    U: Clone + Serialize + DeserializeOwned + Send + Sync,
{
    async fn generate_magic_link(
        &self,
        id: &Self::UserId,
        expires_at: DateTime<Utc>,
    ) -> Result<MagicLink, Self::Error> {
        let mut conn = self.pool.get().await?;
        let magic_link = MagicLink::new();

        redis::cmd("SET")
            .arg(format!("{PREFIX}/magic-link/{}", &magic_link.token))
            .arg(serde_json::to_string(&id).unwrap())
            .arg("EXAT")
            .arg(expires_at.timestamp())
            .query_async(&mut conn)
            .await?;

        Ok(magic_link)
    }

    async fn verify_magic_link(&self, token: &str) -> Result<Self::UserId, Self::Error> {
        let mut conn = self.pool.get().await?;
        let result: String = redis::cmd("GET")
            .arg(format!("{PREFIX}/magic-link/{token}"))
            .query_async(&mut conn)
            .await?;
        Ok(serde_json::from_str(&result)?)
    }

    async fn consume_magic_link(
        &self,
        token: &str,
        session_expires_at: DateTime<Utc>,
    ) -> Result<Self::Session, Self::Error> {
        let mut conn = self.pool.get().await?;
        let result: String = redis::cmd("GETDEL")
            .arg(format!("{PREFIX}/magic-link/{token}"))
            .query_async(&mut conn)
            .await?;
        let user_id: Self::UserId = serde_json::from_str(&result)?;
        self.new_session(user_id, session_expires_at).await
    }
}
