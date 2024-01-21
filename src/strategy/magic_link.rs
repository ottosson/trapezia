use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    session::{self, SessionBackend},
    PREFIX,
};

#[async_trait]
pub trait SendEmail {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn send_email(&self, to_email: &str, url: &str) -> Result<(), Self::Error>;
}

pub struct Config<M: SendEmail, S: MagicLinkSession> {
    pub mailer: M,
    pub session_backend: S,
    pub url_prefix: String,
    pub link_expiry: Duration,
    pub session_expiry: Duration,
}

pub struct MagicLinkStrategy<M: SendEmail, S: MagicLinkSession> {
    mailer: M,
    session_backend: S,
    url_prefix: String,
    link_expiry: Duration,
    session_expiry: Duration,
}

impl<M: SendEmail, S: MagicLinkSession> MagicLinkStrategy<M, S> {
    pub fn new(config: Config<M, S>) -> Self {
        let Config {
            mailer,
            session_backend,
            mut url_prefix,
            link_expiry,
            session_expiry,
        } = config;
        if !url_prefix.ends_with('/') {
            url_prefix = format!("{url_prefix}/");
        }

        Self {
            mailer,
            session_backend,
            url_prefix,
            link_expiry,
            session_expiry,
        }
    }
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
        data: &S::MagicLinkData,
        to_email: &str,
    ) -> Result<MagicLink, Error<M, S>> {
        let link_expires_at = Utc::now() + self.link_expiry;
        let magic_link = self
            .session_backend
            .generate_magic_link(data, link_expires_at)
            .await
            .map_err(Error::SessionBackend)?;
        let url = format!("{}{}", self.url_prefix, magic_link.identity_token);
        self.mailer
            .send_email(to_email, &url)
            .await
            .map_err(Error::Email)?;
        tracing::trace!(email=%to_email, token=%magic_link.identity_token, url=%url, "Magic link");
        Ok(magic_link)
    }

    pub async fn verify_token(
        &self,
        identity_key: &str,
        identity_token: &str,
    ) -> Result<bool, S::Error> {
        let result = self.session_backend
            .verify_magic_link(identity_key, identity_token)
            .await?;
        Ok(result.is_some())
    }

    pub async fn create_session(
        &self,
        identity_key: &str,
        identity_token: &str,
    ) -> Result<Option<S::Session>, S::Error> {
        let session_expires_at = Utc::now() + self.session_expiry;
        self.session_backend
            .consume_magic_link(identity_key, identity_token, session_expires_at)
            .await
    }
}

pub struct MagicLink {
    pub identity_key: String,
    pub identity_token: String,
}

impl MagicLink {
    pub fn new() -> Self {
        Self {
            identity_key: uuid::Uuid::new_v4().as_simple().to_string(),
            identity_token: uuid::Uuid::new_v4().as_simple().to_string(),
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
    type MagicLinkData;

    async fn generate_magic_link(
        &self,
        data: &Self::MagicLinkData,
        expires_at: DateTime<Utc>,
    ) -> Result<MagicLink, Self::Error>;

    async fn verify_magic_link(
        &self,
        identity_key: &str,
        identity_token: &str,
    ) -> Result<Option<MagicLinkPayload<Self::MagicLinkData>>, Self::Error>;

    async fn consume_magic_link(
        &self,
        identity_key: &str,
        identity_token: &str,
        session_expires_at: DateTime<Utc>,
    ) -> Result<Option<Self::Session>, Self::Error>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MagicLinkPayload<D> {
    identity_key: String,
    data: D,
}

#[async_trait]
impl<U> MagicLinkSession for session::redis::Backend<U>
where
    U: Clone + Serialize + DeserializeOwned + Send + Sync,
{
    type MagicLinkData = Self::SessionData;

    async fn generate_magic_link(
        &self,
        data: &Self::MagicLinkData,
        expires_at: DateTime<Utc>,
    ) -> Result<MagicLink, Self::Error> {
        let mut conn = self.pool.get().await?;
        let magic_link = MagicLink::new();

        redis::cmd("SET")
            .arg(format!(
                "{PREFIX}/magic-link/{}",
                &magic_link.identity_token
            ))
            .arg(
                serde_json::to_string(&MagicLinkPayload {
                    identity_key: magic_link.identity_key.clone(),
                    data: data.clone(),
                })
                .unwrap(),
            )
            .arg("EXAT")
            .arg(expires_at.timestamp())
            .query_async(&mut conn)
            .await?;

        Ok(magic_link)
    }

    async fn verify_magic_link(
        &self,
        identity_key: &str,
        identity_token: &str,
    ) -> Result<Option<MagicLinkPayload<Self::MagicLinkData>>, Self::Error> {
        let mut conn = self.pool.get().await?;
        let id_token_key = format!("{PREFIX}/magic-link/{identity_token}");
        let result: Option<String> = redis::cmd("GET")
            .arg(&id_token_key)
            .query_async(&mut conn)
            .await?;
        let Some(result) = result else {
            return Ok(None);
        };

        let magic_link_data: MagicLinkPayload<Self::MagicLinkData> = serde_json::from_str(&result)?;

        if magic_link_data.identity_key != *identity_key {
            return Err(session::redis::Error::Custom(
                "Identity keys do not match".into(),
            ));
        }

        Ok(Some(magic_link_data))
    }

    async fn consume_magic_link(
        &self,
        identity_key: &str,
        identity_token: &str,
        session_expires_at: DateTime<Utc>,
    ) -> Result<Option<Self::Session>, Self::Error> {
        let mut conn = self.pool.get().await?;

        let magic_link_data = match self.verify_magic_link(identity_key, identity_token).await? {
            Some(v) => v,
            None => return Ok(None),
        };

        let key = format!("{PREFIX}/magic-link/{identity_token}");

        let result: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await?;

        if result.is_none() {
            return Err(session::redis::Error::KeyNotFound(key));
        }

        Ok(Some(
            self.new_session(magic_link_data.data, session_expires_at)
                .await?,
        ))
    }
}
