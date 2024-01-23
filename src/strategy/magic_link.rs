use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use rand::distributions::{Distribution, Uniform};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    session::{self, SessionBackend},
    PREFIX,
};

pub struct Config<S: MagicLinkSession, G: MagicLinkGenerator> {
    pub session_backend: S,
    pub link_generator: G,
    pub link_expiry: Duration,
    pub session_expiry: Duration,
}

pub struct MagicLinkStrategy<S: MagicLinkSession, G: MagicLinkGenerator> {
    session_backend: S,
    link_generator: G,
    link_expiry: Duration,
    session_expiry: Duration,
}

impl<S: MagicLinkSession, G: MagicLinkGenerator> MagicLinkStrategy<S, G> {
    pub fn new(config: Config<S, G>) -> Self {
        let Config {
            session_backend,
            link_generator,
            link_expiry,
            session_expiry,
        } = config;

        Self {
            session_backend,
            link_generator,
            link_expiry,
            session_expiry,
        }
    }
}

impl<S: MagicLinkSession, G: MagicLinkGenerator> MagicLinkStrategy<S, G> {
    pub async fn generate_magic_link(
        &self,
        data: &S::MagicLinkData,
    ) -> Result<MagicLink, S::Error> {
        let link_expires_at = Utc::now() + self.link_expiry;
        let magic_link = self.link_generator.random();
        self.session_backend
            .store_magic_link(&magic_link, data, link_expires_at)
            .await?;
        Ok(magic_link)
    }

    pub async fn verify_magic_link(
        &self,
        identity_key: &str,
        identity_secret: &str,
    ) -> Result<bool, S::Error> {
        let result = self
            .session_backend
            .verify_magic_link(identity_key, identity_secret)
            .await?;
        Ok(result.is_some())
    }

    pub async fn create_session(
        &self,
        identity_key: &str,
        identity_secret: &str,
    ) -> Result<Option<S::Session>, S::Error> {
        let session_expires_at = Utc::now() + self.session_expiry;
        self.session_backend
            .consume_magic_link(identity_key, identity_secret, session_expires_at)
            .await
    }
}

pub struct MagicLink {
    pub identity_secret: String,
    pub identity_key: String,
}

pub trait MagicLinkGenerator {
    fn random(&self) -> MagicLink;
}

pub struct UuidSecret;

impl MagicLinkGenerator for UuidSecret {
    fn random(&self) -> MagicLink {
        MagicLink {
            identity_secret: Uuid::new_v4().as_simple().to_string(),
            identity_key: Uuid::new_v4().as_simple().to_string(),
        }
    }
}

pub struct NumericSecret;

impl MagicLinkGenerator for NumericSecret {
    fn random(&self) -> MagicLink {
        let between = Uniform::from(0..=9);
        let mut rng = rand::thread_rng();
        let mut secret = String::with_capacity(8);
        for _ in 0..8 {
            let v = between.sample(&mut rng);
            secret.push_str(&v.to_string());
        }

        MagicLink {
            identity_secret: secret,
            identity_key: Uuid::new_v4().as_simple().to_string(),
        }
    }
}

#[async_trait]
pub trait MagicLinkSession: SessionBackend {
    type MagicLinkData;

    async fn store_magic_link(
        &self,
        magic_link: &MagicLink,
        data: &Self::MagicLinkData,
        expires_at: DateTime<Utc>,
    ) -> Result<(), Self::Error>;

    async fn verify_magic_link(
        &self,
        identity_key: &str,
        identity_secret: &str,
    ) -> Result<Option<MagicLinkPayload<Self::MagicLinkData>>, Self::Error>;

    async fn consume_magic_link(
        &self,
        identity_key: &str,
        identity_secret: &str,
        session_expires_at: DateTime<Utc>,
    ) -> Result<Option<Self::Session>, Self::Error>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MagicLinkPayload<D> {
    identity_secret: String,
    identity_key: String,
    data: D,
}

#[async_trait]
impl<U> MagicLinkSession for session::redis::Backend<U>
where
    U: Clone + Serialize + DeserializeOwned + Send + Sync,
{
    type MagicLinkData = Self::SessionData;

    async fn store_magic_link(
        &self,
        magic_link: &MagicLink,
        data: &Self::MagicLinkData,
        expires_at: DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        let mut conn = self.pool.get().await?;

        redis::cmd("SET")
            .arg(format!("{PREFIX}/magic-link/{}", &magic_link.identity_key))
            .arg(
                serde_json::to_string(&MagicLinkPayload {
                    identity_secret: magic_link.identity_secret.clone(),
                    identity_key: magic_link.identity_key.clone(),
                    data: data.clone(),
                })
                .unwrap(),
            )
            .arg("EXAT")
            .arg(expires_at.timestamp())
            .query_async(&mut conn)
            .await?;

        Ok(())
    }

    async fn verify_magic_link(
        &self,
        identity_key: &str,
        identity_secret: &str,
    ) -> Result<Option<MagicLinkPayload<Self::MagicLinkData>>, Self::Error> {
        let mut conn = self.pool.get().await?;
        let id_token_key = format!("{PREFIX}/magic-link/{identity_key}");
        let result: Option<String> = redis::cmd("GET")
            .arg(&id_token_key)
            .query_async(&mut conn)
            .await?;
        let Some(result) = result else {
            return Ok(None);
        };

        let magic_link_data: MagicLinkPayload<Self::MagicLinkData> = serde_json::from_str(&result)?;

        if magic_link_data.identity_secret != *identity_secret {
            return Err(session::redis::Error::Custom(
                "Identity secrets do not match".into(),
            ));
        }

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
        identity_secret: &str,
        session_expires_at: DateTime<Utc>,
    ) -> Result<Option<Self::Session>, Self::Error> {
        let mut conn = self.pool.get().await?;

        let magic_link_data = match self
            .verify_magic_link(identity_key, identity_secret)
            .await?
        {
            Some(v) => v,
            None => return Ok(None),
        };

        let key = format!("{PREFIX}/magic-link/{identity_key}");

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
