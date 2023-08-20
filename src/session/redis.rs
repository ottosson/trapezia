use std::marker::PhantomData;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use deadpool_redis::{Config, Runtime};
use redis::FromRedisValue;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::SessionId;
use crate::PREFIX;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session<D: Clone> {
    pub id: SessionId,
    pub data: D,
    pub expires_at: DateTime<Utc>,
}

pub struct Backend<D: Clone> {
    pub(crate) pool: deadpool_redis::Pool,
    _data: PhantomData<D>,
}

impl<U: Clone> Backend<U> {
    pub fn new(url: &str) -> Result<Self, deadpool_redis::CreatePoolError> {
        let config = Config::from_url(url);
        let pool = config.create_pool(Some(Runtime::Tokio1))?;
        Ok(Self {
            pool,
            _data: PhantomData,
        })
    }

    pub fn with_pool(pool: deadpool_redis::Pool) -> Self {
        Self {
            pool,
            _data: PhantomData,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error establishing connection to Redis pool")]
    Pool(#[from] deadpool_redis::PoolError),

    #[error("Redis error")]
    Redis(#[from] redis::RedisError),

    #[error("Json parsing error")]
    Json(#[from] serde_json::Error),

    #[error("Key {0} not found")]
    KeyNotFound(String),

    #[error("Key {0} has missing TTL")]
    MissingTtl(String),

    #[error("An error occurred: {0}")]
    Custom(String),
}

#[derive(Debug, Clone, Copy)]
pub enum Ttl {
    Seconds(u64),
    NoExpiry,
    NotFound,
}

impl From<i64> for Ttl {
    fn from(value: i64) -> Self {
        match value {
            -2 => Ttl::NotFound,
            -1 => Ttl::NoExpiry,
            _ => Ttl::Seconds(value as u64),
        }
    }
}

impl FromRedisValue for Ttl {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        i64::from_redis_value(v).map(Ttl::from)
    }
}

#[async_trait]
impl<D> super::SessionBackend for Backend<D>
where
    D: Clone + Serialize + DeserializeOwned + Send + Sync,
{
    type Error = Error;
    type Session = Session<D>;
    type SessionData = D;

    async fn new_session(
        &self,
        data: Self::SessionData,
        expires_at: DateTime<Utc>,
    ) -> Result<Self::Session, Self::Error> {
        let mut conn = self.pool.get().await?;
        let session_id = SessionId::new();
        let session = Session {
            id: session_id,
            data,
            expires_at,
        };
        redis::cmd("SET")
            .arg(format!("{PREFIX}/session/{}", session_id))
            .arg(serde_json::to_string(&session.data).unwrap())
            .arg("EXAT")
            .arg(expires_at.timestamp())
            .query_async(&mut conn)
            .await?;
        Ok(session)
    }

    async fn session(
        &self,
        id: SessionId,
        extend_expiry: Option<DateTime<Utc>>,
    ) -> Result<Self::Session, Self::Error> {
        let mut conn = self.pool.get().await?;
        let session_key = format!("{PREFIX}/session/{}", id);

        let (session_data, ttl): (Option<String>, Ttl) = match extend_expiry {
            Some(expiry) => {
                redis::pipe()
                    .atomic()
                    .cmd("GETEX")
                    .arg(&session_key)
                    .arg("EXAT")
                    .arg(expiry.timestamp())
                    .cmd("TTL")
                    .arg(&session_key)
                    .query_async(&mut conn)
                    .await?
            }
            None => {
                redis::pipe()
                    .atomic()
                    .cmd("GET")
                    .arg(&session_key)
                    .cmd("TTL")
                    .arg(&session_key)
                    .query_async(&mut conn)
                    .await?
            }
        };

        let ttl = match ttl {
            Ttl::Seconds(ttl) => ttl,
            Ttl::NoExpiry => return Err(Error::MissingTtl(session_key)),
            Ttl::NotFound => return Err(Error::KeyNotFound(session_key)),
        };

        let Some(session_data) = session_data else {
            return Err(Error::KeyNotFound(session_key));
        };

        let data = serde_json::from_str(&session_data)?;

        let session = Session {
            id,
            data,
            expires_at: Utc::now() + Duration::seconds(ttl.try_into().unwrap()),
        };

        Ok(session)
    }

    async fn clear_stale_sessions(&self) -> Result<(), Self::Error> {
        // Not really supported by Redis, does it itself.
        Ok(())
    }

    async fn expire(&self, session: Self::Session) -> Result<(), Self::Error> {
        let mut conn = self.pool.get().await?;
        redis::cmd("DEL")
            .arg(format!("{PREFIX}/session/{}", session.id))
            .query_async(&mut conn)
            .await?;
        Ok(())
    }
}
