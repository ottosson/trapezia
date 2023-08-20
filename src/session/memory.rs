use std::{collections::HashMap, sync::RwLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::SessionId;

#[derive(Debug, Clone)]
pub struct Session<D: Clone> {
    pub id: SessionId,
    pub data: D,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct Backend<U: Clone> {
    sessions: RwLock<HashMap<SessionId, Session<U>>>,
}

impl<U: Clone> Default for Backend<U> {
    fn default() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Session not found for given id {0}")]
    NotFound(SessionId),
}

#[async_trait]
impl<D: Clone + Send + Sync> super::SessionBackend for Backend<D> {
    type Error = Error;
    type Session = Session<D>;
    type SessionData = D;

    async fn new_session(
        &self,
        data: Self::SessionData,
        expires_at: DateTime<Utc>,
    ) -> Result<Self::Session, Self::Error> {
        let mut guard = self.sessions.write().unwrap();
        let id = SessionId::new();
        let session = Session {
            id,
            data,
            expires_at,
        };
        guard.insert(id, session.clone());
        Ok(session)
    }

    async fn session(
        &self,
        id: SessionId,
        _extend_expiry: Option<DateTime<Utc>>,
    ) -> Result<Self::Session, Self::Error> {
        let mut guard = self.sessions.write().unwrap();
        Ok(match guard.get(&id).cloned() {
            Some(v) => {
                if Utc::now() < v.expires_at {
                    v
                } else {
                    // Remove because expired.
                    guard.remove(&id);
                    return Err(Error::NotFound(id));
                }
            }
            None => return Err(Error::NotFound(id)),
        })
    }

    async fn clear_stale_sessions(&self) -> Result<(), Self::Error> {
        let keys = {
            let guard = self.sessions.read().unwrap();
            guard
                .iter()
                .filter(|(_, v)| Utc::now() >= v.expires_at)
                .map(|(k, _)| k)
                .copied()
                .collect::<Vec<_>>()
        };

        let mut guard = self.sessions.write().unwrap();
        for key in keys {
            guard.remove(&key);
        }

        Ok(())
    }

    async fn expire(&self, session: Self::Session) -> Result<(), Self::Error> {
        let mut guard = self.sessions.write().unwrap();
        guard.remove(&session.id);
        Ok(())
    }

    // async fn generate_password_reset_id(
    //     &self,
    //     _id: Self::UserId,
    //     _expires_at: DateTime<Utc>,
    // ) -> Result<PasswordResetId, Self::Error> {
    //     todo!()
    // }

    // async fn verify_password_reset_id(
    //     &self,
    //     _id: PasswordResetId,
    // ) -> Result<Self::UserId, Self::Error> {
    //     todo!()
    // }

    // async fn consume_password_reset_id(
    //     &self,
    //     _id: PasswordResetId,
    // ) -> Result<Self::UserId, Self::Error> {
    //     todo!()
    // }
}
