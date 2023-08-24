use async_trait::async_trait;
use bankid::config::Config;
use bankid::model::{
    AuthenticatePayload, AuthenticateResponse, CancelPayload, CollectResponse, SignPayload,
    SignResponse, UserVisibleDataFormat,
};
pub use bankid::{
    client::BankID, error::Error as BankIdError,
    model::{CollectPayload, CompletionData},
};
use chrono::{DateTime, Duration, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::PREFIX;

#[nova::newtype(serde)]
pub type Pn = String;

use crate::session::SessionBackend;

pub struct BankIdStrategy<S: BankIdSession> {
    client: BankID,
    session_backend: S,
}

#[async_trait]
pub trait BankIdSession: SessionBackend {
    async fn store_auth_payload(&self, payload: &BankIdAuthPayload) -> Result<(), Self::Error>;
    async fn auth_payload(&self, order_ref: &str) -> Result<BankIdAuthPayload, Self::Error>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankIdAuthPayload {
    pub auto_start_token: String,
    pub order_ref: String,
    pub qr_start_token: String,
    pub qr_start_secret: String,
    pub start_time: DateTime<Utc>,
}

pub struct AuthError {
    pub error_code: String,
    pub details: String,
}

impl TryFrom<AuthenticateResponse> for BankIdAuthPayload {
    type Error = AuthError;

    fn try_from(value: AuthenticateResponse) -> Result<Self, Self::Error> {
        match value {
            AuthenticateResponse::Success {
                auto_start_token,
                order_ref,
                qr_start_token,
                qr_start_secret,
            } => Ok(Self {
                auto_start_token,
                order_ref,
                qr_start_token,
                qr_start_secret,
                start_time: Utc::now(),
            }),
            AuthenticateResponse::Error {
                error_code,
                details,
            } => Err(AuthError {
                error_code,
                details,
            }),
        }
    }
}

impl TryFrom<SignResponse> for BankIdAuthPayload {
    type Error = AuthError;

    fn try_from(value: SignResponse) -> Result<Self, Self::Error> {
        match value {
            SignResponse::Success {
                auto_start_token,
                order_ref,
                qr_start_token,
                qr_start_secret,
            } => Ok(Self {
                auto_start_token,
                order_ref,
                qr_start_token,
                qr_start_secret,
                start_time: Utc::now(),
            }),
            SignResponse::Error {
                error_code,
                details,
            } => Err(AuthError {
                error_code,
                details,
            }),
        }
    }
}

#[async_trait]
impl<U> BankIdSession for crate::session::redis::Backend<U>
where
    U: Clone + Serialize + DeserializeOwned + Send + Sync,
{
    async fn store_auth_payload(&self, payload: &BankIdAuthPayload) -> Result<(), Self::Error> {
        let mut conn = self.pool.get().await?;
        let start_time = Utc::now();
        let expires_at = start_time + Duration::seconds(60);

        redis::cmd("SET")
            .arg(format!("{PREFIX}/bankid/{}", &payload.order_ref))
            .arg(serde_json::to_string(&payload).unwrap())
            .arg("EXAT")
            .arg(expires_at.timestamp())
            .query_async(&mut conn)
            .await?;
        Ok(())
    }

    async fn auth_payload(&self, order_ref: &str) -> Result<BankIdAuthPayload, Self::Error> {
        let mut conn = self.pool.get().await?;
        let order_ref_key = format!("{PREFIX}/bankid/{order_ref}");
        let result: Option<String> = redis::cmd("GET")
            .arg(&order_ref_key)
            .query_async(&mut conn)
            .await?;
        let Some(result) = result else {
            return Err(crate::session::redis::Error::KeyNotFound(order_ref_key));
        };
        let payload: BankIdAuthPayload = serde_json::from_str(&result)?;
        Ok(payload)
    }
}

fn generate_bankid_hmac(payload: &BankIdAuthPayload) -> Result<String, Error> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let BankIdAuthPayload {
        qr_start_token,
        qr_start_secret,
        start_time,
        ..
    } = payload;

    let qr_time: chrono::Duration = Utc::now().signed_duration_since(*start_time);
    let qr_time = qr_time.num_seconds();
    if qr_time < 0 {
        // TODO: this is problematic and indicates the computer time changed.
        return Err(Error::QrCodeTimeDrift);
    }
    let qr_time = qr_time.to_string();

    let mut hmac = HmacSha256::new_from_slice(qr_start_secret.as_bytes()).unwrap();
    hmac.update(qr_time.as_bytes());
    let hmac = hmac.finalize();
    let hmac = hmac.into_bytes();

    Ok(format!("bankid.{qr_start_token}.{qr_time}.{hmac:064x}"))
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("An invalid person number was provider")]
    InvalidPn,

    #[error("An error occurred with BankID: {0}")]
    BankId(#[from] bankid::client::Error),

    #[error("Authentication failed")]
    Failed(String),

    #[error("Authentication timed out")]
    TimedOut,

    #[error("Hint code is missing")]
    MissingHintCode,

    #[error("The authentication succeeded but the completion data is missing")]
    MissingData,

    #[error("No authentication payload found in session store")]
    NoAuthPayload,

    #[error("Storing payload in session store failed")]
    StorePayloadFailed,

    #[error("Time has drifted, invalidating the QR code.")]
    QrCodeTimeDrift,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartAuthResponse {
    order_ref: String,
    auto_start_token: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum PollCollectResponse {
    Pending { hint_code: String },
    Complete { completion_data: CompletionData },
    Failed { hint_code: String },
    Error { code: String, details: String },
}

impl<S> BankIdStrategy<S>
where
    S: BankIdSession,
{
    pub fn new(session_backend: S, pem_data: &[u8]) -> Result<Self, bankid::error::Error> {
        let identity = bankid::config::Identity::from_pem(pem_data)?;
        let config = Config::prod(identity);

        Ok(Self {
            client: BankID::new(config).unwrap(),
            session_backend,
        })
    }

    pub async fn start_signing(
        &self,
        pn: &str,
        user_visible_data: &str,
        non_user_visible_data: &str,
        ip_addr: std::net::IpAddr,
    ) -> Result<StartAuthResponse, Error> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        // Remove dashes if they were put in the number
        let pn = pn.replace('-', "");
        if pn.len() != 12 {
            return Err(Error::InvalidPn);
        }

        let user_visible_data = STANDARD.encode(user_visible_data);
        let non_user_visible_data = STANDARD.encode(non_user_visible_data);

        let payload = SignPayload {
            personal_number: Some(pn),
            end_user_ip: ip_addr.to_string(),
            user_visible_data,
            user_non_visible_data: Some(non_user_visible_data),
            user_visible_data_format: Some(UserVisibleDataFormat::SimpleMarkdownV1),
            requirement: None,
        };

        let response: SignResponse = self.client.sign(payload).await?;
        let response: BankIdAuthPayload = response
            .try_into()
            .map_err(|e: AuthError| Error::Failed(e.details))?;
        self.session_backend
            .store_auth_payload(&response)
            .await
            .map_err(|_| Error::StorePayloadFailed)?;

        Ok(StartAuthResponse {
            order_ref: response.order_ref,
            auto_start_token: response.auto_start_token,
        })
    }

    pub async fn start_authentication(
        &self,
        pn: &str,
        ip_addr: std::net::IpAddr,
    ) -> Result<StartAuthResponse, Error> {
        // Remove dashes if they were put in the number
        let pn = pn.replace('-', "");
        if pn.len() != 12 {
            return Err(Error::InvalidPn);
        }

        let payload = AuthenticatePayload {
            personal_number: Some(pn),
            end_user_ip: ip_addr.to_string(),
            requirement: None,
        };

        let response: AuthenticateResponse = self.client.authenticate(payload).await?;
        let response: BankIdAuthPayload = response
            .try_into()
            .map_err(|e: AuthError| Error::Failed(e.details))?;
        self.session_backend
            .store_auth_payload(&response)
            .await
            .map_err(|_| Error::StorePayloadFailed)?;

        Ok(StartAuthResponse {
            order_ref: response.order_ref,
            auto_start_token: response.auto_start_token,
        })
    }

    pub async fn qr_code(&self, order_ref: &str) -> Result<String, Error> {
        let payload = self
            .session_backend
            .auth_payload(order_ref)
            .await
            .map_err(|_| Error::NoAuthPayload)?;
        generate_bankid_hmac(&payload)
    }

    pub async fn poll_authentication(&self, order_ref: &str) -> Result<PollCollectResponse, Error> {
        let result = self
            .client
            .collect(CollectPayload {
                order_ref: order_ref.to_string(),
            })
            .await;

        let collect = match result {
            Ok(x) => x,
            Err(e) => {
                match &e {
                    bankid::client::Error::InvalidJson(e, body) => {
                        tracing::error!(error=%e, body=body, "error parsing collect payload");
                    }
                    bankid::client::Error::Http(e) => {
                        tracing::error!(error=%e, "error parsing collect payload");
                    }
                }
                return Err(e.into());
            }
        };

        match collect {
            CollectResponse::Pending { hint_code, .. } => {
                Ok(PollCollectResponse::Pending { hint_code })
            }
            CollectResponse::Failed { hint_code, .. } => {
                self.client
                    .cancel(CancelPayload {
                        order_ref: order_ref.to_string(),
                    })
                    .await?;

                Ok(PollCollectResponse::Failed { hint_code })
            }
            CollectResponse::Complete {
                completion_data, ..
            } => Ok(PollCollectResponse::Complete { completion_data }),
            CollectResponse::Error {
                error_code,
                details,
            } => Ok(PollCollectResponse::Error {
                code: error_code,
                details,
            }),
        }
    }
}
