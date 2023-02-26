use async_trait::async_trait;
use bankid::config::{CA_PROD, CA_TEST, P12_TEST};
use bankid::model::Authenticate as AuthenticateResponse;
use bankid::{
    client::BankID,
    config::{ConfigBuilder, Pkcs12},
    model::{
        AuthenticatePayloadBuilder, AuthenticatePayloadBuilderError, CollectPayload,
        CompletionData, Status,
    },
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

impl From<AuthenticateResponse> for BankIdAuthPayload {
    fn from(value: AuthenticateResponse) -> Self {
        Self {
            auto_start_token: value.auto_start_token,
            order_ref: value.order_ref,
            qr_start_token: value.qr_start_token,
            qr_start_secret: value.qr_start_secret,
            start_time: Utc::now(),
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
        let result: String = redis::cmd("GET")
            .arg(format!("{PREFIX}/bankid/{order_ref}"))
            .query_async(&mut conn)
            .await?;
        let payload: BankIdAuthPayload = serde_json::from_str(&result)?;
        Ok(payload)
    }
}

fn generate_bankid_hmac(payload: &BankIdAuthPayload) -> Result<String, ()> {
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
        return Err(());
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

    #[error("An error occurred with BankID")]
    BankId(#[from] bankid::error::Error),

    #[error("Invalid input provided to authenticator")]
    AuthenticationBuilder(#[from] AuthenticatePayloadBuilderError),

    #[error("Authentication failed")]
    Failed(String),

    #[error("Authentication timed out")]
    TimedOut,

    #[error("The authentication succeeded but the completion data is missing")]
    MissingData,
}

const BANKID_TEST_URL: &str = "https://appapi2.test.bankid.com/rp/v5.1";
const BANKID_PROD_URL: &str = "https://appapi2.bankid.com/rp/v5.1";

#[derive(Debug, Clone, Serialize)]
pub struct StartAuthResponse {
    order_ref: String,
    auto_start_token: String,
}

impl<S> BankIdStrategy<S>
where
    S: BankIdSession,
{
    pub fn new(session_backend: S, p12_data: Vec<u8>, password: &str) -> Self {
        let pkcs12 = Pkcs12::Der {
            der: p12_data,
            password: password.to_string(),
        };

        let config = ConfigBuilder::default()
            .pkcs12(pkcs12)
            .url(BANKID_PROD_URL.to_string())
            .ca(CA_PROD.to_string())
            .build()
            .unwrap();

        Self {
            client: BankID::new(config),
            session_backend,
        }
    }

    pub fn test(session_backend: S) -> Self {
        let pkcs12 = Pkcs12::Der {
            der: P12_TEST.to_vec(),
            password: "qwerty123".to_string(),
        };

        let config = ConfigBuilder::default()
            .pkcs12(pkcs12)
            .url(BANKID_TEST_URL.to_string())
            .ca(CA_TEST.to_string())
            .build()
            .unwrap();

        Self {
            client: BankID::new(config),
            session_backend,
        }
    }

    pub async fn start_authentication(
        &self,
        pn: &str,
        ip_addr: std::net::IpAddr,
    ) -> Result<StartAuthResponse, Error> {
        // Remove dashes if they were put in the number
        let pn = pn.replace("-", "");
        if pn.len() != 12 {
            return Err(Error::InvalidPn);
        }

        let payload = AuthenticatePayloadBuilder::default()
            .personal_number(pn)
            .end_user_ip(ip_addr.to_string())
            .build()?;

        let response: BankIdAuthPayload = self.client.authenticate(payload).await?.into();
        self.session_backend.store_auth_payload(&response).await.map_err(|_| panic!());

        Ok(StartAuthResponse {
            order_ref: response.order_ref,
            auto_start_token: response.auto_start_token,
        })
    }

    pub async fn qr_code(&self, order_ref: &str) -> Result<String, Error> {
        let payload = self.session_backend.auth_payload(order_ref).await.unwrap();
        Ok(generate_bankid_hmac(&payload).unwrap())
    }

    pub async fn poll_authentication(&self, order_ref: &str) -> Result<CompletionData, Error> {
        let collect = self
            .client
            .wait_collect(CollectPayload {
                order_ref: order_ref.to_string(),
            })
            .await?;

        match collect.status {
            Status::Pending => {
                // We should never be able to get into this state, but alas...
                Err(Error::TimedOut)
            }
            Status::Failed => Err(Error::Failed(collect.hint_code)),
            Status::Complete => {
                let Some(data) = collect.completion_data else {
                    return Err(Error::MissingData);
                };

                Ok(data)
            }
        }
    }
}
