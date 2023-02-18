use bankid::config::{CA_TEST, P12_TEST};
use bankid::{
    client::BankID,
    config::{ConfigBuilder, Pkcs12},
    model::{
        AuthenticatePayloadBuilder, AuthenticatePayloadBuilderError, CollectPayload,
        CompletionData, Status,
    },
};

pub struct BankIdStrategy {
    client: BankID,
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

impl BankIdStrategy {
    pub fn test() -> Self {
        let pkcs12 = Pkcs12::Der {
            der: P12_TEST.to_vec(),
            password: "qwerty123".to_string(),
        };

        let config = ConfigBuilder::default()
            .pkcs12(pkcs12)
            .url("https://appapi2.test.bankid.com/rp/v5.1".to_string())
            .ca(CA_TEST.to_string())
            .build()
            .unwrap();

        Self {
            client: BankID::new(config),
        }
    }

    pub async fn start_authentication(
        &self,
        pn: &str,
        ip_addr: std::net::IpAddr,
    ) -> Result<bankid::model::Authenticate, Error> {
        // Remove dashes if they were put in the number
        let pn = pn.replace("-", "");
        if pn.len() != 12 {
            return Err(Error::InvalidPn);
        }

        let payload = AuthenticatePayloadBuilder::default()
            .personal_number(pn)
            .end_user_ip(ip_addr.to_string())
            .build()?;

        Ok(self.client.authenticate(payload).await?)
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
                // todo!()
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
