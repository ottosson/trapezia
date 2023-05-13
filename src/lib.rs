pub mod appauth;
pub mod session;
pub mod strategy;
pub mod user;
pub mod username;

pub(crate) const PREFIX: &str = "trapezia";

mod util;

#[cfg(feature = "deadpool")]
pub use util::deadpool::{PgHandle, PgPool};

#[cfg(feature = "deadpool")]
pub use user::postgres::DeadpoolPasswordResetBackend;
