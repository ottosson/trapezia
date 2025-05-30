use std::marker::PhantomData;

use async_trait::async_trait;
use secrecy::ExposeSecret;
use sqlx::{PgPool, Postgres, Transaction};

use crate::{strategy::password::Strategy, username::UsernameType};

use super::{NewUser, User, UserBackend, UserBackendTransactional, UserId};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlx error")]
    Sqlx(#[from] sqlx::Error),

    #[error("invalid username")]
    Username(#[source] Box<dyn std::error::Error + Sync + Send>),

    #[error("password error")]
    Password(#[from] crate::strategy::password::Error),

    #[error("The entered password was invalid.")]
    InvalidPassword,
}

pub struct Backend<S: Strategy, U: UsernameType> {
    strategy: S,
    pool: PgPool,
    table_name: &'static str,
    _username: PhantomData<U>,
}

impl<S: Strategy, U: UsernameType> Backend<S, U> {
    pub fn new(pool: PgPool, table_name: &'static str, strategy: S) -> Self {
        Self {
            strategy,
            pool,
            table_name,
            _username: PhantomData,
        }
    }
}

#[inline]
async fn create_user<'a, S: Strategy, U: UsernameType>(
    conn: &mut Transaction<'a, Postgres>,
    strategy: &'a S,
    table_name: &'static str,
    user: NewUser<U>,
) -> Result<User<U>, Error> {
    let password_hash = strategy.generate_password_hash(user.password.expose_secret())?;
    let user_id = match user.id {
        Some(id) => {
            database::insert_user_with_id(
                conn,
                id,
                user.username,
                password_hash,
                user.meta,
                table_name,
            )
            .await?
        }
        None => {
            database::insert_user(conn, user.username, password_hash, user.meta, table_name).await?
        }
    };
    let user = database::find_user_by_id(conn, user_id, table_name).await?;
    Ok(user)
}

#[async_trait]
impl<'a, S: Strategy, U: UsernameType> UserBackendTransactional<'a, S, U, UserId>
    for Backend<S, U>
{
    type Tx = Transaction<'a, Postgres>;

    async fn create_user_transaction(
        &'a self,
        tx: &mut Self::Tx,
        user: NewUser<U>,
    ) -> Result<User<U>, Self::Error> {
        create_user(tx, &self.strategy, self.table_name, user).await
    }
}

#[async_trait]
impl<S: Strategy, U: UsernameType> UserBackend<S, U> for Backend<S, U> {
    type Error = Error;

    async fn create_user(&self, user: NewUser<U>) -> Result<User<U>, Self::Error> {
        let mut conn = self.pool.begin().await?;
        let user = create_user(&mut conn, &self.strategy, self.table_name, user).await?;
        conn.commit().await?;
        Ok(user)
    }

    async fn find_user_by_id(&self, id: UserId) -> Result<User<U>, Self::Error> {
        let mut conn = self.pool.acquire().await?;
        Ok(database::find_user_by_id(&mut conn, id, self.table_name).await?)
    }

    async fn find_user_by_username(&self, username: &str) -> Result<User<U>, Self::Error> {
        let mut conn = self.pool.acquire().await?;
        Ok(
            database::find_user_by_username(&mut conn, username.to_string(), self.table_name)
                .await?,
        )
    }

    async fn list_users(&self) -> Result<Vec<User<U>>, Self::Error> {
        let mut conn = self.pool.acquire().await?;
        Ok(database::list_users(&mut conn, self.table_name).await?)
    }

    fn verify_password(&self, user: &User<U>, password: &str) -> Result<(), Self::Error> {
        match self
            .strategy
            .verify_password(user.password_hash.expose_secret(), password)?
        {
            true => Ok(()),
            false => Err(Error::InvalidPassword),
        }
    }

    async fn change_password(&self, user: &User<U>, new_password: &str) -> Result<(), Self::Error> {
        let mut conn = self.pool.acquire().await?;
        let password_hash = self.strategy.generate_password_hash(new_password)?;
        database::set_password(
            &mut conn,
            user.username.clone(),
            password_hash,
            self.table_name,
        )
        .await?;
        Ok(())
    }
}

mod database {
    use secrecy::{ExposeSecret, SecretString};
    use sqlx::{PgConnection, Row};

    use crate::username::{Username, UsernameType};

    use super::{User, UserId};

    pub async fn insert_user_with_id<U: UsernameType>(
        conn: &mut PgConnection,
        id: UserId,
        username: Username<U>,
        password_hash: SecretString,
        meta: serde_json::Value,
        table_name: &'static str,
    ) -> Result<UserId, sqlx::Error> {
        let rec = sqlx::query(&format!(
            r#"
                INSERT INTO {}(id, username, password_hash, meta) VALUES ($1, $2::text, $3, $4)
                RETURNING id;
            "#,
            table_name
        ))
        .bind(*id)
        .bind(&*username)
        .bind(password_hash.expose_secret())
        .bind(meta)
        .fetch_one(conn)
        .await?;

        Ok(UserId(rec.get(0)))
    }

    pub async fn insert_user<U: UsernameType>(
        conn: &mut PgConnection,
        username: Username<U>,
        password_hash: SecretString,
        meta: serde_json::Value,
        table_name: &'static str,
    ) -> Result<UserId, sqlx::Error> {
        let rec = sqlx::query(&format!(
            r#"
                INSERT INTO {}(username, password_hash, meta) VALUES ($1::text, $2, $3)
                RETURNING id;
            "#,
            table_name
        ))
        .bind(&*username)
        .bind(password_hash.expose_secret())
        .bind(meta)
        .fetch_one(conn)
        .await?;

        Ok(UserId(rec.get(0)))
    }

    pub async fn set_password<U: UsernameType>(
        conn: &mut PgConnection,
        username: Username<U>,
        password_hash: SecretString,
        table_name: &'static str,
    ) -> Result<(), sqlx::Error> {
        let _rec = sqlx::query(&format!(
            r#"
                UPDATE {} SET password_hash = $1 WHERE username = $2::text
                RETURNING id;
            "#,
            table_name
        ))
        .bind(password_hash.expose_secret())
        .bind(&*username)
        .fetch_one(conn)
        .await?;

        Ok(())
    }

    pub async fn find_user_by_id<U: UsernameType>(
        conn: &mut PgConnection,
        id: UserId,
        table_name: &'static str,
    ) -> Result<User<U>, sqlx::Error> {
        let r = sqlx::query(&format!(
            r#"
                SELECT
                    id as "id: UserId",
                    username::TEXT,
                    password_hash,
                    meta
                FROM {}
                WHERE id = $1
                LIMIT 1;
            "#,
            table_name
        ))
        .bind(*id)
        .fetch_one(conn)
        .await?;

        let raw_username: String = r.get(1);
        let username: Username<U> = match raw_username.parse() {
            Ok(v) => v,
            Err(e) => return Err(sqlx::Error::Decode(Box::new(e))),
        };

        Ok(User {
            id: r.get(0),
            username,
            password_hash: SecretString::new(r.get(2)),
            meta: r.get(3),
        })
    }

    pub async fn find_user_by_username<U: UsernameType>(
        conn: &mut PgConnection,
        username: String,
        table_name: &'static str,
    ) -> Result<User<U>, sqlx::Error> {
        let r = sqlx::query(&format!(
            r#"
                SELECT
                    id as "id: UserId",
                    username::TEXT,
                    password_hash,
                    meta
                FROM {}
                WHERE LOWER(username) = $1
                LIMIT 1;
            "#,
            table_name
        ))
        .bind(username.to_lowercase())
        .fetch_one(conn)
        .await?;

        let raw_username: String = r.get(1);
        let username: Username<U> = match raw_username.parse() {
            Ok(v) => v,
            Err(e) => return Err(sqlx::Error::Decode(Box::new(e))),
        };

        Ok(User {
            id: r.get(0),
            username,
            password_hash: SecretString::new(r.get(2)),
            meta: r.get(3),
        })
    }

    pub async fn list_users<U: UsernameType>(
        conn: &mut PgConnection,
        table_name: &'static str,
    ) -> Result<Vec<User<U>>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            r#"
                SELECT
                    id as "id: UserId",
                    username::TEXT,
                    password_hash,
                    meta
                FROM {};
            "#,
            table_name
        ))
        .fetch_all(conn)
        .await?;

        let users = rows
            .iter()
            .map(|r| {
                let raw_username: String = r.get(1);
                let username: Username<U> = match raw_username.parse() {
                    Ok(v) => v,
                    Err(e) => return Err(sqlx::Error::Decode(Box::new(e))),
                };
                Ok(User {
                    id: r.get(0),
                    username,
                    password_hash: SecretString::new(r.get(2)),
                    meta: r.get(3),
                })
            })
            // TODO: handle errors better
            .flat_map(|u| u.ok())
            .collect();

        Ok(users)
    }
}
