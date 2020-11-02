//! DB
//!
//! Postgres DB access and update tools.

use super::super::Result;

use crate::server::get_postgres_url;
use crate::{
    error::{
        DBErrorType::{ConnectionFailed, NoDataForID, UpdateFailed},
        LockboxError,
    },
    Database, DatabaseR, DatabaseW, PGDatabase,
};
use chrono::NaiveDateTime;
use rocket_contrib::databases::postgres::{rows::Row, types::ToSql};
use rocket_contrib::databases::r2d2;
use rocket_contrib::databases::r2d2_postgres::{PostgresConnectionManager, TlsMode};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;



#[derive(Debug)]
pub enum Schema {
    Lockbox,
}

impl Schema {
    pub fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}

#[derive(Debug)]
pub enum Table {
    UserSession,
}

impl Table {
    pub fn to_string(&self) -> String {
        match self {
            _ => format!(
                "{:?}.{:?}",
                Schema::Lockbox.to_string().to_lowercase(),
                self
            ),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub enum Column {
    Data,
    Complete,

    // UserSession
    Id,
    Authentication,
    ProofKey,
    StateChainId,
}

impl Column {
    pub fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}

impl PGDatabase {
    fn get_postgres_connection_pool(
        rocket_url: &String,
    ) -> Result<r2d2::Pool<PostgresConnectionManager>> {
        let url: String = rocket_url.clone().to_string();
        let manager = PostgresConnectionManager::new(url.clone(), TlsMode::None)?;
        match r2d2::Pool::new(manager) {
            Ok(m) => Ok(m),
            Err(e) => Err(LockboxError::DBError(
                ConnectionFailed,
                format!(
                    "Failed to get postgres connection managerfor rocket url {}: {}",
                    url, e
                ),
            )),
        }
    }

    pub fn database_r(&self) -> Result<DatabaseR> {
        match &self.pool {
            Some(p) => match p.get() {
                Ok(c) => Ok(DatabaseR(c)),
                Err(e) => Err(LockboxError::DBError(
                    ConnectionFailed,
                    format!("Failed to get pooled connection for read: {}", e),
                )),
            },
            None => Err(LockboxError::DBError(
                ConnectionFailed,
                "Failed to get pooled connection for read: pool not set".to_string(),
            )),
        }
    }

    pub fn database_w(&self) -> Result<DatabaseW> {
        match &self.pool {
            Some(p) => match p.get() {
                Ok(c) => Ok(DatabaseW(c)),
                Err(e) => Err(LockboxError::DBError(
                    ConnectionFailed,
                    format!("Failed to get pooled connection for write: {}", e),
                )),
            },
            None => Err(LockboxError::DBError(
                ConnectionFailed,
                "Failed to get pooled connection for write: pool not set".to_string(),
            )),
        }
    }

    /// Build DB tables and Schemas
    pub fn make_tables(&self) -> Result<()> {
        // Create Schemas if they do not already exist
        let _ = self.database_w()?.execute(
            &format!(
                "
            CREATE SCHEMA IF NOT EXISTS lockbox;
            "
            ),
            &[],
        )?;
        
        // Create tables if they do not already exist
        self.database_w()?.execute(
            &format!(
                "
            CREATE TABLE IF NOT EXISTS {} (
                id uuid NOT NULL,
                statechainid uuid,
                authentication varchar,
                proofkey varchar,
                PRIMARY KEY (id)
            );",
                Table::UserSession.to_string(),
            ),
            &[],
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    /// Drop all DB tables and Schemas.
    fn drop_tables(&self) -> Result<()> {
        let _ = self.database_w()?.execute(
            &format!(
                "
            DROP SCHEMA statechainentity CASCADE;",
            ),
            &[],
        )?;
        let _ = self.database_w()?.execute(
            &format!(
                "
            DROP SCHEMA watcher CASCADE;",
            ),
            &[],
        )?;

        Ok(())
    }

    /// Drop all DB tables and schemas.
    fn truncate_tables(&self) -> Result<()> {
        self.database_w()?.execute(
            &format!(
                "
            TRUNCATE {} RESTART IDENTITY;",
                Table::UserSession.to_string(),
            ),
            &[],
        )?;
        Ok(())
    }

    /// Serialize data into string. To add custom types to Postgres they must be serialized to String.
    pub fn ser<T>(data: T) -> Result<String>
    where
        T: serde::ser::Serialize,
    {
        match serde_json::to_string(&data) {
            Ok(v) => Ok(v),
            Err(_) => Err(LockboxError::Generic(String::from("Failed to serialize data."))),
        }
    }

    /// Deserialize custom type data from string. Reverse of ser().
    pub fn deser<T>(data: String) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        match serde_json::from_str(&data) {
            Ok(v) => Ok(v),
            Err(_) => Err(LockboxError::Generic(String::from(
                "Failed to deserialize string.",
            ))),
        }
    }

    /// Create new item in table
    pub fn insert(&self, id: &Uuid, table: Table) -> Result<u64> {
        let dbw = self.database_w()?;
        let statement = dbw.prepare(&format!(
            "INSERT INTO {} (id) VALUES ($1)",
            table.to_string()
        ))?;

        Ok(statement.execute(&[id])?)
    }

    /// Remove row in table
    pub fn remove(&self, id: &Uuid, table: Table) -> Result<()> {
        let dbw = self.database_w()?;
        let statement =
            dbw.prepare(&format!("DELETE FROM {} WHERE id = $1;", table.to_string()))?;
        if statement.execute(&[&id])? == 0 {
            return Err(LockboxError::DBError(UpdateFailed, id.to_string()));
        }

        Ok(())
    }

    /// Returns str list of column names for SQL UPDATE prepare statement.
    fn update_columns_str(&self, cols: Vec<Column>) -> String {
        let cols_len = cols.len();
        let mut str = "".to_owned();
        for (i, col) in cols.iter().enumerate() {
            str.push_str(&col.to_string());
            str.push_str(&format!("=${}", i + 1));
            if i != cols_len - 1 {
                str.push_str(",");
            }
        }
        str
    }

    /// Update items in table for some ID with PostgreSql data types (String, int, bool, Uuid, chrono::NaiveDateTime).
    pub fn update<'a>(
        &self,
        id: &Uuid,
        table: Table,
        column: Vec<Column>,
        data: Vec<&'a dyn ToSql>,
    ) -> Result<()> {
        let num_items = column.len();
        let dbw = self.database_w()?;
        let statement = dbw.prepare(&format!(
            "UPDATE {} SET {} WHERE id = ${}",
            table.to_string(),
            self.update_columns_str(column),
            num_items + 1
        ))?;

        let mut owned_data = data.clone();
        owned_data.push(id);

        if statement.execute(&owned_data)? == 0 {
            return Err(LockboxError::DBError(UpdateFailed, id.to_string()));
        }

        Ok(())
    }

    /// Get items from table for some ID with PostgreSql data types (String, int, Uuid, bool, Uuid, chrono::NaiveDateTime).
    /// Err if ID not found. Return None if data item empty.
    fn get<T, U, V, W>(
        &self,
        id: Uuid,
        table: Table,
        column: Vec<Column>,
    ) -> Result<(Option<T>, Option<U>, Option<V>, Option<W>)>
    where
        T: rocket_contrib::databases::postgres::types::FromSql,
        U: rocket_contrib::databases::postgres::types::FromSql,
        V: rocket_contrib::databases::postgres::types::FromSql,
        W: rocket_contrib::databases::postgres::types::FromSql,
    {
        let num_items = column.len();
        let dbr = self.database_r()?;

        let fmt_str = format!(
            "SELECT {} FROM {} WHERE id = $1",
            self.get_columns_str(&column),
            table.to_string()
        );

        let statement = dbr.prepare(&fmt_str)?;

        let rows = statement.query(&[&id])?;

        if rows.is_empty() {
            return Err(LockboxError::DBError(NoDataForID, id.to_string()));
        };

        let row = rows.get(0);

        let col1 = self.get_item_from_row::<T>(&row, 0, &id.to_string(), column[0])?;
        if num_items == 1 {
            return Ok((Some(col1), None, None, None));
        }

        let col2 = self.get_item_from_row::<U>(&row, 1, &id.to_string(), column[1])?;
        if num_items == 2 {
            return Ok((Some(col1), Some(col2), None, None));
        }

        let col3 = self.get_item_from_row::<V>(&row, 2, &id.to_string(), column[2])?;
        if num_items == 3 {
            return Ok((Some(col1), Some(col2), Some(col3), None));
        }

        let col4 = self.get_item_from_row::<W>(&row, 3, &id.to_string(), column[3])?;
        if num_items == 4 {
            return Ok((Some(col1), Some(col2), Some(col3), Some(col4)));
        }

        Ok((None, None, None, None))
    }
    /// Returns str list of column names for SQL SELECT query statement.
    pub fn get_columns_str(&self, cols: &Vec<Column>) -> String {
        let cols_len = cols.len();
        let mut str = "".to_owned();
        for (i, col) in cols.iter().enumerate() {
            str.push_str(&col.to_string());
            if i != cols_len - 1 {
                str.push_str(",");
            }
        }
        str
    }

    fn get_item_from_row<T>(
        &self,
        row: &Row,
        index: usize,
        id: &String,
        column: Column,
    ) -> Result<T>
    where
        T: rocket_contrib::databases::postgres::types::FromSql,
    {
        match row.get_opt::<usize, T>(index) {
            None => return Err(LockboxError::DBError(NoDataForID, id.to_string())),
            Some(data) => match data {
                Ok(v) => Ok(v),
                Err(_) => return Err(LockboxError::DBErrorWC(NoDataForID, id.to_string(), column)),
            },
        }
    }

    /// Get 1 item from row in table. Err if ID not found. Return None if data item empty.
    pub fn get_1<T>(&self, id: Uuid, table: Table, column: Vec<Column>) -> Result<T>
    where
        T: rocket_contrib::databases::postgres::types::FromSql,
    {
        let (res, _, _, _) = self.get::<T, T, T, T>(id, table, column)?;
        res.ok_or(LockboxError::DBError(
            crate::error::DBErrorType::NoDataForID,
            "item not found".to_string(),
        ))
        //Ok(res.unwrap()) //  err returned from db_get if desired item is None
    }
    /// Get 2 items from row in table. Err if ID not found. Return None if data item empty.
    pub fn get_2<T, U>(&self, id: Uuid, table: Table, column: Vec<Column>) -> Result<(T, U)>
    where
        T: rocket_contrib::databases::postgres::types::FromSql,
        U: rocket_contrib::databases::postgres::types::FromSql,
    {
        let (res1, res2, _, _) = self.get::<T, U, U, U>(id, table, column)?;
        Ok((res1.unwrap(), res2.unwrap()))
    }
    /// Get 3 items from row in table. Err if ID not found. Return None if data item empty.
    pub fn get_3<T, U, V>(&self, id: Uuid, table: Table, column: Vec<Column>) -> Result<(T, U, V)>
    where
        T: rocket_contrib::databases::postgres::types::FromSql,
        U: rocket_contrib::databases::postgres::types::FromSql,
        V: rocket_contrib::databases::postgres::types::FromSql,
    {
        let (res1, res2, res3, _) = self.get::<T, U, V, V>(id, table, column)?;
        Ok((res1.unwrap(), res2.unwrap(), res3.unwrap()))
    }
    /// Get 4 items from row in table. Err if ID not found. Return None if data item empty.
    pub fn get_4<T, U, V, W>(
        &self,
        id: Uuid,
        table: Table,
        column: Vec<Column>,
    ) -> Result<(T, U, V, W)>
    where
        T: rocket_contrib::databases::postgres::types::FromSql,
        U: rocket_contrib::databases::postgres::types::FromSql,
        V: rocket_contrib::databases::postgres::types::FromSql,
        W: rocket_contrib::databases::postgres::types::FromSql,
    {
        let (res1, res2, res3, res4) = self.get::<T, U, V, W>(id, table, column)?;
        Ok((res1.unwrap(), res2.unwrap(), res3.unwrap(), res4.unwrap()))
    }
}

impl Database for PGDatabase {
    fn init(&self) -> Result<()> {
        self.make_tables()
    }

    fn from_pool(pool: r2d2::Pool<PostgresConnectionManager>) -> Self {
        Self {
            pool: Some(pool),
        }
    }

    fn get_new() -> Self {
        Self {
            pool: None,
        }
    }

    fn set_connection_from_config(&mut self, config: &crate::config::Config) -> Result<()> {
        let rocket_url = get_postgres_url(
            config.storage.db_host_w.clone(),
            config.storage.db_port_w.clone(),
            config.storage.db_user_w.clone(),
            config.storage.db_pass_w.clone(),
            config.storage.db_database_w.clone(),
        );
        self.set_connection(&rocket_url)
    }

    fn set_connection(&mut self, url: &String) -> Result<()> {
        match Self::get_postgres_connection_pool(url) {
            Ok(p) => {
                self.pool = Some(p.clone());
                Ok(())
            }
            Err(e) => Err(LockboxError::DBError(
                ConnectionFailed,
                format!("Error obtaining pool address for url {}: {}", url, e),
            )),
        }
    }

    fn reset(&self) -> Result<()> {
        // truncate all postgres tables
        self.truncate_tables()
    }

    fn get_user_auth(&self, user_id: Uuid) -> Result<Uuid> {
        self.get_1::<Uuid>(user_id, Table::UserSession, vec![Column::Id])
    }

    fn get_statechain_id(&self, user_id: Uuid) -> Result<Uuid> {
        self.get_1::<Uuid>(user_id, Table::UserSession, vec![Column::StateChainId])
    }

    fn update_statechain_id(&self, user_id: &Uuid, state_chain_id: &Uuid) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::StateChainId],
            vec![state_chain_id],
        )
    }

    // Remove state_chain_id from user session to signal end of session
    fn remove_statechain_id(&self, user_id: &Uuid) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::StateChainId],
            vec![&Uuid::nil()],
        )
    }

    fn get_proof_key(&self, user_id: Uuid) -> Result<String> {
        let proof_key =
            self.get_1::<String>(user_id, Table::UserSession, vec![Column::ProofKey])?;
        Ok(proof_key)
    }
}
