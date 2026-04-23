use std::ops::Deref;

use serde::{Deserialize, Serialize};
use stackable_operator::{
    database_connections::{
        databases::{postgresql::PostgresqlConnection, redis::RedisConnection},
        drivers::{
            celery::{CeleryDatabaseConnection, GenericCeleryDatabaseConnection},
            sqlalchemy::{GenericSqlAlchemyDatabaseConnection, SqlAlchemyDatabaseConnection},
        },
    },
    schemars::{self, JsonSchema},
};

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MetadataDatabaseConnection {
    // Docs are on the struct
    Postgresql(PostgresqlConnection),

    // Docs are on the struct
    Generic(GenericSqlAlchemyDatabaseConnection),
}

impl Deref for MetadataDatabaseConnection {
    type Target = dyn SqlAlchemyDatabaseConnection;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Postgresql(p) => p,
            Self::Generic(g) => g,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CeleryResultBackendConnection {
    // Docs are on the struct
    Postgresql(PostgresqlConnection),

    // Docs are on the struct
    Generic(GenericCeleryDatabaseConnection),
}

impl Deref for CeleryResultBackendConnection {
    type Target = dyn CeleryDatabaseConnection;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Postgresql(p) => p,
            Self::Generic(g) => g,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CeleryBrokerConnection {
    // Docs are on the struct
    Redis(RedisConnection),

    // Docs are on the struct
    Generic(GenericCeleryDatabaseConnection),
}

impl Deref for CeleryBrokerConnection {
    type Target = dyn CeleryDatabaseConnection;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Redis(r) => r,
            Self::Generic(g) => g,
        }
    }
}
