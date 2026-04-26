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
pub enum CeleryResultsBackendConnection {
    // Docs are on the struct
    Redis(RedisConnection),
}

impl Deref for CeleryResultsBackendConnection {
    type Target = dyn CeleryDatabaseConnection;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Redis(r) => r,
        }
    }
}

impl CeleryResultsBackendConnection {
    pub fn as_python_parameters(&self) -> CeleryResultsBackendConnectionDetails {
        match &self {
            CeleryResultsBackendConnection::Redis(redis_connection) => {
                CeleryResultsBackendConnectionDetails {
                    host: stackable_operator::commons::networking::HostName::from(
                        redis_connection.host.clone(),
                    ),
                    port: redis_connection.port,
                    database_id: redis_connection.database_id,
                }
            }
        }
    }
}

pub struct CeleryResultsBackendConnectionDetails {
    pub host: stackable_operator::commons::networking::HostName,
    pub port: u16,
    pub database_id: u16,
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
