use std::ops::Deref;

use serde::{Deserialize, Serialize};
use stackable_operator::{
    database_connections::{
        databases::postgresql::PostgresqlConnection,
        drivers::sqlalchemy::{GenericSqlAlchemyDatabaseConnection, SqlAlchemyDatabaseConnection},
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
