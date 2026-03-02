#!/bin/sh
ACCESS_TOKEN=$(curl -s -X POST "http://superset-node:8088/api/v1/security/login" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "admin",
        "password": "admin",
        "provider": "db"
    }' | jq -r '.access_token')

curl -X POST "http://superset-node:8088/api/v1/database/" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "database_name": "postgresql-integrationtest",
        "sqlalchemy_uri": "postgresql+psycopg2://superset:superset@superset-postgresql:5432/superset",
        "expose_in_sqllab": true,
        "allow_run_async": true,
        "allow_ctas": false,
        "allow_cvas": false,
        "allow_dml": false,
        "extra": "{\"allows_virtual_table_explore\": true}"
    }'
