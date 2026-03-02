#!/bin/sh
ACCESS_TOKEN=$(curl -s -X POST "http://superset-node:8088/api/v1/security/login" \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "admin", "provider": "db"}' | jq -r '.access_token')

EXECUTE_QUERY_RESPONSE=$(curl -X POST "http://superset-node:8088/api/v1/sqllab/execute/" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"database_id": 1, "runAsync": true, "sql": "SELECT username, first_name, last_name from public.ab_user;"}')

QUERY_ID=$(echo "$EXECUTE_QUERY_RESPONSE" | jq -r '.query.queryId')
QUERY_STATE=$(echo "$EXECUTE_QUERY_RESPONSE" | jq -r '.query.state')

echo "Query started with ID: '$QUERY_ID' in state '$QUERY_STATE' ..."

while [ "$QUERY_STATE" == "pending" ] || [ "$QUERY_STATE" == "running" ]; do
    POLL_RESPONSE=$(curl -s -X GET "http://superset-node:8088/api/v1/query/$QUERY_ID" \
        -H "Authorization: Bearer $ACCESS_TOKEN")
    
    QUERY_STATE=$(echo $POLL_RESPONSE | jq -r '.result.status')
    echo "Current State: '$QUERY_STATE'"

    if [ "$QUERY_STATE" == "failed" ]; then
        echo "Query failed!"
        echo "$POLL_RESPONSE"
        exit 1
    fi

    sleep 1
done

if [ "$QUERY_STATE" == "success" ]; then
    RESULTS_KEY=$(echo "$POLL_RESPONSE" | jq -r '.result.results_key')
    
    echo "Query successful! Fetching data for results_key '$RESULTS_KEY' ..."

    DATA_RESPONSE=$(curl -s -X GET "http://superset-node:8088/api/v1/sqllab/results/?q=%7B%0A%20%20%22key%22%3A%20%22${RESULTS_KEY}%22%0A%7D" \
        -H "Authorization: Bearer $ACCESS_TOKEN")

    echo "$DATA_RESPONSE" | jq '.data'
else
    echo "Query finished with unexpected state: $QUERY_STATE"
    exit 1
fi
