#!/bin/sh
ACCESS_TOKEN=$(curl -s -X POST "http://superset-node:8088/api/v1/security/login" \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "admin", "provider": "db"}' | jq -r '.access_token')

EXECUTE_QUERY_RESPONSE=$(curl -X POST "http://superset-node:8088/api/v1/sqllab/execute/" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"database_id": 1, "runAsync": true, "sql": "SELECT username from public.ab_user;"}')

QUERY_ID=$(echo "$EXECUTE_QUERY_RESPONSE" | jq -r '.query.queryId')
QUERY_STATE=$(echo "$EXECUTE_QUERY_RESPONSE" | jq -r '.query.state')

echo "Query started with ID: '$QUERY_ID' in state '$QUERY_STATE'"

while [ "$QUERY_STATE" == "pending" ] || [ "$QUERY_STATE" == "running" ]; do
    sleep 1

    POLL_RESPONSE=$(curl -s -X GET "http://superset-node:8088/api/v1/query/$QUERY_ID" \
        -H "Authorization: Bearer $ACCESS_TOKEN")
    
    QUERY_STATE=$(echo $POLL_RESPONSE | jq -r '.result.status')
    echo "Current State: '$QUERY_STATE'"

    if [ "$QUERY_STATEE" == "failed" ]; then
        echo "Query failed!"
        echo $POLL_RESPONSE | jq -r '.result.error'
        exit 1
    fi
done

echo "Query finished! Fetching results..."
echo "$POLL_RESPONSE" | jq '.result'
