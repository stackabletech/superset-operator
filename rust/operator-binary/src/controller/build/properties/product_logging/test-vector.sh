#!/usr/bin/env sh

# `TZ=UTC` so the Python-JSON `asctime` (which has no timezone) parses deterministically.
TZ=UTC \
DATA_DIR=/stackable/log/_vector-state \
LOG_DIR=/stackable/log \
NAMESPACE=default \
CLUSTER_NAME=superset \
ROLE_NAME=node \
ROLE_GROUP_NAME=default \
VECTOR_AGGREGATOR_ADDRESS=vector-aggregator \
VECTOR_FILE_LOG_LEVEL=info \
vector test vector.yaml vector-test.yaml
