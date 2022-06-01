#!/bin/bash
git clone -b "$GIT_BRANCH" https://github.com/stackabletech/superset-operator.git
(cd superset-operator/ && ./scripts/run_tests.sh)
exit_code=$?
./operator-logs.sh superset > /target/superset-operator.log
exit $exit_code
