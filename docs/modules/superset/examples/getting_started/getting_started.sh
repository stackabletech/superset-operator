#! /usr/bin/env bash
set -euo pipefail

# DO NOT EDIT THE SCRIPT
# Instead, update the j2 template, and regenerate it for dev with `make render-docs`.

# TODO (@NickLarsenNZ): Use bitnami/postgres chart, and add version var to the above list
# See similar changes in: https://github.com/stackabletech/hive-operator/pull/489/commits/8189f196f018c009370ae9b07a3f9609ee2e8681

# This script contains all the code snippets from the guide, as well as some assert tests
# to test if the instructions in the guide work. The user *could* use it, but it is intended
# for testing only.
# The script will install the operators, create a superset instance and briefly open a port
# forward and connect to the superset instance to make sure it is up and running.
# No running processes are left behind (i.e. the port-forwarding is closed at the end)

if [ $# -eq 0 ]
then
  echo "Installation method argument ('helm' or 'stackablectl') required."
  exit 1
fi

cd "$(dirname "$0")"

case "$1" in
"helm")
echo "Installing Operators with Helm"
# tag::helm-install-operators[]
helm install --wait commons-operator oci://oci.stackable.tech/sdp-charts/commons-operator --version 0.0.0-dev
helm install --wait secret-operator oci://oci.stackable.tech/sdp-charts/secret-operator --version 0.0.0-dev
helm install --wait listener-operator oci://oci.stackable.tech/sdp-charts/listener-operator --version 0.0.0-dev
helm install --wait superset-operator oci://oci.stackable.tech/sdp-charts/superset-operator --version 0.0.0-dev
# end::helm-install-operators[]
;;
"stackablectl")
echo "installing Operators with stackablectl"
# tag::stackablectl-install-operators[]
stackablectl operator install \
  commons=0.0.0-dev \
  secret=0.0.0-dev \
  listener=0.0.0-dev \
  superset=0.0.0-dev
# end::stackablectl-install-operators[]
;;
*)
echo "Need to give 'helm' or 'stackablectl' as an argument for which installation method to use!"
exit 1
;;
esac

echo "Installing bitnami PostgreSQL"
# tag::install-bitnami-psql[]
helm install superset oci://registry-1.docker.io/bitnamicharts/postgresql \
    --version 16.5.0 \
    --set auth.username=superset \
    --set auth.password=superset \
    --set auth.database=superset \
    --wait
# end::install-bitnami-psql[]

echo "Creating credentials secret"
# tag::apply-superset-credentials[]
kubectl apply -f superset-credentials.yaml
# end::apply-superset-credentials[]

echo "Creating Superset cluster"
# tag::apply-superset-cluster[]
kubectl apply -f superset.yaml
# end::apply-superset-cluster[]

sleep 5

for (( i=1; i<=15; i++ ))
do
  echo "Waiting for SupersetCluster to appear ..."
  if eval kubectl get statefulset simple-superset-node-default; then
    break
  fi

  sleep 1
done

echo "Waiting on superset StatefulSet ..."
# tag::wait-superset[]
kubectl rollout status --watch statefulset/simple-superset-node-default --timeout 300s
# end::wait-superset[]

# wait a bit for the port to open
sleep 10

echo "Starting port-forwarding of port 8088"
# tag::port-forwarding[]
kubectl port-forward service/simple-superset-node 8088 > /dev/null 2>&1 &
# end::port-forwarding[]
PORT_FORWARD_PID=$!
# shellcheck disable=2064 # we want the PID evaluated now, not at the time the trap is
trap "kill $PORT_FORWARD_PID" EXIT
sleep 5

echo "Checking if web interface is reachable ..."
return_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8088/login/)
if [ "$return_code" == 200 ]; then
  echo "Web interface reachable!"
else
  echo "Could not reach web interface."
  exit 1
fi

echo "Loading examples ..."
# tag::load-examples[]
kubectl apply -f superset-load-examples-job.yaml
sleep 5
kubectl wait --for=condition=complete --timeout=300s job/superset-load-examples
# end::load-examples[]
