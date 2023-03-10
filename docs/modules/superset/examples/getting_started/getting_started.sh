#! /usr/bin/env bash
set -euo pipefail

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
echo "Adding 'stackable-dev' Helm Chart repository"
# tag::helm-add-repo[]
helm repo add stackable-dev https://repo.stackable.tech/repository/helm-dev/
# end::helm-add-repo[]
echo "Updating Helm repo"
helm repo update
echo "Installing Operators with Helm"
# tag::helm-install-operators[]
helm install --wait commons-operator stackable-dev/commons-operator --version 0.0.0-dev
helm install --wait secret-operator stackable-dev/secret-operator --version 0.0.0-dev
helm install --wait superset-operator stackable-dev/superset-operator --version 0.0.0-dev
# end::helm-install-operators[]
;;
"stackablectl")
echo "installing Operators with stackablectl"
# tag::stackablectl-install-operators[]
stackablectl operator install \
  commons=0.0.0-dev \
  secret=0.0.0-dev \
  superset=0.0.0-dev
# end::stackablectl-install-operators[]
;;
*)
echo "Need to give 'helm' or 'stackablectl' as an argument for which installation method to use!"
exit 1
;;
esac

echo "Adding bitnami Helm repository"
# tag::add-bitnami-repo[]
helm repo add bitnami https://charts.bitnami.com/bitnami
# end::add-bitnami-repo[]

echo "Installing bitnami PostgreSQL"
# tag::install-bitnami-psql[]
helm install --wait superset bitnami/postgresql \
    --set auth.username=superset \
    --set auth.password=superset \
    --set auth.database=superset
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

echo "Waiting on SupersetDB ..."
# tag::wait-supersetdb[]
time kubectl wait supersetdb/simple-superset \
  --for jsonpath='{.status.condition}'=Ready \
  --timeout 600s
# end::wait-supersetdb[]

for (( i=1; i<=15; i++ ))
do
  echo "Waiting for SupersetCluster to appear ..."
  if eval kubectl get statefulset simple-superset-node-default; then
    break
  fi

  sleep 1
done

echo "Wainting on superset StatefulSet ..."
kubectl rollout status --watch statefulset/simple-superset-node-default --timeout 300s

# wait a bit for the port to open
sleep 10

echo "Starting port-forwarding of port 8088"
# tag::port-forwarding[]
kubectl port-forward service/simple-superset-external 8088 > /dev/null 2>&1 &
# end::port-forwarding[]
PORT_FORWARD_PID=$!
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
