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

case "$1" in
"helm")
echo "Adding 'stackable-stable' Helm Chart repository"
# tag::helm-add-repo[]
helm repo add stackable-stable https://repo.stackable.tech/repository/helm-stable/
# end::helm-add-repo[]
echo "Installing Operators with Helm"
# tag::helm-install-operators[]
helm install --wait commons-operator stackable-stable/commons-operator --version 23.1.0
helm install --wait secret-operator stackable-stable/secret-operator --version 23.1.0
helm install --wait superset-operator stackable-stable/superset-operator --version 23.1.0
# end::helm-install-operators[]
;;
"stackablectl")
echo "installing Operators with stackablectl"
# tag::stackablectl-install-operators[]
stackablectl operator install \
  commons=23.1.0 \
  secret=23.1.0 \
  superset=23.1.0
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

echo "Waiting on SupersetDB ..."
# tag::wait-supersetdb[]
kubectl wait supersetdb/simple-superset \
  --for jsonpath='{.status.condition}'=Ready \
  --timeout 300s
# end::wait-supersetdb[]

sleep 5

echo "Wainting on superset StatefulSet ..."
kubectl rollout status --watch statefulset/simple-superset-node-default

echo "Starting port-forwarding of port 8088"
# tag::port-forwarding[]
kubectl port-forward service/simple-superset-external 8088 2>&1 >/dev/null &
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
