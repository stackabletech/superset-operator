#!/usr/bin/env bash
# This script reads a Helm chart from deploy/helm/superset-operator and
# generates manifest files into deploy/manifestss
set -e

tmp=$(mktemp -d ./manifests-XXXXX)

helm template --output-dir "$tmp" \
              --include-crds \
              --name-template superset-operator \
              deploy/helm/superset-operator

while IFS= read -r -d '' file
do
    yq eval -i 'del(.. | select(has("app.kubernetes.io/managed-by")) | ."app.kubernetes.io/managed-by")' /dev/stdin < "$file"
    yq eval -i 'del(.. | select(has("helm.sh/chart")) | ."helm.sh/chart")' /dev/stdin < "$file"
    sed -i '/# Source: .*/d' "$file"
done <   <(find "$tmp" -type f)

cp -r "$tmp"/superset-operator/*/* deploy/manifests/

rm -rf "$tmp"
