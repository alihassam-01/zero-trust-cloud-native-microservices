#!/usr/bin/env bash
# ==============================================================================
# Script: 02_deploy_sockshop.sh
# Purpose: Deploy Sock Shop microservices with distinct ServiceAccounts
# Author: Hassam Ali
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================================"
echo ">> [1/3] Applying sock-shop Namespace and Distinct ServiceAccounts..."
echo "================================================================================"

kubectl apply -f "${ROOT_DIR}/k8s/app/00-namespace.yaml"
kubectl apply -f "${ROOT_DIR}/k8s/app/01-serviceaccounts.yaml"

echo "================================================================================"
echo ">> [2/3] Deploying Sock Shop Microservices and Datastores..."
echo "================================================================================"

kubectl apply -f "${ROOT_DIR}/k8s/app/02-sock-shop-workloads.yaml"

echo "================================================================================"
echo ">> [3/3] Awaiting Rollout of All 14 Deployments..."
echo "================================================================================"

WORKLOADS=(
  "front-end"
  "catalogue"
  "catalogue-db"
  "carts"
  "carts-db"
  "orders"
  "orders-db"
  "payment"
  "shipping"
  "queue-master"
  "rabbitmq"
  "session-db"
  "user"
  "user-db"
)

for w in "${WORKLOADS[@]}"; do
  echo ">> Waiting for deployment/${w}..."
  kubectl rollout status "deployment/${w}" -n sock-shop --timeout=90s
done

echo ">> All workloads deployed and healthy!"
kubectl get pods -n sock-shop -o custom-columns='NAME:.metadata.name,SERVICE_ACCOUNT:.spec.serviceAccountName,STATUS:.status.phase'
