#!/usr/bin/env bash
# ==============================================================================
# Script: 03_apply_scenario.sh
# Purpose: Dynamically switch security scenarios (c0, c1, c2) in the testbed
# Author: Hassam Ali
# Usage: ./scripts/03_apply_scenario.sh [c0|c1|c2]
# ==============================================================================

set -euo pipefail

SCENARIO="${1:-}"

if [[ -z "${SCENARIO}" ]]; then
  echo "Usage: $0 [c0|c1|c2]"
  echo "  c0: Baseline Perimeter (Permissive mTLS, No AuthorizationPolicies, No NetworkPolicies)"
  echo "  c1: Workload Identity & STRICT mTLS (Authentication Only, No AuthorizationPolicies)"
  echo "  c2: Layered Zero Trust Architecture (STRICT mTLS + L7 AuthorizationPolicies + L3/L4 NetworkPolicies)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================================"
echo ">> Switching Security Configuration to: ${SCENARIO^^}"
echo "================================================================================"

# Step 1: Clean up any existing security & network policies
echo ">> [1/3] Flushing existing AuthorizationPolicies and NetworkPolicies..."
kubectl delete authorizationpolicy --all -n sock-shop --ignore-not-found=true
kubectl delete networkpolicy --all -n sock-shop --ignore-not-found=true
kubectl delete peerauthentication --all -n sock-shop --ignore-not-found=true

case "${SCENARIO}" in
  c0)
    echo ">> [2/3] Configuring Scenario C0: Baseline Perimeter"
    # In C0, peer authentication is PERMISSIVE (or disabled), no auth policies
    cat <<EOF | kubectl apply -f -
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: sock-shop
spec:
  mtls:
    mode: PERMISSIVE
EOF
    echo ">> [3/3] Scenario C0 applied successfully! (East-West open, unauthenticated allowed)"
    ;;

  c1)
    echo ">> [2/3] Configuring Scenario C1: STRICT mTLS"
    kubectl apply -f "${ROOT_DIR}/k8s/mtls-c1/peer-authentication-strict.yaml"
    echo ">> [3/3] Scenario C1 applied successfully! (STRICT mTLS active, no L7 auth rules)"
    ;;

  c2)
    echo ">> [2/3] Configuring Scenario C2: Layered Zero Trust Architecture"
    kubectl apply -f "${ROOT_DIR}/k8s/mtls-c1/peer-authentication-strict.yaml"
    kubectl apply -f "${ROOT_DIR}/k8s/layered-zta-c2/authorization-policies.yaml"
    kubectl apply -f "${ROOT_DIR}/k8s/layered-zta-c2/network-policies.yaml"
    echo ">> [3/3] Scenario C2 applied successfully! (STRICT mTLS + L7 Auth + L4 NetPol active)"
    ;;

  *)
    echo "Error: Unknown scenario '${SCENARIO}'. Must be c0, c1, or c2."
    exit 1
    ;;
esac

echo ">> Configuration successfully verified for scenario: ${SCENARIO^^}"
