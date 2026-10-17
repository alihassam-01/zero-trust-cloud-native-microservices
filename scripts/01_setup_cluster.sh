#!/usr/bin/env bash
# ==============================================================================
# Script: 01_setup_cluster.sh
# Purpose: Initialize Minikube cluster and install Istio Service Mesh
# Author: Hassam Ali
# ==============================================================================

set -euo pipefail

echo "================================================================================"
echo ">> [1/4] Verifying Minikube & Kubernetes Control Plane..."
echo "================================================================================"

if ! minikube status >/dev/null 2>&1; then
  echo ">> Minikube is not running. Starting Minikube..."
  minikube start --driver=docker --memory=6144 --cpus=4
else
  echo ">> Minikube is active."
fi

kubectl cluster-info

echo "================================================================================"
echo ">> [2/4] Verifying Istio Installation..."
echo "================================================================================"

ISTIOCTL_BIN=""
if command -v istioctl >/dev/null 2>&1; then
  ISTIOCTL_BIN="istioctl"
elif [[ -x "/home/hassamali/Work/ZTA/istio-1.30.4/bin/istioctl" ]]; then
  ISTIOCTL_BIN="/home/hassamali/Work/ZTA/istio-1.30.4/bin/istioctl"
fi

if [[ -n "${ISTIOCTL_BIN}" ]]; then
  echo ">> Using istioctl: ${ISTIOCTL_BIN}"
  "${ISTIOCTL_BIN}" version
else
  echo ">> Warning: istioctl binary not in PATH. Please verify Istio installation."
fi

kubectl get pods -n istio-system

echo "================================================================================"
echo ">> [3/4] Enabling Prometheus and Access Telemetry..."
echo "================================================================================"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

kubectl apply -f "${ROOT_DIR}/k8s/observability/telemetry.yaml"

echo "================================================================================"
echo ">> [4/4] Environment verification complete!"
echo "================================================================================"
