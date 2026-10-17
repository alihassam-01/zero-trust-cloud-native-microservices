#!/usr/bin/env python3
"""
Policy Synthesizer for Zero Trust Cloud-Native Architectures
Author: Hassam Ali (ali.hassam1@outlook.com)
Repository: https://github.com/Hassam-01/zero-trust-cloud-native-microservices

Transforms communication graphs into declarative, production-ready
Istio AuthorizationPolicy (L7) and Kubernetes NetworkPolicy (L3/L4) manifests.
Includes an in-memory policy simulator for verification and dry-run validation.
"""

import json
import argparse
from typing import Dict, List, Any, Optional
from collections import defaultdict


class PolicySynthesizer:
    """Synthesizes least-privilege Istio and Kubernetes security policies from communication graphs."""

    def __init__(self, graph_data: Dict[str, Any], namespace: str = "sock-shop"):
        self.graph = graph_data
        self.namespace = namespace
        self.edges = graph_data.get("edges", [])
        self.nodes = graph_data.get("nodes", [])

        # Group edges by destination workload
        self.inbound_by_destination = defaultdict(list)
        for edge in self.edges:
            self.inbound_by_destination[edge["destination"]].append(edge)

    def generate_istio_authorization_policies(self) -> str:
        """Synthesize Istio AuthorizationPolicy manifests."""
        manifests = []

        # 1. Namespace Default-Deny AuthorizationPolicy
        default_deny = f"""apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: default-deny-all
  namespace: {self.namespace}
  labels:
    app.kubernetes.io/managed-by: zero-trust-policy-synthesizer
spec:
  # Empty spec denies all ingress traffic by default in Istio
  {{}}"""
        manifests.append(default_deny)

        # 2. Edge Ingress Policy for Frontend
        if "front-end" in self.nodes:
            frontend_policy = f"""---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-frontend-edge-ingress
  namespace: {self.namespace}
  labels:
    app.kubernetes.io/managed-by: zero-trust-policy-synthesizer
spec:
  selector:
    matchLabels:
      name: front-end
  action: ALLOW
  rules:
  - to:
    - operation:
        ports: ["8079", "80"]"""
            manifests.append(frontend_policy)

        # 3. Workload-specific Least-Privilege Policies
        for dst, edges in sorted(self.inbound_by_destination.items()):
            rules_yaml = []

            for edge in edges:
                src_principal = edge["source_principal"]
                port = str(edge["destination_port"])
                protocol = edge["protocol"]

                if protocol == "HTTP" and edge.get("operations"):
                    for op in edge["operations"]:
                        method = op["method"]
                        paths = op["paths"]
                        paths_formatted = json.dumps(paths)
                        rule = f"""  - from:
    - source:
        principals: ["{src_principal}"]
    to:
    - operation:
        methods: ["{method}"]
        paths: {paths_formatted}
        ports: ["{port}"]"""
                        rules_yaml.append(rule)
                else:
                    # L4 TCP Service (e.g. databases, message queues)
                    rule = f"""  - from:
    - source:
        principals: ["{src_principal}"]
    to:
    - operation:
        ports: ["{port}"]"""
                    rules_yaml.append(rule)

            rules_str = "\n".join(rules_yaml)
            policy = f"""---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-to-{dst}
  namespace: {self.namespace}
  labels:
    app.kubernetes.io/managed-by: zero-trust-policy-synthesizer
spec:
  selector:
    matchLabels:
      name: {dst}
  action: ALLOW
  rules:
{rules_str}"""
            manifests.append(policy)

        return "\n".join(manifests) + "\n"

    def generate_kubernetes_network_policies(self) -> str:
        """Synthesize Layer 3/4 Kubernetes NetworkPolicy manifests."""
        manifests = []

        # 1. Default Deny All Ingress and Egress
        default_deny = f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: {self.namespace}
  labels:
    app.kubernetes.io/managed-by: zero-trust-policy-synthesizer
spec:
  podSelector: {{}}
  policyTypes:
  - Ingress
  - Egress"""
        manifests.append(default_deny)

        # 2. Allow Essential System Egress (DNS & Istio Control Plane)
        system_egress = f"""---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-system-core-egress
  namespace: {self.namespace}
  labels:
    app.kubernetes.io/managed-by: zero-trust-policy-synthesizer
spec:
  podSelector: {{}}
  policyTypes:
  - Egress
  egress:
  # Allow DNS resolution
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
  # Allow Istiod mTLS CA certificate exchange
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: istio-system
    ports:
    - protocol: TCP
      port: 15012"""
        manifests.append(system_egress)

        # 3. Workload Ingress NetworkPolicies
        for dst, edges in sorted(self.inbound_by_destination.items()):
            from_blocks = []
            for edge in edges:
                src = edge["source"]
                port = edge["destination_port"]
                from_block = f"""  - from:
    - podSelector:
        matchLabels:
          name: {src}
    ports:
    - protocol: TCP
      port: {port}"""
                from_blocks.append(from_block)

            # Special case: allow edge ingress to front-end
            if dst == "front-end":
                from_blocks.append("""  - ports:
    - protocol: TCP
      port: 8079""")

            from_str = "\n".join(from_blocks)
            netpol = f"""---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-to-{dst}
  namespace: {self.namespace}
  labels:
    app.kubernetes.io/managed-by: zero-trust-policy-synthesizer
spec:
  podSelector:
    matchLabels:
      name: {dst}
  policyTypes:
  - Ingress
  ingress:
{from_str}"""
            manifests.append(netpol)

        return "\n".join(manifests) + "\n"

    def evaluate_request(
        self,
        source_workload: str,
        destination_workload: str,
        port: int,
        method: Optional[str] = None,
        path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Simulate policy engine evaluation for an arbitrary access request.
        Returns whether the request would be ALLOWED or DENIED by the synthesized policy set.
        """
        # Find matching edge in inbound rules for destination
        candidate_edges = [
            e for e in self.inbound_by_destination.get(destination_workload, [])
            if e["source"] == source_workload and e["destination_port"] == port
        ]

        if not candidate_edges:
            return {
                "decision": "DENY",
                "reason": f"No allowed edge from '{source_workload}' to '{destination_workload}:{port}' in policy graph"
            }

        edge = candidate_edges[0]
        if edge["protocol"] == "TCP":
            return {
                "decision": "ALLOW",
                "reason": f"Authorized L4 TCP flow from '{source_workload}' to '{destination_workload}:{port}'"
            }

        # HTTP evaluation
        if method:
            for op in edge.get("operations", []):
                if op["method"].upper() == method.upper():
                    # Check path matching (exact or wildcard)
                    if not path:
                        return {"decision": "ALLOW", "reason": "Method authorized (no path specified)"}

                    for allowed_path in op["paths"]:
                        if allowed_path.endswith("*"):
                            prefix = allowed_path[:-1]
                            if path.startswith(prefix):
                                return {
                                    "decision": "ALLOW",
                                    "reason": f"Path '{path}' matched wildcard pattern '{allowed_path}'"
                                }
                        elif path == allowed_path:
                            return {
                                "decision": "ALLOW",
                                "reason": f"Exact path match on '{path}'"
                            }

            return {
                "decision": "DENY",
                "reason": f"Method '{method}' or path '{path}' not whitelisted in policy rule"
            }

        return {"decision": "ALLOW", "reason": "Edge connection authorized"}


def main():
    parser = argparse.ArgumentParser(description="Synthesize Istio and K8s Zero Trust policies from communication graph")
    parser.add_argument("--graph-file", "-g", required=True, help="Input communication graph JSON file")
    parser.add_argument("--output-dir", "-o", default="k8s/synthesized", help="Output directory for YAML manifests")
    parser.add_argument("--namespace", "-n", default="sock-shop", help="Target Kubernetes namespace")
    args = parser.parse_args()

    with open(args.graph_file, "r", encoding="utf-8") as f:
        graph = json.load(f)

    synthesizer = PolicySynthesizer(graph, namespace=args.namespace)

    import os
    os.makedirs(args.output_dir, exist_ok=True)

    # 1. Export Istio AuthorizationPolicies
    istio_file = os.path.join(args.output_dir, "istio-authorization-policies.yaml")
    istio_yaml = synthesizer.generate_istio_authorization_policies()
    with open(istio_file, "w", encoding="utf-8") as f:
        f.write(istio_yaml)
    print(f"Synthesized Istio AuthorizationPolicies written to: {istio_file}")

    # 2. Export Kubernetes NetworkPolicies
    k8s_file = os.path.join(args.output_dir, "kubernetes-network-policies.yaml")
    k8s_yaml = synthesizer.generate_kubernetes_network_policies()
    with open(k8s_file, "w", encoding="utf-8") as f:
        f.write(k8s_yaml)
    print(f"Synthesized Kubernetes NetworkPolicies written to: {k8s_file}")

    # 3. Export Consolidated Bundle
    bundle_file = os.path.join(args.output_dir, "consolidated-zero-trust-policies.yaml")
    with open(bundle_file, "w", encoding="utf-8") as f:
        f.write(istio_yaml + "\n---\n" + k8s_yaml)
    print(f"Consolidated Zero Trust Policy bundle written to: {bundle_file}")


if __name__ == "__main__":
    main()
