#!/usr/bin/env python3
"""
Unit and Integration Test Suite for Zero Trust Policy Generator Extension
Author: Hassam Ali (ali.hassam1@outlook.com)
Repository: https://github.com/Hassam-01/zero-trust-cloud-native-microservices
"""

import os
import sys
import json
import unittest
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from traffic_analyzer import TrafficAnalyzer
from policy_synthesizer import PolicySynthesizer


class TestTrafficAnalyzer(unittest.TestCase):
    """Unit tests for telemetry parsing and path normalization."""

    def setUp(self):
        self.analyzer = TrafficAnalyzer()

    def test_normalize_path_uuid(self):
        """Verify UUIDs are correctly parameterized with wildcard *."""
        raw = "/catalogue/3395a43e-2d88-40de-b95f-e00e1502085e"
        normalized = TrafficAnalyzer.normalize_path(raw)
        self.assertEqual(normalized, "/catalogue/*")

    def test_normalize_path_numeric_id(self):
        """Verify numeric IDs are correctly parameterized."""
        raw = "/cart/item/104"
        normalized = TrafficAnalyzer.normalize_path(raw)
        self.assertEqual(normalized, "/cart/item/*")

    def test_normalize_path_query_parameters(self):
        """Verify query strings are stripped from endpoint path."""
        raw = "/catalogue?sort=name&limit=10"
        normalized = TrafficAnalyzer.normalize_path(raw)
        self.assertEqual(normalized, "/catalogue")

    def test_normalize_path_static_unchanged(self):
        """Verify static REST paths are unchanged."""
        raw = "/tags"
        normalized = TrafficAnalyzer.normalize_path(raw)
        self.assertEqual(normalized, "/tags")

    def test_build_communication_graph(self):
        """Verify directed communication graph generation from sample logs."""
        sample_log = [
            {
                "source_workload": "front-end",
                "source_principal": "spiffe://cluster.local/ns/sock-shop/sa/front-end",
                "destination_workload": "catalogue",
                "destination_port": 80,
                "protocol": "HTTP/1.1",
                "method": "GET",
                "path": "/catalogue/3395a43e-2d88-40de-b95f-e00e1502085e"
            },
            {
                "source_workload": "catalogue",
                "source_principal": "spiffe://cluster.local/ns/sock-shop/sa/catalogue",
                "destination_workload": "catalogue-db",
                "destination_port": 3306,
                "protocol": "TCP"
            }
        ]

        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as f:
            json.dump(sample_log, f)
            temp_path = f.name

        try:
            self.analyzer.load_logs(temp_path)
            graph = self.analyzer.build_communication_graph()

            self.assertEqual(graph["metadata"]["node_count"], 3)
            self.assertEqual(graph["metadata"]["edge_count"], 2)
            self.assertIn("front-end", graph["nodes"])
            self.assertIn("catalogue", graph["nodes"])
            self.assertIn("catalogue-db", graph["nodes"])

            edges = { (e["source"], e["destination"]): e for e in graph["edges"] }
            self.assertIn(("front-end", "catalogue"), edges)
            self.assertEqual(edges[("front-end", "catalogue")]["protocol"], "HTTP")
            self.assertEqual(edges[("catalogue", "catalogue-db")]["protocol"], "TCP")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


class TestPolicySynthesizer(unittest.TestCase):
    """Unit tests for Istio and Kubernetes policy synthesis."""

    def setUp(self):
        self.sample_graph = {
            "nodes": ["front-end", "catalogue", "catalogue-db", "orders", "payment"],
            "edges": [
                {
                    "source": "front-end",
                    "source_principal": "spiffe://cluster.local/ns/sock-shop/sa/front-end",
                    "destination": "catalogue",
                    "destination_namespace": "sock-shop",
                    "destination_port": 80,
                    "protocol": "HTTP",
                    "operations": [
                        {"method": "GET", "paths": ["/catalogue", "/catalogue/*"]}
                    ],
                    "call_count": 5
                },
                {
                    "source": "catalogue",
                    "source_principal": "spiffe://cluster.local/ns/sock-shop/sa/catalogue",
                    "destination": "catalogue-db",
                    "destination_namespace": "sock-shop",
                    "destination_port": 3306,
                    "protocol": "TCP",
                    "operations": [],
                    "call_count": 10
                },
                {
                    "source": "orders",
                    "source_principal": "spiffe://cluster.local/ns/sock-shop/sa/orders",
                    "destination": "payment",
                    "destination_namespace": "sock-shop",
                    "destination_port": 80,
                    "protocol": "HTTP",
                    "operations": [
                        {"method": "POST", "paths": ["/paymentAuth"]}
                    ],
                    "call_count": 2
                }
            ]
        }
        self.synthesizer = PolicySynthesizer(self.sample_graph, namespace="sock-shop")

    def test_istio_manifest_structure(self):
        """Verify synthesized Istio YAML contains default-deny and workload policies."""
        yaml_content = self.synthesizer.generate_istio_authorization_policies()
        self.assertIn("name: default-deny-all", yaml_content)
        self.assertIn("name: allow-to-catalogue", yaml_content)
        self.assertIn("name: allow-to-catalogue-db", yaml_content)
        self.assertIn("name: allow-to-payment", yaml_content)
        self.assertIn('principals: ["spiffe://cluster.local/ns/sock-shop/sa/front-end"]', yaml_content)
        self.assertIn('principals: ["spiffe://cluster.local/ns/sock-shop/sa/orders"]', yaml_content)

    def test_kubernetes_network_policy_structure(self):
        """Verify synthesized Kubernetes NetworkPolicy contains default-deny and pod ingress rules."""
        yaml_content = self.synthesizer.generate_kubernetes_network_policies()
        self.assertIn("name: default-deny-all", yaml_content)
        self.assertIn("name: allow-system-core-egress", yaml_content)
        self.assertIn("name: allow-ingress-to-catalogue-db", yaml_content)
        self.assertIn("name: catalogue", yaml_content)
        self.assertIn("port: 3306", yaml_content)


class TestGroundTruthPolicyEvaluation(unittest.TestCase):
    """Integration test validating policy engine decisions against ground-truth security matrix."""

    @classmethod
    def setUpClass(cls):
        sample_log_path = os.path.join(
            os.path.dirname(__file__), "..", "sample_data", "envoy_access_logs.json"
        )
        analyzer = TrafficAnalyzer()
        analyzer.load_logs(sample_log_path)
        graph = analyzer.build_communication_graph()
        cls.synthesizer = PolicySynthesizer(graph, namespace="sock-shop")

    def test_authorized_requests_are_allowed(self):
        """Verify valid transactional requests are permitted by the policy model."""
        # 1. front-end -> catalogue GET /catalogue
        res1 = self.synthesizer.evaluate_request("front-end", "catalogue", 80, "GET", "/catalogue")
        self.assertEqual(res1["decision"], "ALLOW")

        # 2. front-end -> catalogue GET /catalogue/item-uuid (wildcard match)
        res2 = self.synthesizer.evaluate_request("front-end", "catalogue", 80, "GET", "/catalogue/3395a43e-2d88")
        self.assertEqual(res2["decision"], "ALLOW")

        # 3. orders -> payment POST /paymentAuth
        res3 = self.synthesizer.evaluate_request("orders", "payment", 80, "POST", "/paymentAuth")
        self.assertEqual(res3["decision"], "ALLOW")

        # 4. catalogue -> catalogue-db (L4 TCP)
        res4 = self.synthesizer.evaluate_request("catalogue", "catalogue-db", 3306)
        self.assertEqual(res4["decision"], "ALLOW")

    def test_unauthorized_lateral_attacks_are_denied(self):
        """Verify unauthorized lateral movement attempts are denied by the policy model."""
        # 1. Attacker at front-end attempting direct payment processing
        res1 = self.synthesizer.evaluate_request("front-end", "payment", 80, "POST", "/paymentAuth")
        self.assertEqual(res1["decision"], "DENY")

        # 2. Attacker at front-end attempting direct shipment dispatch
        res2 = self.synthesizer.evaluate_request("front-end", "shipping", 80, "POST", "/shipping")
        self.assertEqual(res2["decision"], "DENY")

        # 3. Attacker at front-end attempting direct database exfiltration
        res3 = self.synthesizer.evaluate_request("front-end", "orders-db", 27017)
        self.assertEqual(res3["decision"], "DENY")

        res4 = self.synthesizer.evaluate_request("front-end", "catalogue-db", 3306)
        self.assertEqual(res4["decision"], "DENY")

        # 4. Attacker at front-end attempting unallowed HTTP method on catalogue (DELETE)
        res5 = self.synthesizer.evaluate_request("front-end", "catalogue", 80, "DELETE", "/catalogue/101")
        self.assertEqual(res5["decision"], "DENY")


if __name__ == "__main__":
    unittest.main()
