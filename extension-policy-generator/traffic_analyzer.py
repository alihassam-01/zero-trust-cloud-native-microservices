#!/usr/bin/env python3
"""
Traffic Analyzer for Zero Trust Policy Generation
Author: Hassam Ali (ali.hassam1@outlook.com)
Repository: https://github.com/Hassam-01/zero-trust-cloud-native-microservices

Ingests Envoy proxy access logs and distributed tracing spans to build a
canonical directed communication graph G = (V, E) across microservices.
Performs REST URL parameterization and protocol classification.
"""

import re
import json
import argparse
from typing import Dict, List, Any, Optional
from collections import defaultdict


class TrafficAnalyzer:
    """Analyzes telemetry logs and builds directed microservice communication graphs."""

    UUID_REGEX = re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    HEX_ID_REGEX = re.compile(r"/[0-9a-fA-F]{16,}")
    NUMERIC_ID_REGEX = re.compile(r"/\d+(?=(/|$))")

    def __init__(self):
        self.logs: List[Dict[str, Any]] = []
        self.nodes = set()
        # Key: (source_workload, dest_workload, dest_port, protocol)
        self.edge_map = defaultdict(lambda: {
            "source_workload": "",
            "source_principal": "",
            "destination_workload": "",
            "destination_namespace": "sock-shop",
            "destination_port": 0,
            "protocol": "HTTP",
            "operations": defaultdict(set),  # method -> set of paths
            "call_count": 0
        })

    def load_logs(self, file_path: str) -> int:
        """Load logs from JSON array or line-delimited JSON."""
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if content.startswith("["):
                self.logs = json.loads(content)
            else:
                self.logs = [json.loads(line) for line in content.splitlines() if line.strip()]
        return len(self.logs)

    @classmethod
    def normalize_path(cls, path: Optional[str]) -> Optional[str]:
        """
        Normalize parameterized REST API endpoints.
        e.g., /catalogue/3395a43e-2d88-... -> /catalogue/*
              /cart/item/99 -> /cart/item/*
        """
        if not path:
            return None

        # Strip query parameters for policy path matching
        clean_path = path.split("?")[0]

        # Replace UUIDs
        clean_path = cls.UUID_REGEX.sub("*", clean_path)
        # Replace hex hashes
        clean_path = cls.HEX_ID_REGEX.sub("/*", clean_path)
        # Replace numeric IDs
        clean_path = cls.NUMERIC_ID_REGEX.sub("/*", clean_path)

        return clean_path

    def build_communication_graph(self) -> Dict[str, Any]:
        """Construct the directed communication graph G = (V, E)."""
        self.nodes.clear()
        self.edge_map.clear()

        for entry in self.logs:
            src = entry.get("source_workload")
            src_principal = entry.get("source_principal", f"spiffe://cluster.local/ns/sock-shop/sa/{src}")
            dst = entry.get("destination_workload")
            dst_ns = entry.get("destination_namespace", "sock-shop")
            dst_port = int(entry.get("destination_port", 80))
            proto = entry.get("protocol", "HTTP/1.1").upper()
            method = entry.get("method")
            raw_path = entry.get("path")

            if not src or not dst:
                continue

            self.nodes.add(src)
            self.nodes.add(dst)

            key = (src, dst, dst_port, "TCP" if "TCP" in proto else "HTTP")
            edge = self.edge_map[key]
            edge["source_workload"] = src
            edge["source_principal"] = src_principal
            edge["destination_workload"] = dst
            edge["destination_namespace"] = dst_ns
            edge["destination_port"] = dst_port
            edge["protocol"] = "TCP" if "TCP" in proto else "HTTP"
            edge["call_count"] += 1

            if edge["protocol"] == "HTTP" and method:
                norm_path = self.normalize_path(raw_path)
                if norm_path:
                    edge["operations"][method.upper()].add(norm_path)

        # Format output
        edges_output = []
        for edge_data in self.edge_map.values():
            ops_list = []
            for m, paths in edge_data["operations"].items():
                ops_list.append({
                    "method": m,
                    "paths": sorted(list(paths))
                })

            edges_output.append({
                "source": edge_data["source_workload"],
                "source_principal": edge_data["source_principal"],
                "destination": edge_data["destination_workload"],
                "destination_namespace": edge_data["destination_namespace"],
                "destination_port": edge_data["destination_port"],
                "protocol": edge_data["protocol"],
                "operations": ops_list,
                "call_count": edge_data["call_count"]
            })

        graph = {
            "metadata": {
                "total_records_processed": len(self.logs),
                "node_count": len(self.nodes),
                "edge_count": len(edges_output)
            },
            "nodes": sorted(list(self.nodes)),
            "edges": sorted(edges_output, key=lambda x: (x["destination"], x["source"]))
        }
        return graph

    def export_graph(self, output_path: str) -> None:
        """Export the graph as formatted JSON."""
        graph = self.build_communication_graph()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(graph, f, indent=2)

    def print_summary(self) -> None:
        """Print human-readable summary of communication edges."""
        graph = self.build_communication_graph()
        print("=" * 70)
        print("  ZERO TRUST TRAFFIC ANALYSIS SUMMARY")
        print("=" * 70)
        print(f"Total Log Records: {graph['metadata']['total_records_processed']}")
        print(f"Discovered Workload Nodes ({len(graph['nodes'])}): {', '.join(graph['nodes'])}")
        print(f"Discovered Communication Edges: {len(graph['edges'])}")
        print("-" * 70)
        for e in graph["edges"]:
            if e["protocol"] == "HTTP":
                ops_str = "; ".join([f"{op['method']} [{', '.join(op['paths'])}]" for op in e["operations"]])
                print(f" [HTTP] {e['source']:<12} -> {e['destination']:<15} (:{e['destination_port']}) | {ops_str}")
            else:
                print(f" [TCP]  {e['source']:<12} -> {e['destination']:<15} (:{e['destination_port']}) | Raw TCP Socket")
        print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Analyze Envoy telemetry and build zero trust communication graph")
    parser.add_argument("--input-logs", "-i", required=True, help="Path to input Envoy access logs (JSON)")
    parser.add_argument("--output-graph", "-o", default="communication_graph.json", help="Path to output graph JSON")
    parser.add_argument("--summary", "-s", action="store_true", help="Print summary table to stdout")
    args = parser.parse_args()

    analyzer = TrafficAnalyzer()
    count = analyzer.load_logs(args.input_logs)
    print(f"Loaded {count} telemetry records from {args.input_logs}")

    if args.summary:
        analyzer.print_summary()

    analyzer.export_graph(args.output_graph)
    print(f"Communication graph exported to {args.output_graph}")


if __name__ == "__main__":
    main()
