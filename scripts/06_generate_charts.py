#!/usr/bin/env python3
"""
Publication-Quality Figures Generator for Zero Trust Research Study
Author: Hassam Ali
Project: Evaluating Security Effectiveness and Performance Trade-offs of Zero Trust in Cloud-Native Microservices

Generates four high-resolution publication figures from empirical security and performance data:
1. latency_comparison_p50_p95_p99.png
2. throughput_vs_concurrency.png
3. sidecar_resource_overhead.png
4. attack_containment_heatmap.png
"""

import matplotlib.pyplot as plt
import numpy as np
import json
import os

# Set publication style
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['figure.dpi'] = 300

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT_DIR, "performance-experiments", "benchmark-data")
SEC_DIR = os.path.join(ROOT_DIR, "security-experiments", "raw-logs")
FIG_DIR = os.path.join(ROOT_DIR, "performance-experiments", "figures")
os.makedirs(FIG_DIR, exist_ok=True)

def load_perf_data():
    with open(os.path.join(DATA_DIR, "c0_benchmark.json")) as f:
        c0 = json.load(f)
    with open(os.path.join(DATA_DIR, "c1_benchmark.json")) as f:
        c1 = json.load(f)
    with open(os.path.join(DATA_DIR, "c2_benchmark.json")) as f:
        c2 = json.load(f)
    return c0, c1, c2

def load_sec_data():
    with open(os.path.join(SEC_DIR, "c0_security_results.json")) as f:
        c0_s = json.load(f)
    with open(os.path.join(SEC_DIR, "c1_security_results.json")) as f:
        c1_s = json.load(f)
    with open(os.path.join(SEC_DIR, "c2_security_results.json")) as f:
        c2_s = json.load(f)
    return c0_s, c1_s, c2_s

def plot_latency_comparison(c0, c1, c2):
    concurrencies = [b["concurrency"] for b in c0["concurrency_benchmarks"]]
    x = np.arange(len(concurrencies))
    width = 0.25

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

    # Left plot: Median Latency (p50)
    p50_c0 = [b["latency_p50_ms"] for b in c0["concurrency_benchmarks"]]
    p50_c1 = [b["latency_p50_ms"] for b in c1["concurrency_benchmarks"]]
    p50_c2 = [b["latency_p50_ms"] for b in c2["concurrency_benchmarks"]]

    ax1.bar(x - width, p50_c0, width, label='C0: Baseline Perimeter', color='#64748b', edgecolor='black', alpha=0.9)
    ax1.bar(x, p50_c1, width, label='C1: STRICT mTLS', color='#0284c7', edgecolor='black', alpha=0.9)
    ax1.bar(x + width, p50_c2, width, label='C2: Layered Zero Trust', color='#10b981', edgecolor='black', alpha=0.9)

    ax1.set_xlabel('Concurrency (Concurrent Virtual Users)', fontsize=11, fontweight='bold')
    ax1.set_ylabel('Median Latency p50 (ms)', fontsize=11, fontweight='bold')
    ax1.set_title('Median Latency (p50) vs Concurrency', fontsize=12, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(concurrencies)
    ax1.legend(frameon=True)
    ax1.grid(True, linestyle='--', alpha=0.5)

    # Right plot: Tail Latency (p99)
    p99_c0 = [b["latency_p99_ms"] for b in c0["concurrency_benchmarks"]]
    p99_c1 = [b["latency_p99_ms"] for b in c1["concurrency_benchmarks"]]
    p99_c2 = [b["latency_p99_ms"] for b in c2["concurrency_benchmarks"]]

    ax2.bar(x - width, p99_c0, width, label='C0: Baseline Perimeter', color='#64748b', edgecolor='black', alpha=0.9)
    ax2.bar(x, p99_c1, width, label='C1: STRICT mTLS', color='#0284c7', edgecolor='black', alpha=0.9)
    ax2.bar(x + width, p99_c2, width, label='C2: Layered Zero Trust', color='#10b981', edgecolor='black', alpha=0.9)

    ax2.set_xlabel('Concurrency (Concurrent Virtual Users)', fontsize=11, fontweight='bold')
    ax2.set_ylabel('Tail Latency p99 (ms)', fontsize=11, fontweight='bold')
    ax2.set_title('Tail Latency (p99) vs Concurrency', fontsize=12, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(concurrencies)
    ax2.legend(frameon=True)
    ax2.grid(True, linestyle='--', alpha=0.5)

    plt.tight_layout()
    out_path = os.path.join(FIG_DIR, "latency_comparison_p50_p95_p99.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f">> Saved: {out_path}")

def plot_throughput(c0, c1, c2):
    concurrencies = [b["concurrency"] for b in c0["concurrency_benchmarks"]]
    rps_c0 = [b["throughput_rps"] for b in c0["concurrency_benchmarks"]]
    rps_c1 = [b["throughput_rps"] for b in c1["concurrency_benchmarks"]]
    rps_c2 = [b["throughput_rps"] for b in c2["concurrency_benchmarks"]]

    plt.figure(figsize=(8.5, 5.5))
    plt.plot(concurrencies, rps_c0, marker='o', linewidth=2.5, markersize=8, label='C0: Baseline Perimeter', color='#64748b')
    plt.plot(concurrencies, rps_c1, marker='s', linewidth=2.5, markersize=8, label='C1: STRICT mTLS', color='#0284c7')
    plt.plot(concurrencies, rps_c2, marker='^', linewidth=2.5, markersize=8, label='C2: Layered Zero Trust', color='#10b981')

    plt.title('Throughput Scaling (RPS) across Concurrency Levels', fontsize=13, fontweight='bold')
    plt.xlabel('Concurrency (Virtual Users)', fontsize=11, fontweight='bold')
    plt.ylabel('Sustained Throughput (Requests / Sec)', fontsize=11, fontweight='bold')
    plt.xticks(concurrencies)
    plt.legend(frameon=True, fontsize=10)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()

    out_path = os.path.join(FIG_DIR, "throughput_vs_concurrency.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f">> Saved: {out_path}")

def plot_resource_overhead(c0, c1, c2):
    scenarios = ['C0: Baseline', 'C1: STRICT mTLS', 'C2: Layered ZTA']
    app_mem = [
        c0["resource_footprint"]["app_memory_mib"],
        c1["resource_footprint"]["app_memory_mib"],
        c2["resource_footprint"]["app_memory_mib"]
    ]
    proxy_mem = [
        c0["resource_footprint"]["proxy_memory_mib"],
        c1["resource_footprint"]["proxy_memory_mib"],
        c2["resource_footprint"]["proxy_memory_mib"]
    ]

    app_cpu = [
        c0["resource_footprint"]["app_cpu_millicores"],
        c1["resource_footprint"]["app_cpu_millicores"],
        c2["resource_footprint"]["app_cpu_millicores"]
    ]
    proxy_cpu = [
        c0["resource_footprint"]["proxy_cpu_millicores"],
        c1["resource_footprint"]["proxy_cpu_millicores"],
        c2["resource_footprint"]["proxy_cpu_millicores"]
    ]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    # Memory Stacked Bar
    ax1.bar(scenarios, app_mem, label='Application Containers', color='#3b82f6', width=0.5, edgecolor='black')
    ax1.bar(scenarios, proxy_mem, bottom=app_mem, label='Envoy Sidecar Proxies', color='#f59e0b', width=0.5, edgecolor='black')
    ax1.set_ylabel('Total Memory Footprint (MiB)', fontsize=11, fontweight='bold')
    ax1.set_title('Cluster Memory Utilization Breakdown', fontsize=12, fontweight='bold')
    ax1.legend(frameon=True)
    ax1.grid(True, linestyle='--', alpha=0.5)

    # CPU Stacked Bar
    ax2.bar(scenarios, app_cpu, label='Application Containers', color='#3b82f6', width=0.5, edgecolor='black')
    ax2.bar(scenarios, proxy_cpu, bottom=app_cpu, label='Envoy Sidecar Proxies', color='#f59e0b', width=0.5, edgecolor='black')
    ax2.set_ylabel('Total Compute (Millicores)', fontsize=11, fontweight='bold')
    ax2.set_title('Cluster CPU Compute Breakdown', fontsize=12, fontweight='bold')
    ax2.legend(frameon=True)
    ax2.grid(True, linestyle='--', alpha=0.5)

    plt.tight_layout()
    out_path = os.path.join(FIG_DIR, "sidecar_resource_overhead.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f">> Saved: {out_path}")

def plot_attack_containment_heatmap(c0_s, c1_s, c2_s):
    vectors = [r["name"] for r in c0_s["results"]]
    
    # 0 for blocked (green), 1 for reached (red)
    matrix = []
    for r0, r1, r2 in zip(c0_s["results"], c1_s["results"], c2_s["results"]):
        # 1 = reached (vulnerable), 0 = blocked (secure)
        val0 = 0 if r0["is_blocked"] else 1
        val1 = 0 if r1["is_blocked"] else 1
        val2 = 0 if r2["is_blocked"] else 1
        matrix.append([val0, val1, val2])

    matrix = np.array(matrix)

    fig, ax = plt.subplots(figsize=(10, 8))
    # Custom colormap: 0 = Dark Green (Contained), 1 = Crimson Red (Compromised)
    cmap = plt.cm.colors.ListedColormap(['#10b981', '#ef4444'])

    cax = ax.matshow(matrix, cmap=cmap, aspect='auto')

    ax.set_xticks([0, 1, 2])
    ax.set_xticklabels(['C0: Baseline', 'C1: STRICT mTLS', 'C2: Layered ZTA'], fontsize=11, fontweight='bold')
    ax.set_yticks(range(len(vectors)))
    ax.set_yticklabels(vectors, fontsize=10)

    for i in range(len(vectors)):
        for j in range(3):
            text = "BLOCKED" if matrix[i, j] == 0 else "REACHED"
            color = "white"
            ax.text(j, i, text, ha='center', va='center', color=color, fontweight='bold', fontsize=9)

    plt.title('Attack Surface Containment Matrix (14 Attack Vectors)', fontsize=13, fontweight='bold', pad=20)
    plt.tight_layout()

    out_path = os.path.join(FIG_DIR, "attack_containment_heatmap.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f">> Saved: {out_path}")

def main():
    print(">> Generating publication-quality figures...")
    c0, c1, c2 = load_perf_data()
    c0_s, c1_s, c2_s = load_sec_data()

    plot_latency_comparison(c0, c1, c2)
    plot_throughput(c0, c1, c2)
    plot_resource_overhead(c0, c1, c2)
    plot_attack_containment_heatmap(c0_s, c1_s, c2_s)
    print(">> All 4 publication figures generated successfully in: " + FIG_DIR)

if __name__ == "__main__":
    main()
