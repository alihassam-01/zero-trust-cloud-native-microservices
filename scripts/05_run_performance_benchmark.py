#!/usr/bin/env python3
"""
Automated Performance Benchmark Suite: Latency, Throughput & Resource Overhead
Author: Hassam Ali
Project: Evaluating Security Effectiveness and Performance Trade-offs of Zero Trust in Cloud-Native Microservices

Benchmarks microservice application performance across security scenarios (C0, C1, C2)
under variable concurrency levels (N ∈ [1, 5, 10, 25, 50]).
Measures request latency percentiles (p50, p90, p95, p99), throughput (RPS), error rates,
and captures container-level CPU/memory utilization via Kubernetes Metrics API.
"""

import urllib.request
import urllib.error
import concurrent.futures
import subprocess
import statistics
import time
import json
import csv
import sys
import os

def get_node_ip():
    try:
        res = subprocess.run(["minikube", "ip"], capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception:
        return "127.0.0.1"

def get_pod_resource_metrics():
    """Captures CPU (m) and Memory (MiB) utilization for app vs istio-proxy containers."""
    try:
        cmd = ["kubectl", "top", "pod", "-n", "sock-shop", "--containers", "--no-headers"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = res.stdout.strip().splitlines()
        
        app_cpu_total = 0
        proxy_cpu_total = 0
        app_mem_total = 0
        proxy_mem_total = 0

        for l in lines:
            parts = l.split()
            if len(parts) >= 4:
                cname = parts[1]
                cpu_str = parts[2].replace("m", "")
                mem_str = parts[3].replace("Mi", "").replace("Gi", "000")
                cpu_val = int(cpu_str) if cpu_str.isdigit() else 0
                mem_val = int(mem_str) if mem_str.isdigit() else 0

                if cname == "istio-proxy":
                    proxy_cpu_total += cpu_val
                    proxy_mem_total += mem_val
                else:
                    app_cpu_total += cpu_val
                    app_mem_total += mem_val

        return {
            "app_cpu_millicores": app_cpu_total,
            "proxy_cpu_millicores": proxy_cpu_total,
            "total_cpu_millicores": app_cpu_total + proxy_cpu_total,
            "app_memory_mib": app_mem_total,
            "proxy_memory_mib": proxy_mem_total,
            "total_memory_mib": app_mem_total + proxy_mem_total
        }
    except Exception as e:
        return {
            "app_cpu_millicores": 0, "proxy_cpu_millicores": 0, "total_cpu_millicores": 0,
            "app_memory_mib": 0, "proxy_memory_mib": 0, "total_memory_mib": 0, "error": str(e)
        }

def single_request(url, timeout=5):
    """Sends a single HTTP GET request and returns latency in milliseconds."""
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ZTA-Benchmark/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            _ = resp.read()
            lat = (time.perf_counter() - t0) * 1000.0
            return True, resp.status, lat
    except urllib.error.HTTPError as e:
        lat = (time.perf_counter() - t0) * 1000.0
        return False, e.code, lat
    except Exception as e:
        lat = (time.perf_counter() - t0) * 1000.0
        return False, 0, lat

def benchmark_concurrency(target_url, concurrency, total_requests=100):
    """Executes a concurrent load test and computes statistical latency distribution."""
    print(f">> Benchmarking concurrency={concurrency} (total_requests={total_requests})...")
    latencies = []
    successes = 0
    failures = 0

    t_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(single_request, target_url) for _ in range(total_requests)]
        for f in concurrent.futures.as_completed(futures):
            ok, status, lat = f.result()
            latencies.append(lat)
            if ok and status == 200:
                successes += 1
            else:
                failures += 1
    t_duration = time.perf_counter() - t_start

    latencies.sort()
    n = len(latencies)
    p50 = latencies[int(0.50 * n)]
    p90 = latencies[int(0.90 * n)]
    p95 = latencies[int(0.95 * n)]
    p99 = latencies[int(0.99 * n)] if n >= 100 else latencies[-1]
    mean_lat = statistics.mean(latencies)
    std_lat = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
    rps = total_requests / t_duration if t_duration > 0 else 0

    return {
        "concurrency": concurrency,
        "total_requests": total_requests,
        "successes": successes,
        "failures": failures,
        "error_rate_pct": (failures / total_requests) * 100.0,
        "duration_sec": round(t_duration, 3),
        "throughput_rps": round(rps, 2),
        "latency_min_ms": round(latencies[0], 2),
        "latency_mean_ms": round(mean_lat, 2),
        "latency_std_ms": round(std_lat, 2),
        "latency_p50_ms": round(p50, 2),
        "latency_p90_ms": round(p90, 2),
        "latency_p95_ms": round(p95, 2),
        "latency_p99_ms": round(p99, 2),
        "latency_max_ms": round(latencies[-1], 2)
    }

def run_scenario_benchmark(scenario_name, target_url=None):
    node_ip = get_node_ip()
    if not target_url:
        target_url = f"http://{node_ip}:30001/catalogue"

    print("=" * 88)
    print(f">> Starting Performance Benchmark for Scenario: {scenario_name.upper()}")
    print(f">> Target Endpoint: {target_url}")
    print("=" * 88)

    # Warmup
    print(">> Warming up endpoint (10 requests)...")
    for _ in range(10):
        single_request(target_url, timeout=3)
        time.sleep(0.05)

    concurrency_levels = [1, 5, 10, 25, 50]
    suite_results = []

    print(f"\n{'Concurrency':<12} | {'RPS':<8} | {'p50 (ms)':<9} | {'p90 (ms)':<9} | {'p95 (ms)':<9} | {'p99 (ms)':<9} | {'Error %'}")
    print("-" * 88)

    for c in concurrency_levels:
        req_count = 100 if c <= 25 else 150
        res = benchmark_concurrency(target_url, c, total_requests=req_count)
        print(f"{c:<12} | {res['throughput_rps']:<8.1f} | {res['latency_p50_ms']:<9.2f} | {res['latency_p90_ms']:<9.2f} | {res['latency_p95_ms']:<9.2f} | {res['latency_p99_ms']:<9.2f} | {res['error_rate_pct']:<5.1f}%")
        suite_results.append(res)
        time.sleep(1)

    print("-" * 88)
    print(">> Sampling cluster container resource footprint...")
    resources = get_pod_resource_metrics()
    print(f">> Total App CPU:    {resources['app_cpu_millicores']}m  | App Memory:    {resources['app_memory_mib']} MiB")
    print(f">> Total Proxy CPU:  {resources['proxy_cpu_millicores']}m  | Proxy Memory:  {resources['proxy_memory_mib']} MiB")
    print(f">> Combined Total:   {resources['total_cpu_millicores']}m  | Combined Mem:  {resources['total_memory_mib']} MiB")
    print("=" * 88)

    # Save scenario JSON
    data_dir = os.path.join(os.path.dirname(__file__), "..", "performance-experiments", "benchmark-data")
    os.makedirs(data_dir, exist_ok=True)
    out_json = os.path.join(data_dir, f"{scenario_name.lower()}_benchmark.json")

    payload = {
        "scenario": scenario_name.upper(),
        "timestamp": time.time(),
        "target_url": target_url,
        "resource_footprint": resources,
        "concurrency_benchmarks": suite_results
    }

    with open(out_json, "w") as f:
        json.dump(payload, f, indent=2)

    # Append to CSV
    csv_file = os.path.join(data_dir, "consolidated_benchmarks.csv")
    csv_exists = os.path.exists(csv_file)

    with open(csv_file, "a", newline="") as f:
        writer = csv.writer(f)
        if not csv_exists:
            writer.writerow([
                "scenario", "concurrency", "throughput_rps", "p50_ms", "p90_ms",
                "p95_ms", "p99_ms", "mean_ms", "error_rate_pct",
                "proxy_cpu_m", "proxy_mem_mib", "app_cpu_m", "app_mem_mib"
            ])
        for b in suite_results:
            writer.writerow([
                scenario_name.upper(), b["concurrency"], b["throughput_rps"],
                b["latency_p50_ms"], b["latency_p90_ms"], b["latency_p95_ms"],
                b["latency_p99_ms"], b["latency_mean_ms"], b["error_rate_pct"],
                resources.get("proxy_cpu_millicores", 0), resources.get("proxy_memory_mib", 0),
                resources.get("app_cpu_millicores", 0), resources.get("app_memory_mib", 0)
            ])

    print(f">> Benchmark data persisted to:\n   - {out_json}\n   - {csv_file}\n")
    return payload

if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "c0"
    run_scenario_benchmark(scenario)
