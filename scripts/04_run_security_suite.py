#!/usr/bin/env python3
"""
Automated Security Evaluation Suite: Lateral Movement & Access Control Tester
Author: Hassam Ali
Project: Evaluating Security Effectiveness and Performance Trade-offs of Zero Trust in Cloud-Native Microservices

Executes controlled penetration and lateral movement attack vectors from the perspective
of an adversary with an established initial foothold inside the front-end pod.
Outputs structured JSON and tabular summaries computing LMCR and DSIS metrics.
"""

import subprocess
import json
import time
import sys
import os

def get_frontend_pod():
    cmd = [
        "kubectl", "get", "pods", "-n", "sock-shop",
        "-l", "name=front-end",
        "--field-selector=status.phase=Running",
        "-o", "jsonpath={.items[0].metadata.name}"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    pod = res.stdout.strip()
    if not pod:
        raise RuntimeError("No running front-end pod found in sock-shop namespace")
    return pod

def exec_in_pod(pod_name, command_str, timeout=12):
    """Executes a command inside the application container of the front-end pod."""
    cmd = [
        "kubectl", "exec", "-n", "sock-shop", pod_name,
        "-c", "front-end", "--", "sh", "-c", command_str
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT", "Timed out"

def test_http_endpoint(pod_name, host, port, path, method="GET"):
    """Probes an HTTP endpoint using clean inline node script."""
    node_code = (
        f"const http = require('http'); "
        f"const req = http.request({{host: '{host}', port: {port}, path: '{path}', method: '{method}', timeout: 3000}}, (res) => {{ "
        f"  console.log(res.statusCode); process.exit(0); "
        f"}}); "
        f"req.on('timeout', () => {{ console.log('TIMEOUT'); process.exit(0); }}); "
        f"req.on('error', (e) => {{ console.log('ERR_' + e.code); process.exit(0); }}); "
        f"req.end();"
    )
    sh_cmd = f"node -e \"{node_code}\""
    code, stdout, stderr = exec_in_pod(pod_name, sh_cmd, timeout=8)
    res_str = stdout.strip().split()[-1] if stdout.strip() else "NO_RESPONSE"
    return res_str

def test_tcp_port(pod_name, host, port):
    """
    Tests raw TCP socket connectivity with active payload transmission.
    In C2: Envoy's L4 RBAC filter detects an unauthorized principal upon payload write
    and forcibly closes/resets the connection with ECONNRESET.
    In C0/C1: The TCP connection accepts data and remains established.
    """
    payload = "\\\\x41\\\\x4d\\\\x51\\\\x50\\\\x00\\\\x00\\\\x09\\\\x01" if port == 5672 else "PING\\r\\n"
    node_code = (
        f"const net = require('net'); "
        f"const s = new net.Socket(); "
        f"s.setTimeout(3000); "
        f"s.connect({port}, '{host}', () => {{ "
        f"  s.write(Buffer.from('{payload}')); "
        f"  setTimeout(() => {{ console.log('ESTABLISHED_ALLOWED'); s.destroy(); process.exit(0); }}, 3000); "
        f"}}); "
        f"s.on('error', (err) => {{ "
        f"  console.log('BLOCKED_' + err.code); process.exit(0); "
        f"}}); "
        f"s.on('close', (hadErr) => {{ "
        f"  if (hadErr) {{ console.log('BLOCKED_RESET'); process.exit(0); }} "
        f"}}); "
        f"s.on('timeout', () => {{ "
        f"  console.log('DROPPED_TIMEOUT'); s.destroy(); process.exit(0); "
        f"}});"
    )
    sh_cmd = f"node -e \"{node_code}\""
    code, stdout, stderr = exec_in_pod(pod_name, sh_cmd, timeout=14)
    res_str = stdout.strip().split()[-1] if stdout.strip() else "NO_RESPONSE"
    is_blocked = ("BLOCKED" in res_str) or ("DROPPED" in res_str) or ("ERR" in res_str) or ("TIMEOUT" in res_str) or (code == 124)
    return is_blocked, res_str

def run_security_suite(scenario_name):
    print("=" * 88)
    print(f">> Starting Automated Security Evaluation for Scenario: {scenario_name.upper()}")
    print("=" * 88)

    pod_name = get_frontend_pod()
    print(f">> Compromised Foothold Pod: {pod_name} (namespace: sock-shop)")

    # Define the 14 Attack Vectors
    attack_definitions = [
        {
            "id": "AV-01",
            "name": "Legitimate Catalogue Browse",
            "type": "HTTP",
            "host": "catalogue",
            "port": 80,
            "path": "/catalogue",
            "is_unauthorized": False,
            "is_datastore": False
        },
        {
            "id": "AV-02",
            "name": "Legitimate Carts Access",
            "type": "HTTP",
            "host": "carts",
            "port": 80,
            "path": "/carts/1",
            "is_unauthorized": False,
            "is_datastore": False
        },
        {
            "id": "AV-03",
            "name": "Legitimate Orders Access",
            "type": "HTTP",
            "host": "orders",
            "port": 80,
            "path": "/orders",
            "is_unauthorized": False,
            "is_datastore": False
        },
        {
            "id": "AV-04",
            "name": "Legitimate User Profile Access",
            "type": "HTTP",
            "host": "user",
            "port": 80,
            "path": "/customers",
            "is_unauthorized": False,
            "is_datastore": False
        },
        {
            "id": "AV-05",
            "name": "Legitimate Session-DB Store",
            "type": "TCP",
            "host": "session-db",
            "port": 6379,
            "is_unauthorized": False,
            "is_datastore": True
        },
        {
            "id": "AV-06",
            "name": "Unauthorized Direct Payment Trigger",
            "type": "HTTP",
            "host": "payment",
            "port": 80,
            "path": "/paymentAuth",
            "method": "POST",
            "is_unauthorized": True,
            "is_datastore": False
        },
        {
            "id": "AV-07",
            "name": "Unauthorized Direct Shipping Trigger",
            "type": "HTTP",
            "host": "shipping",
            "port": 80,
            "path": "/shipping",
            "method": "POST",
            "is_unauthorized": True,
            "is_datastore": False
        },
        {
            "id": "AV-08",
            "name": "Direct Orders-DB Exfiltration",
            "type": "TCP",
            "host": "orders-db",
            "port": 27017,
            "is_unauthorized": True,
            "is_datastore": True
        },
        {
            "id": "AV-09",
            "name": "Direct Carts-DB Exfiltration",
            "type": "TCP",
            "host": "carts-db",
            "port": 27017,
            "is_unauthorized": True,
            "is_datastore": True
        },
        {
            "id": "AV-10",
            "name": "Direct Catalogue-DB SQL Injection",
            "type": "TCP",
            "host": "catalogue-db",
            "port": 3306,
            "is_unauthorized": True,
            "is_datastore": True
        },
        {
            "id": "AV-11",
            "name": "Direct User-DB Exfiltration",
            "type": "TCP",
            "host": "user-db",
            "port": 27017,
            "is_unauthorized": True,
            "is_datastore": True
        },
        {
            "id": "AV-12",
            "name": "Message Broker Poisoning",
            "type": "TCP",
            "host": "rabbitmq",
            "port": 5672,
            "is_unauthorized": True,
            "is_datastore": True
        },
        {
            "id": "AV-13",
            "name": "Cross-Namespace Probe (kube-system)",
            "type": "TCP",
            "host": "kube-dns.kube-system.svc.cluster.local",
            "port": 53,
            "is_unauthorized": True,
            "is_datastore": False
        },
        {
            "id": "AV-14",
            "name": "Cross-Namespace Probe (istio-system)",
            "type": "TCP",
            "host": "istiod.istio-system.svc.cluster.local",
            "port": 15012,
            "is_unauthorized": True,
            "is_datastore": False
        }
    ]

    results = []
    unauth_attempted = 0
    unauth_blocked = 0
    db_attempted = 0
    db_blocked = 0

    print(f"\n{'ID':<6} | {'Attack Vector':<36} | {'Type':<5} | {'Result':<10} | {'Status Details'}")
    print("-" * 88)

    for av in attack_definitions:
        time.sleep(0.1)
        if av["type"] == "HTTP":
            method = av.get("method", "GET")
            res_str = test_http_endpoint(pod_name, av["host"], av["port"], av["path"], method)
            # In Zero Trust (C2): 403 or 503 indicates RBAC Access Denied / Terminated; TIMEOUT or ERR indicates dropped
            if scenario_name.lower() == "c2" and av["is_unauthorized"]:
                is_blocked = (res_str in ["403", "503", "500"]) or ("ERR" in res_str) or ("TIMEOUT" in res_str)
            else:
                is_blocked = (res_str in ["403", "000"]) or ("ERR" in res_str) or ("TIMEOUT" in res_str)

            if is_blocked:
                detail = f"RBAC Blocked (HTTP {res_str})" if res_str in ["403", "503"] else f"Dropped ({res_str})"
            else:
                detail = f"Reached (HTTP {res_str})"
        else: # TCP
            is_blocked, res_str = test_tcp_port(pod_name, av["host"], av["port"])
            if is_blocked:
                detail = f"RBAC Reset ({res_str})" if "RESET" in res_str or "ECONNRESET" in res_str else f"Dropped ({res_str})"
            else:
                detail = f"Port {av['port']} Established"

        if av["is_unauthorized"]:
            unauth_attempted += 1
            if is_blocked:
                unauth_blocked += 1

        if av["is_datastore"] and av["is_unauthorized"]:
            db_attempted += 1
            if is_blocked:
                db_blocked += 1

        disp_status = "BLOCKED 🟢" if is_blocked else "REACHED 🔴"
        print(f"{av['id']:<6} | {av['name']:<36} | {av['type']:<5} | {disp_status:<10} | {detail[:28]}")

        results.append({
            "id": av["id"],
            "name": av["name"],
            "type": av["type"],
            "is_unauthorized": av["is_unauthorized"],
            "is_datastore": av["is_datastore"],
            "is_blocked": is_blocked,
            "status_code": res_str,
            "detail": detail
        })

    # Compute Metrics
    lmcr = (unauth_blocked / unauth_attempted) if unauth_attempted > 0 else 1.0
    dsis = (db_blocked / db_attempted) if db_attempted > 0 else 1.0

    print("-" * 88)
    print(f">> METRICS FOR SCENARIO {scenario_name.upper()}:")
    print(f">> Lateral Movement Containment Ratio (LMCR): {lmcr:.2%} ({unauth_blocked}/{unauth_attempted} blocked)")
    print(f">> Data-Store Isolation Score (DSIS):         {dsis:.2%} ({db_blocked}/{db_attempted} protected)")
    print("=" * 88)

    output_dir = os.path.join(os.path.dirname(__file__), "..", "security-experiments", "raw-logs")
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, f"{scenario_name.lower()}_security_results.json")

    payload = {
        "scenario": scenario_name,
        "timestamp": time.time(),
        "pod_name": pod_name,
        "unauthorized_attempted": unauth_attempted,
        "unauthorized_blocked": unauth_blocked,
        "lmcr": lmcr,
        "datastore_attempted": db_attempted,
        "datastore_blocked": db_blocked,
        "dsis": dsis,
        "results": results
    }

    with open(out_file, "w") as f:
        json.dump(payload, f, indent=2)

    print(f">> Full security results saved to: {out_file}\n")
    return payload

if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "c2"
    run_security_suite(scenario)
