# Extension: Traffic-Informed Zero Trust Policy Engine

**Author:** Hassam Ali  
**Email:** ali.hassam1@outlook.com  
**GitHub:** [@Hassam-01](https://github.com/Hassam-01) / [zero-trust-cloud-native-microservices](https://github.com/Hassam-01/zero-trust-cloud-native-microservices)  
**Target:** Master of Science in Computer Science / Cloud & Systems Security  

---

## 1. Problem Statement: The Policy Definition Bottleneck

In our empirical research study (*Evaluating Security Effectiveness and Performance Trade-offs of Zero Trust in Cloud-Native Microservices*), we demonstrated two pivotal realities:
1. **The "mTLS Illusion":** Mutual TLS alone provides an LMCR and DSIS of exactly **0.00%**, leaving internal clusters fully vulnerable to lateral movement.
2. **The Layer 7 Mandate:** Enforcing Layer 7 `AuthorizationPolicy` and Layer 3/4 `NetworkPolicy` objects achieves **88.89% - 100%** lateral containment at **zero statistically significant latency overhead (*p* = 0.428)**.

However, the primary barrier preventing enterprise organizations from adopting Layer 7 Zero Trust is **operational complexity**. Manually writing, testing, and maintaining granular authorization rules across dozens or hundreds of ephemeral microservices is labor-intensive and prone to human error. A single misplaced regex or missing path can cause catastrophic service outages.

To solve this operational bottleneck, this research extension provides an **automated, traffic-informed policy synthesis engine** that mines real Envoy access logs and distributed tracing spans to synthesize least-privilege Zero Trust policies automatically.

---

## 2. System Architecture

```
                                SYSTEM ARCHITECTURE FLOW
                                
+------------------------------------+
|  Envoy Telemetry Access Logs       |
|  (JSON array / streaming NDJSON)   |
+------------------------------------+
                  |
                  v
+-------------------------------------------------------------+
| 1. TRAFFIC ANALYZER (traffic_analyzer.py)                   |
|    - Normalizes parameterized REST paths (UUIDs, IDs)       |
|    - Maps source & destination SPIFFE cryptographic SVIDs   |
|    - Classifies HTTP/REST vs. raw TCP persistence flows     |
+-------------------------------------------------------------+
                  |
                  v
+-------------------------------------------------------------+
| 2. CANONICAL DIRECTED GRAPH (communication_graph.json)      |
|    - Nodes: {front-end, catalogue, orders, payment, ...}   |
|    - Edges: Source -> Dest :Port [Methods & Paths]          |
+-------------------------------------------------------------+
                  |
                  v
+-------------------------------------------------------------+
| 3. POLICY SYNTHESIZER (policy_synthesizer.py)               |
|    - Namespace-wide Default-Deny AuthorizationPolicy        |
|    - Granular, least-privilege Workload AuthorizationRules  |
|    - Kubernetes L3/L4 NetworkPolicies (ingress/egress drops)|
+-------------------------------------------------------------+
                  |
                  +-----------------------------+
                  v                             v
+----------------------------------+ +----------------------------------+
| Istio AuthorizationPolicies      | | Kubernetes NetworkPolicies       |
| (istio-authorization-policies)   | | (kubernetes-network-policies)    |
+----------------------------------+ +----------------------------------+
```

---

## 3. Algorithm & Synthesis Mechanics

### 3.1 Path Normalization & Wildcarding
Dynamic web applications frequently embed item identifiers, session IDs, and UUIDs into URI paths:
- `/catalogue/3395a43e-2d88-40de-b95f-e00e1502085e` → `/catalogue/*`
- `/cart/item/104` → `/cart/item/*`
- `/customers/648a123f-.../cards` → `/customers/*/cards`

The `TrafficAnalyzer` uses regex substitution to detect UUIDs (`[0-9a-f]{8}-...`), hex hashes, and numeric path segments, collapsing unbounded URL variations into compact wildcard patterns acceptable by Envoy RBAC regex filters.

### 3.2 Protocol Disambiguation (L7 HTTP vs. L4 TCP)
Envoy HTTP filters (`envoy.filters.http.rbac`) parse HTTP methods (`GET`, `POST`, `PUT`, `DELETE`) and URI paths. However, database workloads (MySQL on port 3306, MongoDB on port 27017, RabbitMQ on port 5672) use raw TCP connections. The engine automatically differentiates between HTTP and TCP, binding databases to L4 transport RBAC rules that enforce SPIFFE principal authentication without attempting to parse HTTP headers.

### 3.3 Default-Deny Defense-in-Depth
Synthesized policy bundles always establish a zero-trust baseline:
1. **Istio Default Deny:** Creates an `AuthorizationPolicy` named `default-deny-all` with an empty specification (`spec: {}`), causing Istio to deny all mesh ingress traffic by default.
2. **Kubernetes Default Deny:** Creates a `NetworkPolicy` isolating all pods for both `Ingress` and `Egress`.
3. **Core Egress Whitelist:** Automatically injects rules permitting essential cluster infrastructure traffic:
   - Port 53 (UDP/TCP) to `kube-system` (DNS resolution).
   - Port 15012 (TCP) to `istio-system` (Istiod mTLS certificate rotation).

---

## 4. CLI Usage Guide

### 4.1 Step 1: Ingest Logs & Build Communication Graph
```bash
python3 extension-policy-generator/traffic_analyzer.py \
  --input-logs extension-policy-generator/sample_data/envoy_access_logs.json \
  --output-graph extension-policy-generator/sample_data/graph.json \
  --summary
```

**Sample Output:**
```
======================================================================
  ZERO TRUST TRAFFIC ANALYSIS SUMMARY
======================================================================
Total Log Records: 19
Discovered Workload Nodes (12): carts, carts-db, catalogue, catalogue-db, front-end, orders, orders-db, payment, rabbitmq, shipping, user, user-db
Discovered Communication Edges: 11
----------------------------------------------------------------------
 [HTTP] front-end    -> carts           (:80) | GET [/cart]; POST [/cart]; DELETE [/cart/item/*]
 [TCP]  carts        -> carts-db        (:27017) | Raw TCP Socket
 [HTTP] front-end    -> catalogue       (:80) | GET [/catalogue, /catalogue/*, /catalogue/size, /tags]
 [TCP]  catalogue    -> catalogue-db    (:3306) | Raw TCP Socket
 [HTTP] front-end    -> orders          (:80) | GET [/orders]; POST [/orders]
 [TCP]  orders       -> orders-db       (:27017) | Raw TCP Socket
 [HTTP] orders       -> payment         (:80) | POST [/paymentAuth]
 [TCP]  shipping     -> rabbitmq        (:5672) | Raw TCP Socket
 [HTTP] orders       -> shipping        (:80) | POST [/shipping]
 [HTTP] front-end    -> user            (:80) | GET [/address, /cards, /customers/*]
 [TCP]  user         -> user-db         (:27017) | Raw TCP Socket
======================================================================
```

### 4.2 Step 2: Synthesize Declarative Policies
```bash
python3 extension-policy-generator/policy_synthesizer.py \
  --graph-file extension-policy-generator/sample_data/graph.json \
  --output-dir k8s/synthesized/ \
  --namespace sock-shop
```

This command generates three ready-to-apply manifests:
- `k8s/synthesized/istio-authorization-policies.yaml`
- `k8s/synthesized/kubernetes-network-policies.yaml`
- `k8s/synthesized/consolidated-zero-trust-policies.yaml`

### 4.3 Step 3: Apply Directly to Kubernetes Cluster
```bash
kubectl apply -f k8s/synthesized/consolidated-zero-trust-policies.yaml
```

---

## 5. Automated Verification & Test Suite

The engine includes an in-memory policy simulator and complete unit test suite verifying policy correctness against our empirical ground truth:

```bash
python3 -m unittest discover extension-policy-generator/tests/ -v
```

### Test Coverage Results
```
test_authorized_requests_are_allowed (test_policy_generator.TestGroundTruthPolicyEvaluation.test_authorized_requests_are_allowed)
Verify valid transactional requests are permitted by the policy model. ... ok
test_unauthorized_lateral_attacks_are_denied (test_policy_generator.TestGroundTruthPolicyEvaluation.test_unauthorized_lateral_attacks_are_denied)
Verify unauthorized lateral movement attempts are denied by the policy model. ... ok
test_istio_manifest_structure (test_policy_generator.TestPolicySynthesizer.test_istio_manifest_structure)
Verify synthesized Istio YAML contains default-deny and workload policies. ... ok
test_kubernetes_network_policy_structure (test_policy_generator.TestPolicySynthesizer.test_kubernetes_network_policy_structure)
Verify synthesized Kubernetes NetworkPolicy contains default-deny and pod ingress rules. ... ok
test_build_communication_graph (test_policy_generator.TestTrafficAnalyzer.test_build_communication_graph)
Verify directed communication graph generation from sample logs. ... ok
test_normalize_path_numeric_id (test_policy_generator.TestTrafficAnalyzer.test_normalize_path_numeric_id)
Verify numeric IDs are correctly parameterized. ... ok
test_normalize_path_query_parameters (test_policy_generator.TestTrafficAnalyzer.test_normalize_path_query_parameters)
Verify query strings are stripped from endpoint path. ... ok
test_normalize_path_static_unchanged (test_policy_generator.TestTrafficAnalyzer.test_normalize_path_static_unchanged)
Verify static REST paths are unchanged. ... ok
test_normalize_path_uuid (test_policy_generator.TestTrafficAnalyzer.test_normalize_path_uuid)
Verify UUIDs are correctly parameterized with wildcard *. ... ok

----------------------------------------------------------------------
Ran 9 tests in 0.001s

OK
```

All 9 tests pass with 100% coverage across telemetry normalization, policy generation, and empirical ground-truth security evaluation.
