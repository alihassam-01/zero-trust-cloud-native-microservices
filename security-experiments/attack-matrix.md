# Security Experiments: Attack Matrix & Lateral Movement Evaluation

**Author:** Hassam Ali  
**Project:** Evaluating Security Effectiveness and Performance Trade-offs of Zero Trust in Cloud-Native Microservices  
**Date:** October 2026  

---

## 1. Experimental Threat Formulation

The empirical security evaluation tests the lateral movement resilience of cloud-native microservices under the **Assumed Breach Paradigm**. An adversary has achieved initial code execution within the public-facing storefront container (`front-end`).

From this compromised foothold, the attacker systematically executes 14 controlled penetration probes spanning:
1. **Legitimate Operational Paths** (Control Group: Baseline service access required for normal application functionality).
2. **Unauthorized Layer-7 Service Pivots** (Bypassing workflow logic to invoke backend payment and shipping endpoints directly).
3. **Unauthorized Data Store Exfiltration** (Direct TCP probes to MongoDB, MySQL, and RabbitMQ persistence tiers).
4. **Cluster Infrastructure Probing** (Reconnaissance targeting Kubernetes DNS and Istio control plane interfaces).

---

## 2. Empirical Attack Evaluation Matrix

The table below presents the verified empirical outcomes across the three experimental architectures:
- **C0 (Baseline Perimeter):** Unrestricted east-west network, default perimeter security.
- **C1 (STRICT mTLS):** Workload identity & transport encryption active (Citadel SPIFFE certs), no L7 authorization rules.
- **C2 (Layered Zero Trust):** STRICT mTLS + ServiceAccount-level least-privilege `AuthorizationPolicy` + L3/L4 `NetworkPolicy`.

| ID | Attack Vector Description | Protocol & Target Port | Authorization Classification | C0 (Baseline) | C1 (STRICT mTLS) | C2 (Layered ZTA) | Security Enforcement Mechanism (C2) |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **AV-01** | Legitimate Catalog Browse | HTTP/80 (`catalogue/catalogue`) | **Legitimate (Allowed)** | 🔴 Reached (200) | 🔴 Reached (200) | 🟢 **Allowed (200)** | Policy `allow-catalogue` permits caller SA. |
| **AV-02** | Legitimate Cart Item Query | HTTP/80 (`carts/carts/1`) | **Legitimate (Allowed)** | 🔴 Reached (500) | 🔴 Reached (500) | 🟢 **Allowed (200/500)** | Policy `allow-carts` permits caller SA. |
| **AV-03** | Legitimate Customer Orders API | HTTP/80 (`orders/orders`) | **Legitimate (Allowed)** | 🔴 Reached (500) | 🔴 Reached (500) | 🟢 **Allowed (500)** | Policy `allow-orders` permits caller SA. |
| **AV-04** | Legitimate User Profile Query | HTTP/80 (`user/customers`) | **Legitimate (Allowed)** | 🔴 Reached (200) | 🔴 Reached (200) | 🟢 **Allowed (200)** | Policy `allow-user` permits caller SA. |
| **AV-05** | Legitimate Session Store (Redis) | TCP/6379 (`session-db:6379`) | **Legitimate (Allowed)** | 🔴 Connected | 🔴 Connected | 🟢 **Allowed (Open)** | L4 NetPol allows front-end → session-db. |
| **AV-06** | Direct Payment Trigger (Bypass Orders) | HTTP/80 (`payment/paymentAuth`) | **Unauthorized (Privilege Escalation)** | 🔴 **Reached (500)** | 🔴 **Reached (500)** | 🟢 **BLOCKED (503/Timeout)** | L7 AuthPolicy rejects SA `front-end`; L4 NetPol drops. |
| **AV-07** | Direct Shipping Trigger (Bypass Orders) | HTTP/80 (`shipping/shipping`) | **Unauthorized (Privilege Escalation)** | 🔴 **Reached (400)** | 🔴 **Reached (400)** | 🟢 **BLOCKED (503/Timeout)** | L7 AuthPolicy rejects SA `front-end`; L4 NetPol drops. |
| **AV-08** | Direct Orders-DB Extraction (MongoDB) | TCP/27017 (`orders-db:27017`) | **Unauthorized (Data Breach)** | 🔴 **Connected (Open)** | 🔴 **Connected (Open)** | 🟢 **BLOCKED (ECONNRESET)** | Envoy L4 RBAC terminates socket upon payload write. |
| **AV-09** | Direct Carts-DB Extraction (MongoDB) | TCP/27017 (`carts-db:27017`) | **Unauthorized (Data Breach)** | 🔴 **Connected (Open)** | 🔴 **Connected (Open)** | 🟢 **BLOCKED (ECONNRESET)** | Envoy L4 RBAC terminates socket upon payload write. |
| **AV-10** | Direct Catalogue-DB SQL Injection (MySQL)| TCP/3306 (`catalogue-db:3306`) | **Unauthorized (Data Breach)** | 🔴 **Connected (Open)** | 🔴 **Connected (Open)** | 🟢 **BLOCKED (ECONNRESET)** | Envoy L4 RBAC terminates socket upon payload write. |
| **AV-11** | Direct User-DB Exfiltration (MongoDB) | TCP/27017 (`user-db:27017`) | **Unauthorized (Credential Theft)** | 🔴 **Connected (Open)** | 🔴 **Connected (Open)** | 🟢 **BLOCKED (ECONNRESET)** | Envoy L4 RBAC terminates socket upon payload write. |
| **AV-12** | Message Broker Poisoning (RabbitMQ) | TCP/5672 (`rabbitmq:5672`) | **Unauthorized (Queue Tampering)** | 🔴 **Connected (Open)** | 🔴 **Connected (Open)** | 🟢 **BLOCKED (ECONNRESET)** | Envoy L4 RBAC terminates socket upon AMQP payload. |
| **AV-13** | Cross-Namespace DNS Reconnaissance | TCP/53 (`kube-dns.kube-system`) | **Unauthorized (Cluster Discovery)** | 🔴 **Connected (Open)** | 🔴 **Connected (Open)** | 🟢 **BLOCKED (Timeout)** | L3/L4 NetworkPolicy isolates namespace egress. |
| **AV-14** | Cross-Namespace Control Plane Probe | TCP/15012 (`istiod.istio-system`) | **Unauthorized (Control Plane Pivot)**| 🔴 **Connected (Open)** | 🔴 **Connected (Open)** | ⚠️ **Confined (mTLS)** | Requires valid Citadel xDS token; unauthenticated. |

---

## 3. Quantitative Security Metrics Comparison

| Quantitative Metric | Definition | Baseline (C0) | STRICT mTLS (C1) | Layered ZTA (C2) | Improvement (C0 → C2) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Lateral Movement Containment Ratio (LMCR)** | Blocked Unauthorized Vectors / Total Unauthorized Vectors | **0.00%** (0/9) | **0.00%** (0/9) | **88.89% - 100%** | **+88.9% - +100%** |
| **Data-Store Isolation Score (DSIS)** | Protected Persistence Tiers / Total Persistence Tiers | **0.00%** (0/5) | **0.00%** (0/5) | **100.00%** (5/5) | **+100.0%** |
| **Blast Radius (Accessible DBs from Front-End)** | Count of directly queryable data stores | 5 / 5 Databases | 5 / 5 Databases | **0 / 5 Databases** | **100% Blast Radius Reduction** |
| **Legitimate Workflow Availability** | Percentage of operational user journeys functional | 100% | 100% | **100%** | **0% Service Interruption** |
