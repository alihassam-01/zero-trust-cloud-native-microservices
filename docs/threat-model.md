# Threat Model: Zero Trust Architecture in Cloud-Native Microservices

**Author:** Hassam Ali  
**Target Program:** Master of Science in Computer Science / Cloud & Systems Security  
**Project:** Evaluating Security Effectiveness and Performance Trade-offs of Zero Trust in Cloud-Native Microservices  
**Date:** October 2026  

---

## 1. Overview and Security Philosophy

In traditional cloud-native perimeter security, the internal network is treated as a "walled garden" or trusted zone. Any workload operating within the cluster perimeter is implicitly trusted. In contrast, this research adopts the **Assumed Breach Paradigm** codified in NIST SP 800-207:
> *"The enterprise does not assume that any asset or user is trusted simply based on physical or network location... all access requests are evaluated dynamically and must be verified explicitly."*

This threat model defines the attacker profile, assumed capabilities, attack objectives, trust boundaries, STRIDE threat taxonomy, and mapping to the MITRE ATT&CK for Containers framework.

---

## 2. Attacker Profile and Assumed Capabilities

```
                  +--------------------------------------------------------+
                  |                   INTERNET ADVERSARY                   |
                  +--------------------------------------------------------+
                                              |
                                              | 1. Exploit Ingress/Frontend (CVE/SSRF/RCE)
                                              v
      +==================================================================================+
      |  CLUSTER PERIMETER (sock-shop namespace)                                         |
      |                                                                                  |
      |   [ COMPROMISED FRONT-END POD ] <--- [ATTACKER FOOTHOLD ESTABLISHED]             |
      |   - Valid SPIFFE Identity: spiffe://cluster.local/ns/sock-shop/sa/front-end       |
      |   - Envoy sidecar proxy active (C1/C2)                                           |
      |   - Raw socket, curl, and network capabilities                                   |
      |                                                                                  |
      |          |                            |                           |              |
      |          | 2a. Probe Carts/Catalogue  | 2b. Direct DB Access      | 2c. Bypass   |
      |          |     (Legitimate paths)     |     (UNAUTHORIZED)        |     to Payment|
      |          v                            v                           v              |
      |   +-------------+              +-------------+             +-------------+       |
      |   |  catalogue  |              |  orders-db  |             |   payment   |       |
      |   |  & carts    |              | (Port 27017)|             |  (Port 80)  |       |
      |   +-------------+              +-------------+             +-------------+       |
      |   (Allowed: C0,C1,C2)          (C0: OPEN     )             (C0: OPEN     )       |
      |                                (C1: MESH-AUTH)             (C1: MESH-AUTH)       |
      |                                (C2: BLOCKED! )             (C2: BLOCKED! )       |
      +==================================================================================+
```

### 2.1 Attacker Position
The primary threat actor has achieved an **initial foothold inside the public-facing `front-end` pod**.
- **Initial Vector:** Exploitation of an application-layer vulnerability in the Node.js/Express front-end tier (e.g., Remote Code Execution via an unpatched npm dependency, Server-Side Request Forgery (SSRF), or arbitrary file write leading to shellcode execution).
- **Attacker State:** The attacker executes arbitrary Linux commands and shell scripts within the context of the container runtime.

### 2.2 Assumed Capabilities
The attacker possesses the following concrete operational capabilities:
1. **Container Privilege:** Non-root or standard container user execution within the Linux namespace.
2. **Network Access:** Ability to open arbitrary TCP/UDP sockets, execute HTTP requests via `curl`, `wget`, or Python scripts, and scan internal cluster IP ranges (`10.96.0.0/12` / `10.244.0.0/16`).
3. **Identity Material:** 
   - Access to the local Kubernetes ServiceAccount token (`/var/run/secrets/kubernetes.io/serviceaccount/token`).
   - In service mesh modes ($C_1, C_2$), outbound traffic emitted by the attacker container is transparently routed through the local Envoy sidecar proxy, which automatically injects the pod's valid SPIFFE X.509 certificate into mTLS handshakes.
4. **Knowledge:** Complete knowledge of public DNS names within the cluster (e.g., `orders.sock-shop.svc.cluster.local`, `orders-db.sock-shop.svc.cluster.local`).

### 2.3 Non-Capabilities (Out of Scope)
The attacker does **not** possess:
- Host-level root access (kernel escape / cgroup breakout).
- Minikube host machine hypervisor control.
- Physical access to the underlying hardware.
- Ability to compromise the cryptographic private keys of `istiod` (the CA).

---

## 3. Attacker Objectives (Attack Vectors)

| ID | Attack Vector | Target Service & Port | Normal Architecture Relationship | Attacker Objective |
| :--- | :--- | :--- | :--- | :--- |
| **AV-01** | Legitimate Catalog Query | `catalogue:80` (`/catalogue`) | **Legitimate Path** | Normal user browsing (control test). |
| **AV-02** | Legitimate Cart Operation | `carts:80` (`/carts`) | **Legitimate Path** | Normal user shopping journey (control test). |
| **AV-03** | Lateral Pivot to Orders | `orders:80` (`/orders`) | **Unauthorized** (Only frontend $\rightarrow$ orders via user session; direct orders API should not be exposed). | Enumerate all customer orders, cancel orders, or manipulate prices. |
| **AV-04** | Direct Payment Submission | `payment:80` (`/paymentAuth`) | **Unauthorized** (Payment must ONLY be called by `orders`). | Authorize fraudulent credit card payments bypassing order validation. |
| **AV-05** | Direct Shipping Trigger | `shipping:80` (`/shipping`) | **Unauthorized** (Shipping must ONLY be called by `orders`). | Dispatch orders without payment verification. |
| **AV-06** | Direct Orders-DB Extraction | `orders-db:27017` (MongoDB) | **Unauthorized** (DB must ONLY be accessed by `orders` pod). | Dump raw customer credit cards, addresses, and purchase history. |
| **AV-07** | Direct Carts-DB Extraction | `carts-db:27017` (MongoDB) | **Unauthorized** (DB must ONLY be accessed by `carts` pod). | Dump or tamper with active customer shopping carts. |
| **AV-08** | Direct Catalogue-DB SQL Injection | `catalogue-db:3306` (MySQL) | **Unauthorized** (DB must ONLY be accessed by `catalogue` pod). | Execute raw SQL statements, drop tables, or modify item stock and prices. |
| **AV-09** | Direct User-DB Exfiltration | `user-db:27017` (MongoDB) | **Unauthorized** (DB must ONLY be accessed by `user` pod). | Exfiltrate customer password hashes, emails, and profile tokens. |
| **AV-10** | Message Broker Injection | `rabbitmq:5672,9090` (AMQP) | **Unauthorized** (Queue must ONLY be accessed by `shipping` & `queue-master`). | Intercept or forge shipping order messages on the message bus. |
| **AV-11** | Direct Session-DB Tampering | `session-db:6379` (Redis) | **Unauthorized** (Session store accessed by `front-end` cookies). | Hijack active sessions or inject arbitrary serialized session objects. |
| **AV-12** | Workload Identity Spoofing | Target services | **Unauthorized** | Attempt to forge SPIFFE identities without private key access. |
| **AV-13** | K8s API Server Reconnaissance | `kubernetes.default.svc:443` | **Unauthorized** | Abuse default ServiceAccount token to list pods, secrets, and nodes. |
| **AV-14** | Cross-Namespace Lateral Probe | `kube-system`, `istio-system` | **Unauthorized** | Pivot across namespace boundaries to compromise cluster control plane. |

---

## 4. Trust Boundaries and Architectural Defense Layers

```
+---------------------------------------------------------------------------------------------+
|                                    DEFENSE-IN-DEPTH LAYERS                                  |
+---------------------------------------------------------------------------------------------+
| Layer 1: Cryptographic Authentication (mTLS / SPIFFE)                                       |
| - Verifies WHO is communicating (e.g., spiffe://cluster.local/ns/sock-shop/sa/front-end)     |
| - Encrypts all data in transit against eavesdropping and packet injection                   |
| - DEFICIENCY ALONE: All mesh pods have valid certificates; does not restrict destination!   |
+---------------------------------------------------------------------------------------------+
| Layer 2: Fine-Grained Authorization (Istio AuthorizationPolicy)                             |
| - Enforces WHAT the authenticated identity is permitted to do at Layer 7                    |
| - Specifies allowed source ServiceAccount, destination host, HTTP methods, and paths        |
| - Result: Front-end pod calling payment:80 receives "403 RBAC: access denied"               |
+---------------------------------------------------------------------------------------------+
| Layer 3: Network Segmentation (Kubernetes NetworkPolicy)                                    |
| - Enforces WHERE packets can travel at Layer 3 / Layer 4 (IP/Port)                          |
| - Blocks non-HTTP TCP connections (e.g., direct Mongo 27017 or MySQL 3306 from frontend)   |
| - Result: TCP connection timed out / dropped at Linux kernel iptables/eBPF level            |
+---------------------------------------------------------------------------------------------+
```

### 4.1 Boundary Analysis Across Configurations

1. **Baseline ($C_0$):**
   - No mutual authentication.
   - East-west traffic is completely flat and unencrypted.
   - Any pod can reach any IP and port in the cluster.
   - **Expected Result:** Attacker successfully executes AV-01 through AV-11 (100% lateral reachability).

2. **STRICT mTLS ($C_1$):**
   - Mutual TLS enforced between all pods via Envoy sidecars.
   - Traffic is encrypted and workloads authenticate via Citadel-issued X.509 certs.
   - **Crucial Security Finding:** Because the attacker has compromised `front-end`, their outbound requests are routed through the `front-end` Envoy proxy. The proxy attaches the legitimate `front-end` SPIFFE certificate. **Because $C_1$ lacks authorization rules, the target proxies accept the connection!**
   - **Expected Result:** Attacker still successfully connects to internal services and databases (0% reduction in lateral reachability).

3. **Layered Zero Trust ($C_2$):**
   - STRICT mTLS authenticates the caller identity.
   - L7 `AuthorizationPolicy` blocks `front-end` from calling `payment`, `shipping`, and direct database endpoints (returns `HTTP 403 Forbidden`).
   - L3/L4 `NetworkPolicy` drops unauthorized TCP packets at the kernel level for database ports.
   - **Expected Result:** 100% of unauthorized lateral movement vectors (AV-03 through AV-11) are blocked!

---

## 5. STRIDE Threat Categorization

| STRIDE Category | Threat Description in Microservices | Baseline Mitigation ($C_0$) | mTLS Mitigation ($C_1$) | Layered ZTA Mitigation ($C_2$) |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates legitimate service (e.g. spoofing IP to call payment). | ❌ None (IP easily spoofed in flat network). | ✅ Cryptographic SPIFFE X.509 client certificate verification. | ✅ Cryptographic SPIFFE verification + strict SA binding. |
| **Tampering** | Man-in-the-middle packet modification on cluster bridge. | ❌ Cleartext HTTP/TCP on wire. | ✅ TLS 1.3 wire encryption with authenticated cipher suites. | ✅ TLS 1.3 wire encryption + L7 policy validation. |
| **Repudiation** | Lack of forensic attribution for unauthorized internal API calls. | ❌ Minimal container stdout logs. | ⚠️ Transport logs without policy decision tracking. | ✅ Structured Envoy access logs recording source SPIFFE ID, method, path, and RBAC decision. |
| **Information Disclosure** | Sniffing internal database traffic or direct SQL/Mongo exfiltration. | ❌ Wire sniffing possible; direct DB queries succeed. | ⚠️ Wire sniffed traffic is encrypted, but direct DB queries from frontend still succeed. | ✅ Wire encrypted AND direct DB connections dropped by L4 NetworkPolicy and L7 auth. |
| **Denial of Service** | Flooding backend services or message queues from compromised pod. | ❌ Unrestricted packet flooding. | ⚠️ Unrestricted flooding from authenticated mesh pods. | ✅ Connection limits, rate limiting, and unauthorized paths severed. |
| **Elevation of Privilege** | Frontend pod assumes backend payment authority or calls cluster API. | ❌ Flat access to all services and cluster IP. | ❌ Workload identity valid for all mesh endpoints. | ✅ Least-privilege `AuthorizationPolicy` confines permissions strictly to declared dependencies. |

---

## 6. MITRE ATT&CK for Containers Mapping

| MITRE Tactic | Technique ID | Technique Name | Exploitation in $C_0$ / $C_1$ | Mitigation in $C_2$ (Zero Trust) |
| :--- | :--- | :--- | :--- | :--- |
| **Initial Access** | T1190 | Exploit Public-Facing Application | RCE / SSRF in Front-End container. | Pod isolated in DMZ; blast radius confined. |
| **Execution** | T1059.004 | Unix Shell Execution | Attacker spawns shell in Front-End. | Least-privilege container security context + read-only rootfs. |
| **Discovery** | T1046 | Network Service Discovery | Scanning cluster CIDRs reveals open DB ports (3306, 27017). | NetworkPolicy drops unauthorized port scan packets silently. |
| **Lateral Movement** | T1021.002 | SMB/Remote Services (Internal APIs) | Attacker invokes `/paymentAuth` and `/orders` directly. | Istio `AuthorizationPolicy` returns `403 Access Denied`. |
| **Exfiltration** | T1530 | Data from Cloud Storage / DB | `mongo --host orders-db` dumps all customer credit cards. | NetworkPolicy drops TCP 27017 traffic from frontend to orders-db. |
| **Defense Evasion** | T1562.001 | Impair Defenses (Bypass Ingress) | Attacker bypasses edge WAF by pivoting internally. | Every internal hop acts as an independent Policy Enforcement Point. |
