# Research Proposal: Evaluating Security Effectiveness and Performance Trade-offs of Zero Trust in Cloud-Native Microservices

**Principal Investigator / Author:** Hassam Ali  
**Affiliation:** Independent Research Project  
**Target Program:** Master of Science in Computer Science / Cloud & Systems Security  
**Repository:** [Hassam-01/zero-trust-cloud-native-microservices](https://github.com/Hassam-01/zero-trust-cloud-native-microservices)  
**Date:** October 2026  

---

## 1. Executive Summary and Problem Statement

Modern enterprise applications have shifted from monolithic designs to containerized, distributed microservice architectures deployed on container orchestrators like Kubernetes. Traditionally, organizational security has relied on **perimeter-based defenses** (firewalls, VPNs, ingress API gateways). Under this traditional model, once traffic enters the internal network perimeter, inter-service ("east-west") communication is implicitly trusted and unrestricted.

However, modern threat realities violate this implicit trust assumption:
1. **Assumed Breach Paradigm:** Vulnerabilities in public-facing services (e.g., Remote Code Execution, Server-Side Request Forgery, vulnerable open-source dependencies) allow adversaries to establish an initial foothold within the cluster perimeter.
2. **Unrestricted Lateral Movement:** In default Kubernetes deployments, any compromised Pod can establish TCP connections and HTTP sessions with every other Pod in the cluster, facilitating rapid pivoting toward internal databases, message brokers, and payment backends.
3. **The "mTLS Illusion":** While mutual Transport Layer Security (mTLS) deployed via service meshes (e.g., Istio) provides cryptographic confidentiality and identity verification, **mTLS alone does not enforce least privilege**. Any mesh-authenticated workload can still invoke sensitive internal APIs unless explicit authorization policies are enforced.

To address these vulnerabilities, **Zero Trust Architecture (ZTA)** (codified in NIST SP 800-207 and NIST SP 800-207A) establishes the foundational tenet: *"Never Trust, Always Verify."* In cloud-native microservices, implementing ZTA requires layering workload identity (SPIFFE/mTLS), application-layer authorization (`AuthorizationPolicy`), and transport-layer segmentation (`NetworkPolicy`).

Despite industry advocacy, engineering teams frequently cite the **operational complexity** and **performance overhead** (proxy latency, CPU cycles, memory footprints) as prohibitive barriers to full Zero Trust adoption.

This research study provides a rigorous, empirical evaluation of both the **security containment effectiveness** and the **system performance trade-offs** of Zero Trust Architecture across three benchmark configurations using the Sock Shop cloud-native microservice testbed.

---

## 2. Research Questions and Testable Hypotheses

### Research Question 1 (RQ1 - Security Containment)
> *To what extent does a Layered Zero Trust Architecture (STRICT mTLS + L7 AuthorizationPolicy + L3/L4 NetworkPolicy) reduce the attack surface and prevent lateral movement from a compromised perimeter service compared to traditional perimeter and mTLS-only baselines?*

- **Hypothesis $H_{1a}$ (Perimeter Inadequacy):** In a standard perimeter-only Kubernetes deployment ($C_0$), a compromised front-end workload can successfully initiate lateral movement to 100% of internal services and databases.
- **Hypothesis $H_{1b}$ (mTLS Insufficiency):** Deploying STRICT mTLS without layer-7 authorization ($C_1$) fails to reduce the lateral movement reachability of internal services because the compromised workload possesses a valid mesh-issued cryptographic identity.
- **Hypothesis $H_{1c}$ (Layered Defense Efficacy):** Applying layered Zero Trust ($C_2$) with SPIFFE-based least-privilege `AuthorizationPolicy` and defense-in-depth `NetworkPolicy` reduces unauthorized lateral movement reachability to 0% while preserving legitimate operational transactions.

### Research Question 2 (RQ2 - Performance and Resource Overhead)
> *What are the quantifiable performance penalties (p50, p90, p95, and p99 latency inflation, throughput degradation) and host resource overheads (CPU and memory footprint) introduced by each incremental layer of Zero Trust enforcement?*

- **Hypothesis $H_{2a}$ (Latency Profile):** Sidecar proxy interception and mutual TLS cryptographic handshakes introduce a statistically significant latency increase ($\Delta L_{p50} \le 20\%$, but higher tail latency impact $\Delta L_{p99} \ge 35\%$).
- **Hypothesis $H_{2b}$ (Throughput Ceiling):** Layered authorization evaluations introduce negligible throughput degradation relative to mTLS alone ($< 5\%$ difference between $C_1$ and $C_2$), indicating that cryptographic termination dominates proxy overhead rather than policy table evaluations.
- **Hypothesis $H_{2c}$ (Resource Burden):** The memory overhead scales linearly with the number of sidecar proxies, with baseline proxy footprints remaining under 60 MB per pod.

### Research Question 3 (RQ3 - Traffic-Informed Policy Automation)
> *Can automated telemetry-informed policy synthesis reliably infer and enforce least-privilege Zero Trust rules from observed traffic graphs without breaking production functionality?*

- **Hypothesis $H_3$:** A dynamic traffic analysis heuristic can synthesize deterministic, least-privilege Istio `AuthorizationPolicy` manifests from distributed trace logs with 100% precision for observed legitimate paths and 0 false-positive service disruptions.

---

## 3. Experimental Variables

| Variable Classification | Variable Name | Description & Operationalization |
| :--- | :--- | :--- |
| **Independent Variable** | Security Configuration ($C$) | • **$C_0$ (Baseline):** Default Kubernetes perimeter, no service mesh sidecars, flat network.<br>• **$C_1$ (STRICT mTLS):** Istio service mesh sidecars injected, STRICT PeerAuthentication, no L7 authorization rules.<br>• **$C_2$ (Layered ZTA):** STRICT mTLS + ServiceAccount-scoped L7 `AuthorizationPolicy` + L3/L4 `NetworkPolicy`. |
| **Independent Variable** | Workload Concurrency ($N$) | Simulated concurrent virtual users: $N \in \{1, 10, 25, 50, 100\}$. |
| **Dependent Variable (Security)** | Attack Surface Reachability ($R_{lat}$) | Percentage of unauthorized internal services/ports successfully connected to from a compromised pod: $R_{lat} = \frac{\|S_{compromised\_reach}\|}{\|S_{unauthorized}\|} \times 100\%$. |
| **Dependent Variable (Security)** | Lateral Exploitation Blast Radius | Number of distinct data stores (MongoDB, MySQL, Redis, RabbitMQ) directly accessible to an attacker. |
| **Dependent Variable (Performance)** | Request Latency ($L$) | Response time distributions measured at $p_{50}, p_{90}, p_{95}, p_{99}$ in milliseconds (ms). |
| **Dependent Variable (Performance)** | System Throughput ($T$) | Sustained successful HTTP requests per second (RPS). |
| **Dependent Variable (Performance)** | Error Rate ($E$) | Percentage of failed HTTP requests (5xx or connection drops) under load. |
| **Dependent Variable (Resource)** | CPU Utilization ($U_{cpu}$) | Compute consumption of application containers vs. Istio sidecar proxies in millicores (m). |
| **Dependent Variable (Resource)** | Memory Footprint ($U_{mem}$) | Working set memory of application containers vs. Istio sidecars in Megabytes (MB). |
| **Controlled Variables** | Hardware & Hypervisor | Dedicated single-node Minikube Linux environment (12 vCPUs, 16 GB RAM, NVMe storage). |
| **Controlled Variables** | Application Topology | Sock Shop microservices (14 distinct services and datastores). |
| **Controlled Variables** | Benchmark Request Set | Standardized HTTP synthetic user shopping journey (Browse Catalog $\rightarrow$ Add to Cart $\rightarrow$ View Cart). |

---

## 4. Evaluation Metrics and Mathematical Definitions

### 4.1 Security Metrics
1. **Lateral Movement Containment Ratio ($LMCR$):**
   $$\text{LMCR} = 1 - \frac{\sum_{i=1}^{M} A_i}{M}$$
   Where $M$ is the total number of tested unauthorized attack vectors, and $A_i \in \{0, 1\}$ denotes whether attack vector $i$ succeeded ($1$) or was blocked ($0$).
   - A fully protected system achieves $\text{LMCR} = 1.0$ ($100\%$ containment).
   - An unprotected baseline achieves $\text{LMCR} = 0.0$ ($0\%$ containment).

2. **Data-Store Isolation Score ($DSIS$):**
   $$\text{DSIS} = 1 - \frac{N_{accessible\_db}}{N_{total\_db}}$$
   Measures whether backend databases (Mongo, MySQL, Redis) can be directly queried from application pods that have no business relationship with them.

### 4.2 Performance Metrics
1. **Tail Latency Inflation ($\Delta L_{p99}$):**
   $$\Delta L_{p99} = \frac{L_{p99}(C_x) - L_{p99}(C_0)}{L_{p99}(C_0)} \times 100\%$$
2. **Throughput Degradation ($\Delta T$):**
   $$\Delta T = \frac{T(C_0) - T(C_x)}{T(C_0)} \times 100\%$$
3. **Proxy Overhead Ratio ($POR_{mem}$):**
   $$\text{POR}_{mem} = \frac{\sum \text{Memory}(\text{Envoy})}{\sum \text{Memory}(\text{App})} \times 100\%$$

---

## 5. Significance and Contribution

This research provides:
1. **Empirical Clarity on mTLS vs. Authorization:** Concrete experimental evidence dispelling the common misconception that deploying mTLS alone provides Zero Trust security.
2. **Quantified Cost-Benefit Decision Framework:** A benchmark reference enabling architects to assess the exact latency and CPU cost of Zero Trust controls before production rollout.
3. **Reproducible Experimental Testbed:** Fully automated deployment, testing, and plotting scripts executable on standard Kubernetes clusters.
4. **Autonomous Policy Synthesis Extension:** An automated tool demonstrating how production traffic traces can be transformed into Zero Trust policies, addressing the primary barrier of manual policy configuration.
