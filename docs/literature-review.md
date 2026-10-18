# Systematic Literature Review: Zero Trust Architecture in Cloud-Native Microservices

**Author:** Hassam Ali  
**Target Program:** Master of Science in Computer Science / Cloud & Systems Security  
**Project:** Evaluating Security Effectiveness and Performance Trade-offs of Zero Trust in Cloud-Native Microservices  
**Date:** October 2026  

---

## 1. Introduction and Scope

As enterprise architectures transition from monolithic systems to microservice ecosystems, traditional perimeter defense mechanisms (firewalls, VPNs, perimeter demilitarized zones) have become insufficient. Zero Trust Architecture (ZTA) has emerged as the paradigm of choice for securing distributed environments. However, while commercial whitepapers and conceptual guidelines abound, rigorous empirical literature comparing security containment against performance degradation across multi-stage configurations remains scarce.

This literature review analyzes 12 foundational papers, standards, and empirical studies spanning four key thematic pillars:
1. **Foundational Zero Trust Standards and Architectures** (NIST SP 800-207, NIST SP 800-207A, Gilman & Barth).
2. **Service Mesh as a Policy Enforcement Point (PEP)** (NIST SP 800-204A, SP 800-204B, Staffolani et al.).
3. **Empirical Performance and Overhead Studies** (Li et al., Pahl et al., Dragoni et al.).
4. **Automated Least-Privilege Policy Generation** (Zerfass et al., Yu et al., Ward & Barker).

---

## 2. Synthesis of Primary Literature

### 2.1 Foundational Zero Trust Standards

#### [1] NIST SP 800-207: "Zero Trust Architecture" (Rose, Borchert, Mitchell, Connelly, 2020)
- **Core Tenets:** NIST establishes seven foundational tenets: all data sources and computing services are resources; all communication is secured regardless of network location; access to individual enterprise resources is granted on a per-session basis; access is determined by dynamic policy; the enterprise monitors and measures the integrity of all assets; all resource authentication and authorization are dynamic and strictly enforced; continuous logging and monitoring.
- **Relevance:** Serves as the authoritative architectural baseline for this study. The Policy Enforcement Point (PEP) is mapped directly to the Istio Envoy sidecar proxy, while the Policy Decision Point (PDP) maps to `istiod`.
- **Limitation in Literature:** SP 800-207 provides an abstract conceptual framework without concrete container orchestration benchmarks or performance overhead quantification.

#### [2] NIST SP 800-207A: "A Zero Trust Architecture Model for Access Control in Cloud-Native Applications in Multi-Location Environments" (Barker, Chandramouli, 2023)
- **Contribution:** Extends SP 800-207 explicitly to cloud-native, multi-tenant Kubernetes environments. Articulates how SPIFFE/SPIRE cryptographic identities should be mapped to workload identities and evaluated at L7.
- **Relevance:** Defines the exact layered configuration adopted in our C2 architecture, mandating both cryptographic identity verification and fine-grained authorization.

#### [3] "Zero Trust Networks: Building Secure Systems in Untrusted Networks" (Gilman & Barth, O'Reilly Media, 2017)
- **Contribution:** Early pioneering work formalizing that network location must never imply trust. Introduces the concept of authenticated control and data planes, ephemeral short-lived certificates, and dynamic trust scoring.
- **Limitation:** Focuses primarily on corporate endpoint-to-service access rather than high-throughput inter-service microservice meshes.

---

### 2.2 Service Mesh as the Zero Trust Enforcement Fabric

#### [4] NIST SP 800-204A: "Building Secure Microservices-based Applications Using Service-Mesh Architecture" (Chandramouli, 2020)
- **Contribution:** Demonstrates that service mesh proxies (Envoy) serve as optimal transparent PEPs for microservices. Details how mTLS handles identity issuance, key rotation, and wire encryption without modifying application code.
- **Relevance to our study:** Direct guide for our C1 configuration. Emphasizes that mTLS secures the transport channel but explicitly highlights that application authorization requires distinct policy rules.

#### [5] NIST SP 800-204B: "Attribute-based Access Control for Microservices-based Applications using a Service Mesh" (Chandramouli, 2021)
- **Contribution:** Extends 800-204A by defining Attribute-Based Access Control (ABAC) and Role-Based Access Control (RBAC) schemas over service mesh data planes using HTTP headers, JWTs, and SPIFFE IDs.
- **Relevance:** Provides the theoretical rationale for structuring Istio `AuthorizationPolicy` resources evaluated in Phase 3 and Phase 4.

#### [6] "Securing Microservices with Service Mesh: An Architectural Evaluation" (Staffolani, Fontana, et al., IEEE Transactions on Services Computing, 2022)
- **Contribution:** Evaluated security mechanisms in Istio, Linkerd, and Consul. Analyzed cipher suites, certificate distribution mechanisms, and authorization policy granularity.
- **Identified Gap:** The authors performed architectural assessments without executing real penetration or lateral movement attack experiments from an internal compromised pod.

---

### 2.3 Empirical Performance and Overhead Investigations

#### [7] "An Empirical Study of Service Mesh Performance and Scalability" (Li, Ding, et al., ACM Middleware, 2021)
- **Contribution:** Extensive benchmarking of Istio and Linkerd on Kubernetes under synthetic load generators. Concluded that Envoy proxy sidecars contribute 60–80% of total latency overhead, primarily through context switching and kernel network stack traverses.
- **Relevance:** Confirms our hypothesis that sidecar proxies introduce measurable latency inflation.
- **Limitation:** Did not benchmark the incremental differential cost between mTLS-only versus full L7 authorization policies; only measured global on/off switches.

#### [8] "Cloud Container Technologies: A State-of-the-Art Review" (Pahl, Brogi, Soldani, IEEE Transactions on Cloud Computing, 2019)
- **Contribution:** Surveys container isolation, network virtualization, and Linux kernel namespaces (cgroups, netns, seccomp).
- **Relevance:** Establishes the OS-level boundary constraints that make container lateral movement possible when network policies are absent.

#### [9] "Microservices: Yesterday, Today, and Tomorrow" (Dragoni, Lanese, et al., Present and Ulterior Software Engineering, 2017)
- **Contribution:** Foundational survey articulating the microservice decomposition principles, inter-service network coupling, and distributed fault domains.

---

### 2.4 Automated Access Control and Least-Privilege Synthesis

#### [10] "Automated Least-Privilege Policy Generation for Microservices" (Zerfass, Wever, et al., ACM CODASPY, 2023)
- **Contribution:** Proposed an automated policy generation approach using static binary analysis of OpenAPI specifications and runtime tracing.
- **Limitation:** Static analysis frequently misses dynamically dispatched HTTP routes, and runtime traces without heuristic clustering lead to bloated policy sets.
- **Relevance to Phase 8:** Inspires our independent research extension, which utilizes dynamic Envoy access log graphs to synthesize minimal, non-disruptive `AuthorizationPolicy` rules.

#### [11] "Microservice Architecture in Reality: An Industrial Survey" (Yu, Chen, et al., IEEE Transactions on Software Engineering, 2020)
- **Contribution:** Surveyed 257 software practitioners. Revealed that over 74% of organizations leave internal east-west traffic unauthenticated due to perceived deployment difficulty and lack of automated tooling.

#### [12] "Observing and Securing Microservice Communication" (Ward & Barker, IEEE Cloud, 2014)
- **Contribution:** Early paper on distributed tracing as a mechanism for security auditing and communication topology reconstruction.

---

## 3. Comparative Taxonomy of Related Work

The following matrix compares existing key studies against this research across six essential evaluation criteria:
- **C1:** Empirical testbed with realistic multi-tier microservices (e.g., Sock Shop).
- **C2:** Multi-stage security configurations (C0 Baseline, C1 mTLS, C2 Layered ZTA).
- **C3:** Active simulated lateral movement attack evaluation.
- **C4:** Detailed tail latency distribution (p50, p90, p95, p99).
- **C5:** Container CPU & memory sidecar resource profiling.
- **C6:** Automated policy synthesis extension.

| Paper / Study | Realistic Microservice Testbed (C1) | Multi-Stage ZTA Configs (C2) | Active Lateral Movement Attack (C3) | Tail Latency Profiling (C4) | Sidecar Resource Profiling (C5) | Automated Policy Synthesis (C6) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **NIST SP 800-207** (2020) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **NIST SP 800-204A/B** (2020/21) | ❌ | ⚠️ Conceptual | ❌ | ❌ | ❌ | ❌ |
| **Li et al.** (2021) | ⚠️ Synthetic | ❌ (Mesh on/off) | ❌ | ✅ | ✅ | ❌ |
| **Staffolani et al.** (2022) | ⚠️ Generic | ⚠️ (Mesh comparison) | ❌ | ⚠️ Average only | ❌ | ❌ |
| **Zerfass et al.** (2023) | ✅ | ❌ | ⚠️ Static only | ❌ | ❌ | ✅ |
| **This Study (Ali, 2026)** | **✅ Sock Shop (14 svcs)** | **✅ (C0, C1, C2)** | **✅ (14 attack vectors)** | **✅ (p50 to p99)** | **✅ (CPU & RAM)** | **✅ (Traffic-Informed Engine)** |

---

## 4. Identified Gaps and Research Opportunity

From this literature analysis, four distinct gaps emerge:

1. **The "mTLS Conflation" Gap:** Extensive literature treats service mesh adoption as synonymous with Zero Trust. However, mTLS provides identity verification and channel encryption; it does **not** restrict access permissions. A compromised workload possessing a mesh certificate can still query any accessible service. There is a lack of empirical benchmarks verifying this gap under controlled conditions.
2. **Dual-Evaluation Deficit:** Existing literature bifurcates into security papers (which ignore performance overheads) and performance engineering papers (which treat security policies as generic on/off switches without testing attack resistance).
3. **Tail Latency Neglect:** Most cloud performance studies report average or median latency. In microservices where a single user request cascades through 5–10 downstream services, the **99th percentile (p99) tail latency** determines the end-user experience. Quantifying p99 inflation across ZTA layers is critical.
4. **Policy Operationalization Barrier:** While least-privilege policies are theoretically optimal, manual rule authoring is error-prone. There is a need for lightweight, traffic-informed policy synthesis tools that can be validated against both legitimate workloads and attack vectors.

This research study addresses each of these four gaps directly.
