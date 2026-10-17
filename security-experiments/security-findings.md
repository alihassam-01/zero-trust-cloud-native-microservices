# Security Findings: Analysis of Lateral Movement Resistance and The "mTLS Illusion"

**Author:** Hassam Ali  
**Target Program:** Master of Science in Computer Science / Cloud & Systems Security  
**Project:** Evaluating Security Effectiveness and Performance Trade-offs of Zero Trust in Cloud-Native Microservices  
**Date:** October 2026  

---

## 1. Executive Summary of Security Findings

The empirical results generated from our automated security evaluation suite reveal three primary insights regarding cloud-native microservice defense:

1. **Empirical Validation of Hypothesis $H_{1a}$ (Perimeter Inadequacy):** In a traditional perimeter-only architecture ($C_0$), once an adversary establishes initial execution inside a public-facing container, the internal network is completely unprotected. The attacker successfully reached 100% of internal services, databases, and message brokers ($\text{LMCR} = 0.00\%$, $\text{DSIS} = 0.00\%$).
2. **Empirical Validation of Hypothesis $H_{1b}$ (The "mTLS Illusion"):** Enforcing STRICT mutual TLS across all microservice pods ($C_1$) encrypts traffic and establishes cryptographic workload identities (SPIFFE X.509 certificates). However, **mTLS alone provided zero reduction in lateral movement reachability** ($\text{LMCR} = 0.00\%$). Because the compromised front-end workload was authenticated to the mesh, target sidecars accepted connections and allowed direct access to payment APIs and internal databases.
3. **Empirical Validation of Hypothesis $H_{1c}$ (Layered Defense Efficacy):** Combining STRICT mTLS with fine-grained L7 `AuthorizationPolicy` rules and defense-in-depth L3/L4 `NetworkPolicy` segmentations ($C_2$) successfully contained lateral movement ($\text{LMCR} \ge 88.9\%$, $\text{DSIS} = 100.0\%$), reducing data store blast radius to zero without impacting legitimate storefront functionality.

---

## 2. In-Depth Analysis: The "mTLS Illusion"

A widespread misconception among cloud practitioners and commercial security vendors is that adopting a service mesh with mutual TLS fulfills the requirements of Zero Trust Architecture.

Our controlled experiments directly disprove this assumption:
- In Scenario $C_1$, every workload in the `sock-shop` namespace was injected with an Envoy sidecar proxy.
- Istio Citadel dynamically provisioned short-lived X.509 certificates asserting identity:
  `URI: spiffe://cluster.local/ns/sock-shop/sa/front-end`
- When the attacker inside `front-end` initiated an unauthorized connection to `payment:80/paymentAuth` or `orders-db:27017`, the outbound traffic was intercepted by the local Envoy sidecar.
- The local Envoy initiated a mutual TLS handshake with the destination Envoy sidecar on `payment` or `orders-db`. Both sidecars successfully validated each other's certificate chain against `istio-ca-root-cert`.
- **Because $C_1$ lacked explicit authorization policies, the destination Envoy evaluated the connection as "Authenticated" and immediately forwarded the traffic to the application container.**

```
                               THE "mTLS ILLUSION" PARADOX
Attacker in front-end
        |
        v  (Cleartext TCP)
Local Envoy Sidecar
        |
        |===== Cryptographic mTLS 1.3 Tunnel ======> Destination Envoy (payment)
        |      SPIFFE Client Cert: "sa/front-end"           |
        |      Target: "payment"                            | 1. Cert is VALID (Citadel)
        |                                                   | 2. No AuthorizationPolicy
        |                                                   v
        +---------------------------------------------> Forward to App Container!
                                                        (PAYMENT API COMPROMISED!)
```

**Key Takeaway:** Mutual TLS authenticates **WHO** is speaking, but does not dictate **WHAT** they are permitted to do. Zero Trust requires both Authentication (Identity) AND Authorization (Least Privilege).

---

## 3. Defense-in-Depth Mechanisms in Scenario $C_2$

In Scenario $C_2$, security is enforced through two complementary layers:

### 3.1 Layer 7 Authorization Policies (Istio `AuthorizationPolicy`)
- Istio evaluates HTTP attributes (method, URI path, headers) in conjunction with caller identity (`source.principals`).
- When `front-end` attempted to call `payment/paymentAuth`:
  - Policy `allow-payment` explicitly requires:
    `source.principals: ["cluster.local/ns/sock-shop/sa/orders"]`
  - Because the authenticated principal was `front-end`, Envoy intercepted the request before it reached the application process and returned an immediate **HTTP 403 Forbidden (`RBAC: access denied`)**.

### 3.2 Layer 4 RBAC and Network Policies
- For non-HTTP TCP connections (e.g., MongoDB on port 27017, MySQL on port 3306):
  - In Scenario $C_2$, Envoy maintains an L4 network RBAC filter (`envoy.filters.network.rbac`).
  - When the attacker opens a raw TCP socket and writes a payload, Envoy inspects the cryptographic principal and immediately resets the socket (`ECONNRESET`).
  - In parallel, Kubernetes `NetworkPolicy` drops unauthorized TCP packets at the kernel packet-filtering level, ensuring that even if a sidecar proxy is bypassed, the Linux kernel prevents cross-pod socket establishment.

---

## 4. Blast Radius and Containment Summary

```
                      DATA STORE BLAST RADIUS COMPARISON
                   (Number of DBs Directly Accessible from Frontend)

  Baseline (C0)    [■■■■■]  5 / 5 Data Stores (100% Exposed)
  mTLS Only (C1)   [■■■■■]  5 / 5 Data Stores (100% Exposed)
  Layered ZTA (C2) [     ]  0 / 5 Data Stores (0% Exposed - 100% Containment)
```

By decoupling identity from authorization and strictly binding microservice identities to declared operational graphs, Layered Zero Trust transforms a potentially catastrophic perimeter breach into a contained, localized incident.
