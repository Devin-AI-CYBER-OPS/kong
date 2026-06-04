# Architecture — Kong Federal EKS Deployment

## Overview

This deployment places Kong API Gateway as the single ingress point for all API traffic in a federal AWS EKS environment. Keycloak provides OIDC-based identity services, and Elastic Stack provides centralized logging and monitoring.

---

## 1. EKS Cluster Topology

```
┌───────────────────────────────────────────────────────────────────┐
│                         AWS VPC (Private)                         │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                    EKS Cluster (Private)                     │  │
│  │                                                             │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │  │
│  │  │  kong (ns)    │  │ keycloak(ns) │  │ elastic-sys (ns) │  │  │
│  │  │              │  │              │  │                  │  │  │
│  │  │ Kong Proxy   │  │ Keycloak     │  │ Elastic Agent    │  │  │
│  │  │ Kong Ingress │  │ PostgreSQL   │  │ (DaemonSet)      │  │  │
│  │  │ Controller   │  │              │  │                  │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘  │  │
│  │                                                             │  │
│  │  ┌──────────────────────────────────────────────────────┐   │  │
│  │  │           upstream-services (ns)                      │   │  │
│  │  │   Service A    Service B    Service C                 │   │  │
│  │  └──────────────────────────────────────────────────────┘   │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌───────────┐  ┌──────────────────┐  ┌─────────────────────┐    │
│  │ NLB (443) │  │ Secrets Manager  │  │ ACM (TLS Certs)     │    │
│  └───────────┘  └──────────────────┘  └─────────────────────┘    │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ KMS (Envelope encryption for K8s secrets at rest)        │    │
│  └──────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────────┘
```

**Key design decisions:**
- **Private EKS endpoint**: No public API server access (STIG network segmentation)
- **Dedicated node group**: Kong pods run on `security-zone=api-gateway` tainted nodes
- **NLB ingress**: AWS NLB terminates TLS or passes through to Kong proxy
- **IRSA**: Kong pods access AWS Secrets Manager via IAM Roles for Service Accounts

---

## 2. Network Flow

```
Internet Client
       │
       ▼
┌──────────────┐
│   AWS NLB    │  (TLS 443)
│   (public)   │
└──────┬───────┘
       │
       ▼
┌──────────────┐     ┌─────────────┐
│  Kong Proxy  │────▶│  Upstream   │
│  (port 8443) │     │  Services   │
│              │     └─────────────┘
│  Plugins:    │
│  - OIDC      │
│  - ACL       │
│  - Rate Limit│
│  - Headers   │
│  - Logging   │
└──────┬───────┘
       │
       ├──────▶ Keycloak (AuthZ Code + PKCE flow)
       │
       └──────▶ Elasticsearch (_bulk API)
```

**NetworkPolicy rules** (default-deny + explicit allows):
| Source | Destination | Port | Policy |
|--------|-------------|------|--------|
| NLB / Ingress Controller | Kong Proxy | 8443/TCP | `kong-proxy-ingress` |
| Kong Proxy | Keycloak | 8443/TCP | `kong-egress-keycloak` |
| Kong Proxy | Elasticsearch | 9200/TCP | `kong-egress-elastic` |
| Kong Proxy | Upstream services | 443,8080,8443/TCP | `kong-egress-upstream` |
| All Kong pods | kube-dns | 53/UDP,TCP | `kong-egress-dns` |
| Kong CP ↔ DP | Kong CP ↔ DP | 8005,8444/TCP | `kong-internal` |

---

## 3. Authentication Flow

```
┌────────┐     ┌───────────┐     ┌───────────┐
│ Browser │     │   Kong    │     │ Keycloak  │
│ Client  │     │  Proxy    │     │   IdP     │
└────┬───┘     └─────┬─────┘     └─────┬─────┘
     │               │                 │
     │  GET /app     │                 │
     │──────────────▶│                 │
     │               │                 │
     │  302 → Keycloak authorize       │
     │  (+ PKCE code_challenge)        │
     │◀──────────────│                 │
     │               │                 │
     │  GET /realms/.../authorize      │
     │────────────────────────────────▶│
     │               │                 │
     │  Login form   │                 │
     │◀────────────────────────────────│
     │               │                 │
     │  POST credentials               │
     │────────────────────────────────▶│
     │               │                 │
     │  302 → /auth/callback?code=...  │
     │◀────────────────────────────────│
     │               │                 │
     │  GET /auth/callback?code=...    │
     │──────────────▶│                 │
     │               │                 │
     │               │  POST /token    │
     │               │  (code + PKCE   │
     │               │   verifier)     │
     │               │────────────────▶│
     │               │                 │
     │               │  id_token +     │
     │               │  access_token   │
     │               │◀────────────────│
     │               │                 │
     │  Set-Cookie: kong_oidc_session  │
     │  302 → /app   │                 │
     │◀──────────────│                 │
     │               │                 │
     │  GET /app     │                 │
     │  Cookie: ...  │                 │
     │──────────────▶│                 │
     │               │                 │
     │  Validates session, sets        │
     │  X-OIDC-Sub, X-OIDC-Username   │
     │  → proxies to upstream          │
     │               │                 │
```

**Bearer token flow** (API-to-API):
```
Service A ──Bearer token──▶ Kong Proxy ──introspect──▶ Keycloak
                                 │
                                 ▼ (if active)
                            Upstream Service
```

---

## 4. Logging Flow

```
┌───────────┐                   ┌───────────────┐
│Kong Proxy │──log() phase──▶   │elastic-logger │
│  request  │                   │   plugin      │
└───────────┘                   └───────┬───────┘
                                        │
                                  Queue batching
                                        │
                                        ▼
                                ┌───────────────┐
                                │ Elasticsearch  │
                                │  _bulk API     │
                                │  (ECS format)  │
                                └───────┬───────┘
                                        │
                                ┌───────┴───────┐
                                │    Kibana      │
                                │  Dashboards    │
                                │  • Request rate│
                                │  • Latency P99 │
                                │  • Error rates │
                                │  • Auth metrics│
                                │  • Top routes  │
                                └───────────────┘
                                        │
                                ┌───────┴───────┐
                                │   Alerting     │
                                │  • 5xx spike   │
                                │  • Auth fails  │
                                │  • Latency     │
                                │  • Pod restart │
                                └───────────────┘
```

**Log data lifecycle** (ILM policy):
| Phase | Age | Action |
|-------|-----|--------|
| Hot | 0-7 days | Active indexing, rollover at 50 GB |
| Warm | 7-30 days | Shrink to 1 shard, force merge |
| Cold | 30-90 days | Read-only, cold tier allocation |
| Frozen | 90-365 days | Searchable snapshot |
| Delete | 365+ days | Purge (configurable per retention policy) |

---

## 5. Secret Management Flow

```
┌───────────────────┐
│  AWS Secrets      │
│  Manager          │
│  • TLS cert/key   │
│  • OIDC client    │
│  •   secret       │
│  • Elastic API key│
└────────┬──────────┘
         │
         │ IRSA (IAM Role for
         │ Service Accounts)
         │
         ▼
┌────────────────────┐
│  Kong Pod          │
│  (ServiceAccount   │
│   with IRSA)       │
│                    │
│  KONG_SSL_CERT ──────▶ /etc/secrets/tls/tls.crt
│  KONG_SSL_CERT_KEY ──▶ /etc/secrets/tls/tls.key
│                    │
│  {vault://aws/...} │  ← Kong vault backend resolves
│  client_secret     │    secrets at runtime
│  session_secret    │
│  elastic_api_key   │
└────────────────────┘
```

**Security properties:**
- Secrets never stored in Git or ConfigMaps
- TLS certificates managed by ACM + Kubernetes secrets
- Plugin secrets use Kong's vault reference syntax
- KMS envelope encryption for Kubernetes secrets at rest
- IRSA scoped to minimum required Secrets Manager actions

---

## 6. CI/CD Pipeline

```
Developer Push / Tag
       │
       ▼
┌──────────────────────────────────────────────┐
│  GitHub Actions                               │
│                                               │
│  security-scan.yml         build-and-push.yml │
│  ├─ SAST (luacheck,       ├─ Build image      │
│  │  semgrep)               │  (Dockerfile.     │
│  ├─ IaC lint (checkov,    │   federal)         │
│  │  kube-linter, tfsec)   ├─ Trivy scan       │
│  ├─ CVE scan (trivy,      ├─ Push to ECR      │
│  │  grype)                 ├─ Sign with cosign │
│  ├─ SBOM (syft)           └─ Trigger scan     │
│  ├─ Secrets (gitleaks)                        │
│  └─ DAST (ZAP, manual)                       │
└──────────────────────────────────────────────┘
```
