# STIG Compliance Checklist — Kong API Gateway

This document maps Kong configurations to specific DISA STIG controls and NIST SP 800-53 security requirements. Each control references the configuration file and setting that implements it.

---

## Session Management

| STIG ID | Title | Implementation | Config Reference |
|---------|-------|---------------|------------------|
| V-222602 | Session timeout must not exceed 15 minutes idle | `session_lifetime: 900` | `deploy/keycloak-integration/kong-oidc-plugin-config.yaml` |
| V-222602 | Absolute session timeout ≤ 8 hours | `session_absolute_timeout: 28800` | `deploy/keycloak-integration/kong-oidc-plugin-config.yaml` |
| V-222602 | Session cookies HttpOnly + Secure + SameSite | Hardcoded in `handler.lua` cookie attributes | `kong/plugins/keycloak-oidc/handler.lua` |

## Transport Layer Security

| STIG ID | Title | Implementation | Config Reference |
|---------|-------|---------------|------------------|
| V-222596 | TLS 1.2 minimum enforcement | `ssl_protocols: "TLSv1.2 TLSv1.3"` | `deploy/helm/values-eks-federal.yaml` |
| V-222596 | FIPS-approved cipher suites only | `ssl_ciphers` limited to AES-GCM + ECDHE | `deploy/helm/values-eks-federal.yaml` |
| V-222596 | HSTS header with preload | `Strict-Transport-Security` header via response-transformer | `deploy/security/stig-hardening.yaml` |
| V-222596 | No plaintext HTTP listeners | `proxy.http.enabled: false`, `admin.http.enabled: false` | `deploy/helm/values-eks-federal.yaml` |

## Audit Logging

| STIG ID | Title | Implementation | Config Reference |
|---------|-------|---------------|------------------|
| V-222531 | Audit logging of access events | elastic-logger plugin ships all access logs to Elasticsearch | `kong/plugins/elastic-logger/` |
| V-222531 | Correlation IDs for traceability | correlation-id plugin adds `X-Request-ID` | `deploy/security/stig-hardening.yaml` |
| V-222531 | Authenticated user identity in logs | OIDC `sub`, `username`, `email` headers propagated to logs | `kong/plugins/keycloak-oidc/handler.lua` |

## Access Control

| STIG ID | Title | Implementation | Config Reference |
|---------|-------|---------------|------------------|
| V-222543 | Access control enforcement | ACL plugin + keycloak-oidc plugin | `deploy/security/owasp-api-top10.yaml` |
| V-222543 | Admin API restricted to internal access | Admin service type: ClusterIP, TLS only | `deploy/helm/values-eks-federal.yaml` |
| V-222543 | Role-based access control | Keycloak realm roles mapped to consumer headers | `deploy/keycloak-integration/keycloak-realm-export.json` |
| V-222543 | Network segmentation | Kubernetes NetworkPolicy default-deny + explicit allows | `deploy/security/network-policies.yaml` |

## Authentication

| STIG ID | Title | Implementation | Config Reference |
|---------|-------|---------------|------------------|
| V-222540 | Multi-factor authentication support | Keycloak realm requires TOTP as optional action | `deploy/keycloak-integration/keycloak-realm-export.json` |
| V-222540 | PKCE enforcement for authorization code flow | `pkce: "strict"` in OIDC plugin config | `deploy/keycloak-integration/kong-oidc-plugin-config.yaml` |
| V-222540 | Password complexity requirements | Keycloak `passwordPolicy` enforces length(14)+complexity | `deploy/keycloak-integration/keycloak-realm-export.json` |
| V-222540 | Brute force protection | Keycloak `bruteForceProtected: true`, `failureFactor: 5` | `deploy/keycloak-integration/keycloak-realm-export.json` |

## Container & Pod Security

| STIG ID / CIS | Title | Implementation | Config Reference |
|---------------|-------|---------------|------------------|
| CIS 5.2.1 | Pods run as non-root | `runAsNonRoot: true`, `runAsUser: 1000` | `deploy/helm/values-eks-federal.yaml` |
| CIS 5.2.2 | Read-only root filesystem | `readOnlyRootFilesystem: true` | `deploy/helm/values-eks-federal.yaml` |
| CIS 5.2.3 | No privilege escalation | `allowPrivilegeEscalation: false` | `deploy/helm/values-eks-federal.yaml` |
| CIS 5.2.4 | All capabilities dropped | `capabilities.drop: [ALL]` | `deploy/helm/values-eks-federal.yaml` |
| CIS 5.2.5 | Seccomp profile enforced | `seccompProfile.type: RuntimeDefault` | `deploy/helm/values-eks-federal.yaml` |
| CIS 5.2.6 | Pod Security Standards (restricted) | Namespace label `pod-security.kubernetes.io/enforce: restricted` | `deploy/terraform/eks-kong/main.tf` |

## Secrets Management

| Control | Title | Implementation | Config Reference |
|---------|-------|---------------|------------------|
| NIST SC-28 | Encryption at rest for secrets | AWS KMS encryption on EKS secrets + Secrets Manager | `deploy/terraform/eks-kong/main.tf` |
| NIST SC-28 | No hardcoded secrets | Vault references (`{vault://aws/...}`) in Kong config | `deploy/keycloak-integration/kong-oidc-plugin-config.yaml` |
| NIST SC-28 | IRSA for AWS API access | Service account annotated with IAM role ARN | `deploy/helm/values-eks-federal.yaml` |

## Network Security

| STIG ID | Title | Implementation | Config Reference |
|---------|-------|---------------|------------------|
| V-222544 | Default-deny network policy | NetworkPolicy with empty podSelector, Ingress + Egress denied | `deploy/security/network-policies.yaml` |
| V-222544 | Egress restricted to known endpoints | Explicit egress rules for Keycloak, Elastic, upstream, DNS only | `deploy/security/network-policies.yaml` |
| V-222544 | EKS private endpoint only | `cluster_endpoint_public_access: false` | `deploy/terraform/eks-kong/main.tf` |

---

## Validation

Run automated STIG compliance checks:
```bash
./deploy/tests/stig-validation.sh
```

Run the full smoke test suite:
```bash
./deploy/tests/smoke-test.sh
```
