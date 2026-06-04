# Kong Federal EKS Deployment

Infrastructure-as-code for deploying Kong API Gateway on AWS EKS with Keycloak IdP integration, DISA STIG / OWASP compliance, security scanning pipelines, and Elastic observability.

---

## Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| AWS EKS | 1.31+ | Kubernetes cluster |
| Terraform | ≥ 1.5 | Infrastructure provisioning |
| Helm | ≥ 3.14 | Kong and Keycloak chart deployment |
| kubectl | ≥ 1.31 | Cluster management |
| Kustomize | ≥ 5.0 | Environment overlay management |
| Iron Bank registry access | — | DoD-hardened container images |
| Keycloak | 26+ | Identity Provider (OIDC) |
| Elasticsearch | 8.17+ | Log storage and analytics |
| Kibana | 8.17+ | Dashboards and visualization |

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed diagrams covering:
- EKS cluster topology
- Authentication flow (Kong ↔ Keycloak)
- Log shipping pipeline (Kong → Elastic)
- Secret management flow (AWS Secrets Manager → K8s → Kong)

## Quick Start

### 1. Provision EKS Cluster

```bash
cd deploy/terraform/eks-kong
terraform init
terraform plan -var-file=envs/prod.tfvars
terraform apply -var-file=envs/prod.tfvars
```

### 2. Deploy Keycloak

```bash
# Create the realm import ConfigMap
kubectl create configmap keycloak-realm-import \
  --from-file=realm.json=deploy/keycloak-integration/keycloak-realm-export.json \
  -n keycloak

# Deploy Keycloak via Helm
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install keycloak bitnami/keycloak \
  -f deploy/helm/values-keycloak.yaml \
  -n keycloak --create-namespace
```

### 3. Deploy Kong

```bash
# Create TLS secret
kubectl create secret tls kong-tls-cert \
  --cert=path/to/tls.crt --key=path/to/tls.key \
  -n kong

# Deploy Kong via Helm with federal values
helm repo add kong https://charts.konghq.com
helm install kong kong/kong \
  -f deploy/helm/values-eks-federal.yaml \
  -n kong --create-namespace

# Apply Kustomize overlays for your environment
kubectl apply -k deploy/kustomize/overlays/prod/
```

### 4. Apply Security Hardening

```bash
# Apply STIG hardening declarative config
kubectl create configmap kong-dbless \
  --from-file=kong.yml=deploy/security/stig-hardening.yaml \
  -n kong

# Apply network policies
kubectl apply -f deploy/security/network-policies.yaml
```

### 5. Configure OIDC Plugin

```bash
# Merge OIDC config into the declarative config
# Replace <keycloak-host> in kong-oidc-plugin-config.yaml first
kubectl create configmap kong-oidc-config \
  --from-file=kong.yml=deploy/keycloak-integration/kong-oidc-plugin-config.yaml \
  -n kong
```

### 6. Deploy Monitoring

```bash
# Deploy Elastic Agent
kubectl apply -f deploy/monitoring/elastic-agent-daemonset.yaml

# Apply ILM policy
curl -XPUT "${ELASTIC_URL}/_ilm/policy/kong-log-retention" \
  -H 'Content-Type: application/json' \
  -d @deploy/monitoring/elastic-ilm-policy.json

# Import Kibana dashboard
curl -XPOST "${KIBANA_URL}/api/saved_objects/_import" \
  -H 'kbn-xsrf: true' \
  --form file=@deploy/monitoring/kibana-dashboards/kong-overview.ndjson
```

### 7. Run Validation

```bash
chmod +x deploy/tests/*.sh
./deploy/tests/smoke-test.sh
./deploy/tests/stig-validation.sh
```

## Configuration Customization

### Environment-specific overrides

Use Kustomize overlays for per-environment tuning:

| Environment | Replicas | HPA Max | PDB MinAvailable |
|-------------|----------|---------|------------------|
| dev         | 1        | 3       | 0                |
| staging     | 2        | 6       | 1                |
| prod        | 3        | 20      | 2                |

### Custom plugins

Two custom plugins are included:
- **keycloak-oidc**: OIDC Authorization Code + PKCE flow with Keycloak, session management, bearer token introspection
- **elastic-logger**: Elasticsearch bulk log shipping with ECS mapping and queue-based batching

Register custom plugins via the `KONG_PLUGINS` environment variable:
```
KONG_PLUGINS=bundled,keycloak-oidc,elastic-logger
```

### Vault references

All secrets use Kong vault references (`{vault://aws/...}`) for runtime resolution. Configure the AWS vault backend in Kong:
```yaml
env:
  vault_aws_region: us-gov-west-1
```

## Security Compliance

| Framework | Reference | Status |
|-----------|-----------|--------|
| DISA STIG | See `deploy/security/stig-checklist.md` | Mapped |
| OWASP API Top 10 | See `deploy/security/owasp-api-top10.yaml` | Mitigated |
| NIST SP 800-53 | SC-7, SC-8, SC-13, AU-2, AU-3 | Implemented |
| CIS Kubernetes | Pod Security Standards (restricted) | Enforced |

## Troubleshooting

### Kong pods not starting
- Check TLS secret exists: `kubectl get secret kong-tls-cert -n kong`
- Verify Iron Bank registry credentials: `kubectl get secret registry1-credentials -n kong`
- Check pod events: `kubectl describe pod -l app.kubernetes.io/name=kong -n kong`

### OIDC redirect loop
- Verify Keycloak discovery URL is reachable from Kong pods
- Check `redirect_uri_path` matches Keycloak client `Valid Redirect URIs`
- Verify NetworkPolicy allows egress to Keycloak namespace

### Logs not appearing in Elasticsearch
- Check elastic-logger plugin is enabled: `curl -sk ${ADMIN_URL}/plugins`
- Verify NetworkPolicy allows egress to Elasticsearch
- Check Elastic Agent / Filebeat pod logs for connection errors

### Rate limiting not working
- Verify rate-limiting plugin is loaded globally
- Check `KONG_PLUGINS` includes `bundled`
- Review plugin ordering via `curl -sk ${ADMIN_URL}/plugins`
