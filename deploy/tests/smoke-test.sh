#!/usr/bin/env bash
# Security: Post-deployment smoke test for Kong federal EKS deployment.
# Validates proxy, admin API, OIDC flow, security headers, rate limiting, and logging.
# References: NIST SP 800-53 CA-8 (Penetration Testing), STIG validation

set -euo pipefail

# -- Configuration (override via environment variables) --
KONG_PROXY_URL="${KONG_PROXY_URL:-https://kong-proxy.kong.svc.cluster.local:8443}"
KONG_ADMIN_URL="${KONG_ADMIN_URL:-https://kong-admin.kong.svc.cluster.local:8444}"
KEYCLOAK_URL="${KEYCLOAK_URL:-https://keycloak.keycloak.svc.cluster.local:8443}"
ELASTIC_URL="${ELASTIC_URL:-https://elasticsearch.elastic-system.svc.cluster.local:9200}"
ELASTIC_INDEX="${ELASTIC_INDEX:-kong-logs}"

PASS=0
FAIL=0
TOTAL=0

check() {
  local name="$1"
  local result="$2"
  TOTAL=$((TOTAL + 1))
  if [ "$result" -eq 0 ]; then
    echo "[PASS] $name"
    PASS=$((PASS + 1))
  else
    echo "[FAIL] $name"
    FAIL=$((FAIL + 1))
  fi
}

echo "========================================"
echo " Kong Federal EKS Smoke Test"
echo "========================================"
echo ""

# -- 1. Kong proxy responds on HTTPS --
echo "--- Proxy Availability ---"
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${KONG_PROXY_URL}/status" 2>/dev/null || echo "000")
check "Kong proxy HTTPS responds (got ${HTTP_CODE})" "$([ "$HTTP_CODE" != "000" ] && echo 0 || echo 1)"

# -- 2. Admin API internal access --
echo ""
echo "--- Admin API Access ---"
ADMIN_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${KONG_ADMIN_URL}/" 2>/dev/null || echo "000")
check "Admin API accessible internally (got ${ADMIN_CODE})" "$([ "$ADMIN_CODE" = "200" ] || [ "$ADMIN_CODE" = "401" ] && echo 0 || echo 1)"

# Verify admin API is NOT exposed externally (assumes KONG_EXTERNAL_URL is set for external LB)
if [ -n "${KONG_EXTERNAL_URL:-}" ]; then
  EXT_ADMIN_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${KONG_EXTERNAL_URL}:8444/" --connect-timeout 5 2>/dev/null || echo "000")
  check "Admin API NOT exposed externally (got ${EXT_ADMIN_CODE})" "$([ "$EXT_ADMIN_CODE" = "000" ] || [ "$EXT_ADMIN_CODE" = "403" ] && echo 0 || echo 1)"
fi

# -- 3. OIDC Keycloak flow --
echo ""
echo "--- OIDC / Keycloak ---"
OIDC_DISCOVERY="${KEYCLOAK_URL}/realms/kong-federation/.well-known/openid-configuration"
DISCOVERY_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${OIDC_DISCOVERY}" 2>/dev/null || echo "000")
check "Keycloak OIDC discovery endpoint reachable (got ${DISCOVERY_CODE})" "$([ "$DISCOVERY_CODE" = "200" ] && echo 0 || echo 1)"

# Verify unauthenticated request gets 302 redirect to Keycloak
UNAUTH_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${KONG_PROXY_URL}/any-protected-route" 2>/dev/null || echo "000")
check "Unauthenticated request redirects to Keycloak (got ${UNAUTH_CODE})" "$([ "$UNAUTH_CODE" = "302" ] && echo 0 || echo 1)"

# -- 4. Security headers --
echo ""
echo "--- Security Headers ---"
HEADERS=$(curl -sk -D - -o /dev/null "${KONG_PROXY_URL}/status" 2>/dev/null || true)

check_header() {
  local header_name="$1"
  local expected_value="$2"
  if echo "$HEADERS" | grep -qi "^${header_name}:.*${expected_value}"; then
    check "Header '${header_name}' contains '${expected_value}'" 0
  else
    check "Header '${header_name}' contains '${expected_value}'" 1
  fi
}

check_header "Strict-Transport-Security" "max-age=63072000"
check_header "X-Content-Type-Options" "nosniff"
check_header "X-Frame-Options" "DENY"
check_header "Content-Security-Policy" "default-src"
check_header "Referrer-Policy" "strict-origin-when-cross-origin"

# Verify Server header is removed
if echo "$HEADERS" | grep -qi "^Server:"; then
  check "Server header removed" 1
else
  check "Server header removed" 0
fi

# -- 5. Rate limiting --
echo ""
echo "--- Rate Limiting ---"
RATE_LIMIT_HEADER=$(echo "$HEADERS" | grep -i "^RateLimit-Limit:" || true)
if [ -n "$RATE_LIMIT_HEADER" ]; then
  check "Rate limiting headers present" 0
else
  # Try triggering rate limit
  for i in $(seq 1 5); do
    curl -sk -o /dev/null "${KONG_PROXY_URL}/status" 2>/dev/null || true
  done
  HEADERS2=$(curl -sk -D - -o /dev/null "${KONG_PROXY_URL}/status" 2>/dev/null || true)
  RATE_LIMIT_HEADER2=$(echo "$HEADERS2" | grep -i "^RateLimit" || true)
  check "Rate limiting headers present" "$([ -n "$RATE_LIMIT_HEADER2" ] && echo 0 || echo 1)"
fi

# -- 6. Elasticsearch log delivery --
echo ""
echo "--- Elasticsearch Log Delivery ---"
sleep 5  # Allow time for log shipping
ES_COUNT=$(curl -sk "${ELASTIC_URL}/${ELASTIC_INDEX}-*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*' || echo "0")
check "Logs present in Elasticsearch (count: ${ES_COUNT})" "$([ "${ES_COUNT}" -gt 0 ] && echo 0 || echo 1)"

# -- Summary --
echo ""
echo "========================================"
echo " Results: ${PASS}/${TOTAL} passed, ${FAIL} failed"
echo "========================================"

exit "${FAIL}"
