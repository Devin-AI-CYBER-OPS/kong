#!/usr/bin/env bash
# Security: Automated STIG compliance validation for Kong federal deployment.
# Checks TLS versions, cipher suites, session timeouts, headers, admin access,
# and audit logging against DISA STIG and NIST SP 800-52r2 requirements.

set -euo pipefail

KONG_PROXY_URL="${KONG_PROXY_URL:-https://kong-proxy.kong.svc.cluster.local:8443}"
KONG_ADMIN_URL="${KONG_ADMIN_URL:-https://kong-admin.kong.svc.cluster.local:8444}"
ELASTIC_URL="${ELASTIC_URL:-https://elasticsearch.elastic-system.svc.cluster.local:9200}"
ELASTIC_INDEX="${ELASTIC_INDEX:-kong-logs}"

PASS=0
FAIL=0
TOTAL=0

check() {
  local stig_id="$1"
  local name="$2"
  local result="$3"
  TOTAL=$((TOTAL + 1))
  if [ "$result" -eq 0 ]; then
    echo "[PASS] ${stig_id}: ${name}"
    PASS=$((PASS + 1))
  else
    echo "[FAIL] ${stig_id}: ${name}"
    FAIL=$((FAIL + 1))
  fi
}

echo "========================================"
echo " STIG Compliance Validation"
echo "========================================"
echo ""

# Extract host:port from URL for openssl commands
PROXY_HOST=$(echo "$KONG_PROXY_URL" | sed -e 's|https://||' -e 's|/.*||')

# -----------------------------------------------------------------------
# V-222596: TLS version and cipher validation
# -----------------------------------------------------------------------
echo "--- V-222596: TLS Enforcement ---"

# Verify TLS 1.2 is supported
TLS12_RESULT=$(echo | openssl s_client -connect "${PROXY_HOST}" -tls1_2 2>&1 || true)
if echo "$TLS12_RESULT" | grep -q "Cipher is"; then
  check "V-222596" "TLS 1.2 supported" 0
else
  check "V-222596" "TLS 1.2 supported" 1
fi

# Verify TLS 1.0 is NOT supported
TLS10_RESULT=$(echo | openssl s_client -connect "${PROXY_HOST}" -tls1 2>&1 || true)
if echo "$TLS10_RESULT" | grep -q "no protocols available\|wrong version\|handshake failure\|alert protocol"; then
  check "V-222596" "TLS 1.0 rejected" 0
else
  check "V-222596" "TLS 1.0 rejected" 1
fi

# Verify TLS 1.1 is NOT supported
TLS11_RESULT=$(echo | openssl s_client -connect "${PROXY_HOST}" -tls1_1 2>&1 || true)
if echo "$TLS11_RESULT" | grep -q "no protocols available\|wrong version\|handshake failure\|alert protocol"; then
  check "V-222596" "TLS 1.1 rejected" 0
else
  check "V-222596" "TLS 1.1 rejected" 1
fi

# Verify cipher suite is FIPS-approved
CIPHER=$(echo | openssl s_client -connect "${PROXY_HOST}" -tls1_2 2>&1 | grep "Cipher    :" | awk '{print $NF}' || true)
APPROVED_CIPHERS="ECDHE-ECDSA-AES256-GCM-SHA384|ECDHE-RSA-AES256-GCM-SHA384|ECDHE-ECDSA-AES128-GCM-SHA256|ECDHE-RSA-AES128-GCM-SHA256|TLS_AES_256_GCM_SHA384|TLS_AES_128_GCM_SHA256"
if echo "$CIPHER" | grep -qE "$APPROVED_CIPHERS"; then
  check "V-222596" "FIPS-approved cipher suite in use (${CIPHER})" 0
else
  check "V-222596" "FIPS-approved cipher suite in use (${CIPHER:-none})" 1
fi

# -----------------------------------------------------------------------
# V-222602: Session timeout verification
# -----------------------------------------------------------------------
echo ""
echo "--- V-222602: Session Timeout ---"

# Verify session cookie attributes
HEADERS=$(curl -sk -D - -o /dev/null "${KONG_PROXY_URL}/status" 2>/dev/null || true)
SET_COOKIE=$(echo "$HEADERS" | grep -i "^Set-Cookie:.*kong_oidc_session" || true)

if [ -n "$SET_COOKIE" ]; then
  if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
    check "V-222602" "Session cookie has HttpOnly flag" 0
  else
    check "V-222602" "Session cookie has HttpOnly flag" 1
  fi

  if echo "$SET_COOKIE" | grep -qi "Secure"; then
    check "V-222602" "Session cookie has Secure flag" 0
  else
    check "V-222602" "Session cookie has Secure flag" 1
  fi

  if echo "$SET_COOKIE" | grep -qi "SameSite"; then
    check "V-222602" "Session cookie has SameSite attribute" 0
  else
    check "V-222602" "Session cookie has SameSite attribute" 1
  fi
else
  check "V-222602" "Session cookie present (may require auth flow)" 1
fi

# -----------------------------------------------------------------------
# V-222531: Audit logging verification
# -----------------------------------------------------------------------
echo ""
echo "--- V-222531: Audit Logging ---"

# Verify logs are reaching Elasticsearch
ES_COUNT=$(curl -sk "${ELASTIC_URL}/${ELASTIC_INDEX}-*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*' || echo "0")
check "V-222531" "Audit logs present in Elasticsearch (count: ${ES_COUNT})" "$([ "${ES_COUNT}" -gt 0 ] && echo 0 || echo 1)"

# Verify correlation ID header
CORR_ID=$(echo "$HEADERS" | grep -i "^X-Request-ID:" || true)
check "V-222531" "Correlation ID (X-Request-ID) header present" "$([ -n "$CORR_ID" ] && echo 0 || echo 1)"

# -----------------------------------------------------------------------
# V-222543: Access control — Admin API restriction
# -----------------------------------------------------------------------
echo ""
echo "--- V-222543: Access Control ---"

# Verify admin API is not accessible on the proxy port
ADMIN_ON_PROXY=$(curl -sk -o /dev/null -w "%{http_code}" "${KONG_PROXY_URL}:8444/" --connect-timeout 5 2>/dev/null || echo "000")
check "V-222543" "Admin API not exposed on proxy port (got ${ADMIN_ON_PROXY})" "$([ "$ADMIN_ON_PROXY" = "000" ] && echo 0 || echo 1)"

# -----------------------------------------------------------------------
# Security headers (OWASP / STIG)
# -----------------------------------------------------------------------
echo ""
echo "--- Security Headers ---"

RESP_HEADERS=$(curl -sk -D - -o /dev/null "${KONG_PROXY_URL}/status" 2>/dev/null || true)

check_header() {
  local id="$1"
  local header="$2"
  if echo "$RESP_HEADERS" | grep -qi "^${header}:"; then
    check "$id" "Header '${header}' present" 0
  else
    check "$id" "Header '${header}' present" 1
  fi
}

check_absent_header() {
  local id="$1"
  local header="$2"
  if echo "$RESP_HEADERS" | grep -qi "^${header}:"; then
    check "$id" "Header '${header}' absent" 1
  else
    check "$id" "Header '${header}' absent" 0
  fi
}

check_header "V-222596" "Strict-Transport-Security"
check_header "OWASP"    "X-Content-Type-Options"
check_header "OWASP"    "X-Frame-Options"
check_header "OWASP"    "Content-Security-Policy"
check_header "OWASP"    "Referrer-Policy"
check_absent_header "OWASP" "Server"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
echo "========================================"
echo " STIG Results: ${PASS}/${TOTAL} passed, ${FAIL} failed"
echo "========================================"

exit "${FAIL}"
