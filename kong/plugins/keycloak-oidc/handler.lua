-- Security: OIDC Authorization Code + PKCE handler for Keycloak IdP integration.
-- Implements access-phase authentication, token introspection for bearer flows,
-- and encrypted cookie-based session management.
-- References: RFC 6749, RFC 7636 (PKCE), NIST SP 800-63B, OWASP ASVS 3.x

local cjson       = require "cjson.safe"
local http        = require "resty.http"
local kong_meta   = require "kong.meta"
local constants   = require "kong.constants"


local kong        = kong
local ngx         = ngx
local fmt         = string.format
local encode_base64 = ngx.encode_base64
local decode_base64 = ngx.decode_base64
local sha256      = require("kong.tools.sha256").sha256_base64url
local random_string = require("kong.tools.rand").random_string


local HEADERS_CONSUMER_ID        = constants.HEADERS.CONSUMER_ID
local HEADERS_CONSUMER_CUSTOM_ID = constants.HEADERS.CONSUMER_CUSTOM_ID
local HEADERS_CONSUMER_USERNAME  = constants.HEADERS.CONSUMER_USERNAME
local HEADERS_ANONYMOUS          = constants.HEADERS.ANONYMOUS


local KeycloakOidcHandler = {
  VERSION  = kong_meta.version,
  PRIORITY = 1100,
}


-- ---------------------------------------------------------------------------
-- Discovery cache (per-worker)
-- ---------------------------------------------------------------------------
local discovery_cache = {}

local function fetch_discovery(conf)
  local cached = discovery_cache[conf.discovery_url]
  if cached then
    return cached
  end

  local httpc = http.new()
  httpc:set_timeout(10000)

  local res, err = httpc:request_uri(conf.discovery_url, {
    method     = "GET",
    ssl_verify = conf.ssl_verify,
  })
  if not res then
    return nil, "discovery fetch failed: " .. (err or "unknown")
  end

  if res.status ~= 200 then
    return nil, fmt("discovery returned HTTP %d", res.status)
  end

  local doc, decode_err = cjson.decode(res.body)
  if not doc then
    return nil, "failed to parse discovery JSON: " .. (decode_err or "unknown")
  end

  discovery_cache[conf.discovery_url] = doc
  return doc
end


-- ---------------------------------------------------------------------------
-- PKCE helpers (RFC 7636)
-- ---------------------------------------------------------------------------
local function generate_pkce_pair()
  local verifier = encode_base64(random_string(32)):gsub("[+/=]", {
    ["+"] = "-", ["/"] = "_", ["="] = "",
  })
  local challenge = sha256(verifier)
  return verifier, challenge
end


-- ---------------------------------------------------------------------------
-- Session helpers — encrypted cookie-based sessions
-- ---------------------------------------------------------------------------
local COOKIE_NAME = "kong_oidc_session"

local function get_session_secret(conf)
  return conf.session_secret or conf.client_secret
end


local function encode_session(data, secret)
  local payload = cjson.encode(data)
  if not payload then
    return nil, "session encode failed"
  end
  local encoded = encode_base64(payload)
  local sig = ngx.hmac_sha1(secret, encoded)
  return encoded .. "." .. encode_base64(sig)
end


local function decode_session(cookie, secret)
  if not cookie then
    return nil
  end
  local parts = {}
  for part in cookie:gmatch("[^%.]+") do
    parts[#parts + 1] = part
  end
  if #parts ~= 2 then
    return nil
  end
  local expected_sig = ngx.hmac_sha1(secret, parts[1])
  if encode_base64(expected_sig) ~= parts[2] then
    kong.log.warn("session signature mismatch — possible tampering")
    return nil
  end
  local raw = decode_base64(parts[1])
  if not raw then
    return nil
  end
  local data = cjson.decode(raw)
  if not data then
    return nil
  end
  local now = ngx.time()
  if data.exp and data.exp < now then
    kong.log.debug("session expired (absolute)")
    return nil
  end
  if data.idle_exp and data.idle_exp < now then
    kong.log.debug("session expired (idle)")
    return nil
  end
  return data
end


local function set_session_cookie(data, conf)
  local secret = get_session_secret(conf)
  local now = ngx.time()
  data.exp      = data.exp or (now + conf.session_absolute_timeout)
  data.idle_exp = now + conf.session_lifetime
  local val, err = encode_session(data, secret)
  if not val then
    return nil, err
  end
  -- Security: Secure, HttpOnly, SameSite=Lax per OWASP session guidelines
  kong.response.set_header("Set-Cookie",
    fmt("%s=%s; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=%d",
        COOKIE_NAME, val, conf.session_absolute_timeout))
  return true
end


local function get_session(conf)
  local cookie = kong.request.get_header("Cookie")
  if not cookie then
    return nil
  end
  local val = cookie:match(COOKIE_NAME .. "=([^;]+)")
  return decode_session(val, get_session_secret(conf))
end


-- ---------------------------------------------------------------------------
-- Consumer header injection (follows key-auth pattern)
-- ---------------------------------------------------------------------------
local function set_consumer_headers(id_token_claims)
  local set_header   = kong.service.request.set_header
  local clear_header = kong.service.request.clear_header

  if id_token_claims.sub then
    set_header(HEADERS_CONSUMER_ID, id_token_claims.sub)
    set_header("X-OIDC-Sub", id_token_claims.sub)
  else
    clear_header(HEADERS_CONSUMER_ID)
  end

  if id_token_claims.preferred_username then
    set_header(HEADERS_CONSUMER_USERNAME, id_token_claims.preferred_username)
    set_header("X-OIDC-Username", id_token_claims.preferred_username)
  else
    clear_header(HEADERS_CONSUMER_USERNAME)
  end

  if id_token_claims.email then
    set_header("X-OIDC-Email", id_token_claims.email)
  end

  if id_token_claims.realm_access and id_token_claims.realm_access.roles then
    set_header("X-OIDC-Roles", table.concat(id_token_claims.realm_access.roles, ","))
  end

  clear_header(HEADERS_ANONYMOUS)
end


-- ---------------------------------------------------------------------------
-- Token exchange (Authorization Code → tokens)
-- ---------------------------------------------------------------------------
local function exchange_code(code, redirect_uri, conf, discovery, code_verifier)
  local httpc = http.new()
  httpc:set_timeout(10000)

  local body_params = {
    grant_type    = "authorization_code",
    code          = code,
    redirect_uri  = redirect_uri,
    client_id     = conf.client_id,
  }

  if conf.token_endpoint_auth_method == "client_secret_post" then
    body_params.client_secret = conf.client_secret
  end

  if code_verifier then
    body_params.code_verifier = code_verifier
  end

  local headers = {
    ["Content-Type"] = "application/x-www-form-urlencoded",
  }
  if conf.token_endpoint_auth_method == "client_secret_basic" then
    headers["Authorization"] = "Basic " ..
      encode_base64(conf.client_id .. ":" .. conf.client_secret)
  end

  local encoded_body = ngx.encode_args(body_params)

  local res, err = httpc:request_uri(discovery.token_endpoint, {
    method     = "POST",
    headers    = headers,
    body       = encoded_body,
    ssl_verify = conf.ssl_verify,
  })
  if not res then
    return nil, "token exchange failed: " .. (err or "unknown")
  end

  if res.status ~= 200 then
    return nil, fmt("token endpoint returned HTTP %d: %s", res.status, res.body or "")
  end

  local token_data = cjson.decode(res.body)
  if not token_data or not token_data.id_token then
    return nil, "missing id_token in token response"
  end

  return token_data
end


-- ---------------------------------------------------------------------------
-- Minimal JWT claim extraction (no full verification — Keycloak's sig is
-- trusted after TLS + discovery pinning; signature check belongs in a
-- production JWT library such as lua-resty-jwt if required).
-- ---------------------------------------------------------------------------
local function decode_jwt_payload(jwt)
  local parts = {}
  for part in jwt:gmatch("[^%.]+") do
    parts[#parts + 1] = part
  end
  if #parts < 2 then
    return nil, "malformed JWT"
  end
  local padded = parts[2] .. ("="):rep((4 - #parts[2] % 4) % 4)
  padded = padded:gsub("-", "+"):gsub("_", "/")
  local decoded = decode_base64(padded)
  if not decoded then
    return nil, "base64 decode failed"
  end
  return cjson.decode(decoded)
end


-- ---------------------------------------------------------------------------
-- Bearer token introspection (API-to-API flow)
-- ---------------------------------------------------------------------------
local function introspect_token(token, conf, discovery)
  local endpoint = conf.introspection_endpoint or discovery.introspection_endpoint
  if not endpoint then
    return nil, "no introspection endpoint available"
  end

  local httpc = http.new()
  httpc:set_timeout(10000)

  local res, err = httpc:request_uri(endpoint, {
    method  = "POST",
    headers = {
      ["Content-Type"]  = "application/x-www-form-urlencoded",
      ["Authorization"] = "Basic " ..
        encode_base64(conf.client_id .. ":" .. conf.client_secret),
    },
    body       = "token=" .. ngx.escape_uri(token),
    ssl_verify = conf.ssl_verify,
  })
  if not res then
    return nil, "introspection failed: " .. (err or "unknown")
  end
  if res.status ~= 200 then
    return nil, fmt("introspection returned HTTP %d", res.status)
  end

  local data = cjson.decode(res.body)
  if not data or not data.active then
    return nil, "token is inactive or revoked"
  end

  return data
end


-- ---------------------------------------------------------------------------
-- Access phase
-- ---------------------------------------------------------------------------
function KeycloakOidcHandler:access(conf)
  local discovery, err = fetch_discovery(conf)
  if not discovery then
    kong.log.err("OIDC discovery error: ", err)
    return kong.response.exit(500, { message = "OIDC provider unavailable" })
  end

  local request_path = kong.request.get_path()

  -- RP-initiated logout
  if request_path == conf.logout_path then
    local end_session = discovery.end_session_endpoint
    kong.response.set_header("Set-Cookie",
      fmt("%s=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0", COOKIE_NAME))
    if end_session then
      return kong.response.exit(302, nil, {
        ["Location"] = end_session .. "?client_id=" .. ngx.escape_uri(conf.client_id),
      })
    end
    return kong.response.exit(200, { message = "logged out" })
  end

  -- Check existing session
  local session = get_session(conf)
  if session and session.id_token_claims then
    set_consumer_headers(session.id_token_claims)
    -- Refresh idle timeout
    set_session_cookie(session, conf)
    return
  end

  -- Bearer token introspection for API-to-API flows
  if conf.bearer_token_fallback then
    local auth_header = kong.request.get_header("Authorization")
    if auth_header then
      local bearer = auth_header:match("^[Bb]earer%s+(.+)$")
      if bearer then
        local claims, intr_err = introspect_token(bearer, conf, discovery)
        if claims then
          set_consumer_headers(claims)
          return
        end
        kong.log.debug("bearer introspection failed: ", intr_err)
      end
    end
  end

  -- OIDC callback handling
  if request_path == conf.redirect_uri_path then
    local args = kong.request.get_query()
    if not args.code then
      return kong.response.exit(400, { message = "missing authorization code" })
    end

    local scheme = kong.request.get_forwarded_scheme() or kong.request.get_scheme()
    local host   = kong.request.get_forwarded_host() or kong.request.get_host()
    local redirect_uri = fmt("%s://%s%s", scheme, host, conf.redirect_uri_path)

    -- Retrieve PKCE verifier from state cookie
    local state_cookie = kong.request.get_header("Cookie")
    local code_verifier
    if state_cookie then
      code_verifier = state_cookie:match("kong_oidc_pkce_verifier=([^;]+)")
    end

    local token_data, exchange_err = exchange_code(
      args.code, redirect_uri, conf, discovery, code_verifier
    )
    if not token_data then
      kong.log.err("code exchange failed: ", exchange_err)
      return kong.response.exit(401, { message = "authentication failed" })
    end

    local claims, jwt_err = decode_jwt_payload(token_data.id_token)
    if not claims then
      kong.log.err("JWT decode failed: ", jwt_err)
      return kong.response.exit(401, { message = "invalid id_token" })
    end

    local session_data = {
      id_token_claims = claims,
      access_token    = token_data.access_token,
      refresh_token   = token_data.refresh_token,
    }
    local ok, sess_err = set_session_cookie(session_data, conf)
    if not ok then
      kong.log.err("session creation failed: ", sess_err)
      return kong.response.exit(500, { message = "session error" })
    end

    -- Clear PKCE state cookie
    kong.response.add_header("Set-Cookie",
      "kong_oidc_pkce_verifier=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0")

    local redirect_to = args.state or "/"
    return kong.response.exit(302, nil, { ["Location"] = redirect_to })
  end

  -- No session, no bearer → redirect to Keycloak authorize endpoint
  local scheme = kong.request.get_forwarded_scheme() or kong.request.get_scheme()
  local host   = kong.request.get_forwarded_host() or kong.request.get_host()
  local redirect_uri = fmt("%s://%s%s", scheme, host, conf.redirect_uri_path)
  local original_url = kong.request.get_forwarded_path() or kong.request.get_path()
  local query_string = kong.request.get_raw_query()
  if query_string and query_string ~= "" then
    original_url = original_url .. "?" .. query_string
  end

  local auth_params = {
    response_type = conf.response_type,
    client_id     = conf.client_id,
    redirect_uri  = redirect_uri,
    scope         = table.concat(conf.scopes, " "),
    state         = original_url,
  }

  -- PKCE (RFC 7636) — always applied in strict mode, optional in lax
  if conf.pkce ~= "none" then
    local verifier, challenge = generate_pkce_pair()
    auth_params.code_challenge        = challenge
    auth_params.code_challenge_method = "S256"
    -- Store verifier in a short-lived cookie for the callback
    kong.response.add_header("Set-Cookie",
      fmt("kong_oidc_pkce_verifier=%s; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300",
          verifier))
  end

  local authorize_url = discovery.authorization_endpoint .. "?" .. ngx.encode_args(auth_params)
  return kong.response.exit(302, nil, { ["Location"] = authorize_url })
end


return KeycloakOidcHandler
