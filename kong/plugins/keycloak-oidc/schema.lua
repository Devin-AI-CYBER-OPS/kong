-- Security: Custom OIDC plugin for Keycloak IdP integration.
-- Enforces STIG session timeout requirements (V-222602) and PKCE for public/confidential clients.
-- References: NIST SP 800-63B, OWASP ASVS 3.3

local typedefs = require "kong.db.schema.typedefs"


return {
  name = "keycloak-oidc",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { discovery_url = {
              description = "Keycloak OIDC discovery endpoint URL (.well-known/openid-configuration).",
              type = "string",
              required = true,
          } },
          { client_id = {
              description = "OIDC client ID registered in Keycloak.",
              type = "string",
              required = true,
          } },
          { client_secret = {
              description = "OIDC client secret. Stored encrypted at rest.",
              type = "string",
              required = true,
              encrypted = true,
              referenceable = true,
          } },
          { scopes = {
              description = "OIDC scopes to request from Keycloak.",
              type = "array",
              elements = { type = "string" },
              default = { "openid", "profile", "email" },
          } },
          { response_type = {
              description = "OAuth 2.0 response type. Only 'code' (Authorization Code) is supported.",
              type = "string",
              default = "code",
              one_of = { "code" },
          } },
          { token_endpoint_auth_method = {
              description = "Authentication method for the token endpoint.",
              type = "string",
              default = "client_secret_post",
              one_of = { "client_secret_basic", "client_secret_post", "private_key_jwt" },
          } },
          { ssl_verify = {
              description = "Verify TLS certificate of the Keycloak server.",
              type = "boolean",
              default = true,
          } },
          { session_secret = {
              description = "Secret used to encrypt session cookies. Stored encrypted at rest.",
              type = "string",
              encrypted = true,
              referenceable = true,
          } },
          { logout_path = {
              description = "Path that triggers RP-initiated logout via Keycloak.",
              type = "string",
              default = "/logout",
          } },
          { redirect_uri_path = {
              description = "Callback path where Keycloak redirects after authentication.",
              type = "string",
              default = "/auth/callback",
          } },
          { session_lifetime = {
              description = "Idle session timeout in seconds (STIG V-222602: 900s / 15 min).",
              type = "number",
              default = 900,
          } },
          { session_absolute_timeout = {
              description = "Absolute session timeout in seconds (STIG: 28800s / 8 hr max).",
              type = "number",
              default = 28800,
          } },
          { bearer_token_fallback = {
              description = "Allow bearer token introspection for API-to-API flows.",
              type = "boolean",
              default = true,
          } },
          { introspection_endpoint = {
              description = "Token introspection endpoint URL. Derived from discovery if empty.",
              type = "string",
          } },
          { pkce = {
              description = "PKCE enforcement mode per RFC 7636. 'strict' recommended for defense environments.",
              type = "string",
              default = "strict",
              one_of = { "none", "lax", "strict" },
          } },
          { realm = {
              description = "Realm value for WWW-Authenticate header on 401 responses.",
              type = "string",
              required = false,
          } },
        },
    } },
  },
}
