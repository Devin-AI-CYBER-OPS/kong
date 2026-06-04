-- Security: Logging plugin that ships Kong request/response telemetry to Elasticsearch.
-- Supports ECS (Elastic Common Schema) mapping for SIEM integration and audit trail compliance.
-- References: NIST SP 800-53 AU-2/AU-3/AU-6, STIG V-222531

local typedefs = require "kong.db.schema.typedefs"


return {
  name = "elastic-logger",
  fields = {
    { protocols = typedefs.protocols },
    { config = {
        type = "record",
        fields = {
          { elasticsearch_url = {
              description = "Elasticsearch base URL (e.g. https://es.example.com:9200).",
              type = "string",
              required = true,
              encrypted = true,
              referenceable = true,
          } },
          { index_name = {
              description = "Target index or data stream name for log documents.",
              type = "string",
              default = "kong-logs",
          } },
          { api_key = {
              description = "Elasticsearch API key for authentication. Stored encrypted.",
              type = "string",
              encrypted = true,
              referenceable = true,
          } },
          { ssl_verify = {
              description = "Verify the TLS certificate of the Elasticsearch server.",
              type = "boolean",
              default = true,
          } },
          { include_request_body = {
              description = "Include request body in log entries. Disable in production to avoid PII leakage.",
              type = "boolean",
              default = false,
          } },
          { include_response_body = {
              description = "Include response body in log entries. Disable in production to avoid PII leakage.",
              type = "boolean",
              default = false,
          } },
          { ecs_compatible = {
              description = "Map log fields to Elastic Common Schema for SIEM compatibility.",
              type = "boolean",
              default = true,
          } },
          { custom_fields = {
              description = "Arbitrary key-value pairs appended to every log document.",
              type = "map",
              keys = { type = "string" },
              values = { type = "string" },
          } },
          { queue = typedefs.queue },
          { custom_fields_by_lua = typedefs.lua_code },
        },
    } },
  },
}
