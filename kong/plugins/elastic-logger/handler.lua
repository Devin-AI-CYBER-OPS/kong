-- Security: Elasticsearch bulk-shipping log handler.
-- Maps Kong request telemetry to ECS (Elastic Common Schema) for SIEM integration.
-- Implements queue-based batching with retry/circuit-breaker semantics.
-- References: NIST SP 800-53 AU-2/AU-3, STIG V-222531

local Queue     = require "kong.tools.queue"
local cjson     = require "cjson"
local http      = require "resty.http"
local kong_meta = require "kong.meta"
local sandbox   = require "kong.tools.sandbox".sandbox


local kong      = kong
local ngx       = ngx
local fmt       = string.format
local pairs     = pairs
local table_concat = table.concat


local ElasticLoggerHandler = {
  PRIORITY = 11,
  VERSION  = kong_meta.version,
}


-- ---------------------------------------------------------------------------
-- ECS field mapping
-- ---------------------------------------------------------------------------
local function to_ecs(entry)
  local log = cjson.decode(entry)
  if not log then
    return entry
  end

  local ecs = {
    ["@timestamp"]          = log.started_at and
      ngx.http_time(log.started_at / 1000) or os.date("!%Y-%m-%dT%H:%M:%SZ"),
    ["event.dataset"]       = "kong.access",
    ["event.kind"]          = "event",
    ["event.category"]      = { "web" },
    ["event.duration"]      = log.latencies and
      (log.latencies.request and log.latencies.request * 1000000) or nil,

    ["source.ip"]           = log.client_ip,
    ["url.path"]            = log.request and log.request.uri,
    ["url.query"]           = log.request and log.request.querystring,
    ["http.request.method"] = log.request and log.request.method,
    ["http.request.body.bytes"] = log.request and log.request.size,
    ["http.response.status_code"] = log.response and log.response.status,
    ["http.response.body.bytes"]  = log.response and log.response.size,

    ["service.name"]        = log.service and log.service.name,
    ["service.id"]          = log.service and log.service.id,

    ["kong.route.id"]       = log.route and log.route.id,
    ["kong.route.name"]     = log.route and log.route.name,
    ["kong.consumer.id"]    = log.consumer and log.consumer.id,
    ["kong.consumer.username"] = log.consumer and log.consumer.username,
    ["kong.latencies.kong"]    = log.latencies and log.latencies.kong,
    ["kong.latencies.proxy"]   = log.latencies and log.latencies.proxy,
    ["kong.latencies.request"] = log.latencies and log.latencies.request,
  }

  -- Propagate authenticated identity from OIDC headers for audit trail
  if log.request and log.request.headers then
    ecs["user.name"] = log.request.headers["x-oidc-username"]
    ecs["user.id"]   = log.request.headers["x-oidc-sub"]
    ecs["user.email"] = log.request.headers["x-oidc-email"]
  end

  return cjson.encode(ecs)
end


-- ---------------------------------------------------------------------------
-- Bulk API payload builder
-- ---------------------------------------------------------------------------
local function build_bulk_body(conf, entries)
  local lines = {}
  for i = 1, #entries do
    local action = cjson.encode({
      index = { _index = conf.index_name },
    })
    local doc = conf.ecs_compatible and to_ecs(entries[i]) or entries[i]
    lines[#lines + 1] = action
    lines[#lines + 1] = doc
  end
  -- Elasticsearch _bulk API requires a trailing newline
  return table_concat(lines, "\n") .. "\n"
end


-- ---------------------------------------------------------------------------
-- Send entries to Elasticsearch _bulk API
-- ---------------------------------------------------------------------------
local function send_entries(conf, entries)
  local body = build_bulk_body(conf, entries)
  local es_url = conf.elasticsearch_url

  local httpc = http.new()
  httpc:set_timeout(10000)

  local headers = {
    ["Content-Type"] = "application/x-ndjson",
  }
  if conf.api_key then
    headers["Authorization"] = "ApiKey " .. conf.api_key
  end

  local url = fmt("%s/_bulk", es_url)
  local res, err = httpc:request_uri(url, {
    method     = "POST",
    headers    = headers,
    body       = body,
    ssl_verify = conf.ssl_verify,
  })
  if not res then
    return nil, "bulk request failed: " .. (err or "unknown")
  end

  if res.status >= 300 then
    return nil, fmt("Elasticsearch returned HTTP %d: %s",
                    res.status, res.body or "")
  end

  local resp = cjson.decode(res.body)
  if resp and resp.errors then
    kong.log.warn("Elasticsearch bulk response contained errors")
  end

  return true
end


-- ---------------------------------------------------------------------------
-- Queue name (follows http-log convention)
-- ---------------------------------------------------------------------------
local function make_queue_name(conf)
  return fmt("elastic-logger:%s:%s", conf.elasticsearch_url, conf.index_name)
end


-- ---------------------------------------------------------------------------
-- Log phase
-- ---------------------------------------------------------------------------
function ElasticLoggerHandler:log(conf)
  if conf.custom_fields_by_lua then
    local set_serialize_value = kong.log.set_serialize_value
    for key, expression in pairs(conf.custom_fields_by_lua) do
      set_serialize_value(key, sandbox(expression)())
    end
  end

  -- Inject static custom fields
  if conf.custom_fields then
    local set_serialize_value = kong.log.set_serialize_value
    for key, value in pairs(conf.custom_fields) do
      set_serialize_value(key, value)
    end
  end

  local queue_conf = Queue.get_plugin_params("elastic-logger", conf, make_queue_name(conf))

  local ok, err = Queue.enqueue(
    queue_conf,
    send_entries,
    conf,
    cjson.encode(kong.log.serialize())
  )
  if not ok then
    kong.log.err("Failed to enqueue log entry to Elasticsearch: ", err)
  end
end


return ElasticLoggerHandler
