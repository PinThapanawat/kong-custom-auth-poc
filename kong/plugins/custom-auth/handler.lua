local http = require "resty.http"
local cjson = require "cjson.safe"

local CustomAuthHandler = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

-- Declared via KONG_NGINX_HTTP_LUA_SHARED_DICT="custom_auth_cache 10m".
-- Kong's own kong.cache/mlcache does not honor per-key TTLs in DB-less mode,
-- so claims caching is done directly against this shared dict instead.
local CACHE_DICT_NAME = "custom_auth_cache"

local function unauthorized(message)
  return kong.response.exit(401, {
    message = message or "Unauthorized"
  }, {
    ["WWW-Authenticate"] = "Bearer"
  })
end

-- Kong never decrypts the JWE; the raw ciphertext is only ever hashed to
-- form a cache lookup key.
local function cache_key(raw_token)
  return "custom_auth:" .. ngx.md5(raw_token)
end

local function get_cached_auth(dict, token)
  if not dict then
    return nil
  end

  local cached, err = dict:get(cache_key(token))
  if err then
    kong.log.warn("custom-auth cache get error: ", err)
    return nil
  end

  if not cached then
    return nil
  end

  local auth, decode_err = cjson.decode(cached)
  if not auth or decode_err then
    return nil
  end

  return auth
end

local function store_cached_auth(dict, token, auth, max_ttl_seconds)
  if not dict then
    return
  end

  local ttl = max_ttl_seconds

  if type(auth.exp) == "number" then
    local remaining = auth.exp - ngx.time()
    if remaining <= 0 then
      return
    end
    ttl = math.min(ttl, remaining)
  end

  local ok, err = dict:set(cache_key(token), cjson.encode(auth), ttl)
  if not ok then
    kong.log.warn("custom-auth cache set error: ", err)
  end
end

function CustomAuthHandler:access(conf)
  local authorization = kong.request.get_header("Authorization")

  if not authorization then
    return unauthorized("Missing Authorization header")
  end

  local token = authorization:match("^Bearer%s+(.+)$")

  if not token then
    return unauthorized("Invalid Authorization header")
  end

  local dict = conf.enable_cache and ngx.shared[CACHE_DICT_NAME] or nil
  local auth = get_cached_auth(dict, token)

  if not auth then
    local httpc = http.new()
    httpc:set_timeout(conf.timeout_ms)

    local res, err = httpc:request_uri(conf.auth_service_url, {
      method = "POST",
      body = cjson.encode({
        token = token,
        method = kong.request.get_method(),
        path = kong.request.get_path(),
        correlation_id = kong.request.get_header("X-Correlation-ID")
      }),
      headers = {
        ["Content-Type"] = "application/json",
        ["X-Auth-Caller"] = "kong"
      },
      keepalive = true
    })

    if not res then
      kong.log.err("Authentication service unavailable: ", err)
      return kong.response.exit(503, {
        message = "Authentication service unavailable"
      })
    end

    if res.status == 401 then
      return unauthorized("Invalid or expired credential")
    end

    if res.status ~= 200 then
      kong.log.err("Authentication service returned status ", res.status)
      return kong.response.exit(503, {
        message = "Authentication service error"
      })
    end

    local decode_err
    auth, decode_err = cjson.decode(res.body)

    if not auth or decode_err then
      kong.log.err("Invalid authentication service response")
      return kong.response.exit(503, {
        message = "Invalid authentication service response"
      })
    end

    if auth.authenticated == true then
      store_cached_auth(dict, token, auth, conf.cache_ttl_seconds)
    end
  end

  if auth.authenticated ~= true then
    return unauthorized("Authentication failed")
  end

  local user = auth.user or {}
  local authorization_context = auth.authorization or {}

  -- Remove client-supplied identity headers before setting trusted values.
  kong.service.request.clear_header("X-User-ID")
  kong.service.request.clear_header("X-Client-ID")
  kong.service.request.clear_header("X-User-Roles")
  kong.service.request.clear_header("X-User-Scopes")
  kong.service.request.clear_header("X-Auth-Authenticated")

  kong.service.request.set_header("X-User-ID", tostring(user.id or ""))
  kong.service.request.set_header("X-Client-ID", tostring(user.client_id or ""))
  kong.service.request.set_header(
    "X-User-Roles",
    table.concat(authorization_context.roles or {}, ",")
  )
  kong.service.request.set_header(
    "X-User-Scopes",
    table.concat(authorization_context.scopes or {}, ",")
  )
  kong.service.request.set_header("X-Auth-Authenticated", "true")
end

return CustomAuthHandler
