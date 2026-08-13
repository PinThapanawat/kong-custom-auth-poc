local http = require "resty.http"
local cjson = require "cjson.safe"
local pkey_lib = require "resty.openssl.pkey"
local cipher_lib = require "resty.openssl.cipher"
local rand = require "resty.openssl.rand"

local CustomAuthHandler = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

-- OpenSSL's RSA_PKCS1_OAEP_PADDING, hardcoded rather than pulled from a
-- resty.openssl constants table since the exact export path has moved
-- across library versions; the numeric padding ID is stable OpenSSL ABI.
local RSA_PKCS1_OAEP_PADDING = 4

local function b64url_encode(s)
  local encoded = ngx.encode_base64(s)
  encoded = encoded:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
  return encoded
end

local function b64url_decode(s)
  local padded = s:gsub("-", "+"):gsub("_", "/")
  local rem = #padded % 4
  if rem == 2 then
    padded = padded .. "=="
  elseif rem == 3 then
    padded = padded .. "="
  end
  return ngx.decode_base64(padded)
end

-- Imports the client's public key from the X-Response-Pubkey request
-- header (base64url-encoded JSON JWK). A public key grants no authority
-- (only its matching private key, held by the client, can decrypt), so
-- Kong trusts it without any authentication check. Done in header_filter,
-- before any body has arrived, so the Content-Type decision and the
-- actual encryption can never disagree about whether encryption is
-- happening.
local function import_response_pubkey(pubkey_b64url)
  local jwk_json = b64url_decode(pubkey_b64url)
  if not jwk_json then
    return nil, "invalid X-Response-Pubkey encoding"
  end

  local jwk, decode_err = cjson.decode(jwk_json)
  if not jwk or decode_err then
    return nil, "invalid X-Response-Pubkey JSON"
  end

  local pkey, pkey_err = pkey_lib.new(jwk_json, { format = "JWK" })
  if not pkey then
    return nil, "invalid public key: " .. (pkey_err or "unknown error")
  end

  return pkey
end

-- Encrypts `plaintext` into a compact JWE (RSA-OAEP-256 key wrap +
-- A256GCM content encryption) for the holder of `pkey`. Wire-compatible
-- with `jose.compactDecrypt` on the client side.
local function encrypt_response_for_client(pkey, plaintext)
  local protected = cjson.encode({ alg = "RSA-OAEP-256", enc = "A256GCM" })
  local protected_b64 = b64url_encode(protected)

  local cek = rand.bytes(32)
  local iv = rand.bytes(12)
  if not cek or not iv then
    return nil, "failed to generate random key material"
  end

  local encrypted_key, ek_err = pkey:encrypt(cek, RSA_PKCS1_OAEP_PADDING, {
    oaep_md = "sha256",
    mgf1_md = "sha256"
  })
  if not encrypted_key then
    return nil, "key wrap failed: " .. (ek_err or "unknown error")
  end

  local cipher, cipher_err = cipher_lib.new("aes-256-gcm")
  if not cipher then
    return nil, "cipher init failed: " .. (cipher_err or "unknown error")
  end

  -- AAD per the JWE spec: ASCII(BASE64URL(UTF8(protected header))).
  local ciphertext, enc_err = cipher:encrypt(cek, iv, plaintext, false, protected_b64)
  if not ciphertext then
    return nil, "content encryption failed: " .. (enc_err or "unknown error")
  end

  local tag, tag_err = cipher:get_aead_tag()
  if not tag then
    return nil, "tag retrieval failed: " .. (tag_err or "unknown error")
  end

  return table.concat({
    protected_b64,
    b64url_encode(encrypted_key),
    b64url_encode(iv),
    b64url_encode(ciphertext),
    b64url_encode(tag)
  }, ".")
end

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

  -- A request body is unique per-request (unlike the token, which repeats
  -- across many requests), so it is never cached: caching a decrypted
  -- payload under the token's cache key would replay a stale payload onto
  -- a later request that reuses the same token with different content.
  local raw_body = kong.request.get_raw_body()
  local has_payload = raw_body ~= nil and raw_body ~= ""

  local dict = (conf.enable_cache and not has_payload) and ngx.shared[CACHE_DICT_NAME] or nil
  local auth = get_cached_auth(dict, token)

  if not auth then
    local httpc = http.new()
    httpc:set_timeout(conf.timeout_ms)

    local body = {
      token = token,
      method = kong.request.get_method(),
      path = kong.request.get_path(),
      correlation_id = kong.request.get_header("X-Correlation-ID")
    }

    if has_payload then
      body.payload = raw_body
    end

    local res, err = httpc:request_uri(conf.auth_service_url, {
      method = "POST",
      body = cjson.encode(body),
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

    if auth.authenticated == true and not has_payload then
      store_cached_auth(dict, token, auth, conf.cache_ttl_seconds)
    end
  end

  if auth.authenticated ~= true then
    return unauthorized("Authentication failed")
  end

  if auth.payload_error == true then
    return kong.response.exit(400, {
      message = "Invalid encrypted payload"
    })
  end

  if type(auth.payload_plaintext) == "string" then
    kong.service.request.set_raw_body(auth.payload_plaintext)
    kong.service.request.set_header("Content-Type", "application/json")
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

-- header_filter decides *whether* to encrypt, before any response body has
-- arrived: only for successful responses carrying the client's one-off
-- public key (X-Response-Pubkey, set by the client on the original
-- request). Errors (401/403/503 etc.) and requests without that header
-- pass through untouched. The imported key is stashed in the
-- request-scoped plugin context so body_filter — which runs later, once
-- per response chunk — doesn't need to re-parse the header, and so the
-- Content-Type set here can never disagree with what body_filter actually
-- does to the body.
function CustomAuthHandler:header_filter(conf)
  if not conf.encrypt_response then
    return
  end

  if kong.response.get_status() ~= 200 then
    return
  end

  local pubkey_header = kong.request.get_header("X-Response-Pubkey")
  if not pubkey_header then
    return
  end

  local pkey, err = import_response_pubkey(pubkey_header)
  if not pkey then
    kong.log.warn("Response encryption skipped: ", err)
    return
  end

  kong.ctx.plugin.response_pkey = pkey
  kong.response.set_header("Content-Type", "application/jwe")
  kong.response.clear_header("Content-Length")
end

-- body_filter runs once per response chunk; kong.response.get_raw_body()
-- buffers them internally and only returns the full body once the last
-- chunk has arrived (nil on every call before that).
function CustomAuthHandler:body_filter(conf)
  local pkey = kong.ctx.plugin.response_pkey
  if not pkey then
    return
  end

  local body = kong.response.get_raw_body()
  if not body then
    return
  end

  local jwe, err = encrypt_response_for_client(pkey, body)
  if not jwe then
    -- Content-Type was already committed to application/jwe in
    -- header_filter, so failing silently here would ship a body that
    -- doesn't match it. Surface it as plaintext content, even though the
    -- header now claims JWE — this is the only place there's genuinely
    -- no clean recovery from a body-stage failure.
    kong.log.err("Response encryption failed after committing to it: ", err)
    kong.response.set_raw_body(body)
    return
  end

  kong.response.set_raw_body(jwe)
end

return CustomAuthHandler
