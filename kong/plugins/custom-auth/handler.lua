local http = require "resty.http"
local cjson = require "cjson.safe"

-- Category 2/3 BFF traffic (PDF pp.4-5), brokered by Kong instead of the
-- PDS calling account-service itself: this plugin calls the PDS
-- (cryptography-service) to check auth is complete and get back plaintext + trusted
-- headers, forwards the now-plaintext request to account-service itself,
-- then calls the PDS a second time to re-encrypt the reply before it goes
-- back to the client. The SEK never leaves the PDS/Vault boundary — Kong
-- only ever sees ciphertext coming in and going out, and plaintext for the
-- single hop to account-service in between.
--
-- Everything happens in `access`, including the account-service call: this
-- plugin makes its own resty.http request to account-service rather than
-- relying on Kong's declarative service/upstream proxying, so that a
-- connection failure or timeout talking to account-service is caught right
-- here as a normal Lua error instead of depending on how (or whether) a
-- given Kong version invokes response-phase handlers for its own
-- internally generated error pages. `kong.response.exit` always sends the
-- final answer; Kong's core proxy phase for this route never runs.

local CustomAuthHandler = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

local function plaintext_error_exit(status, message)
  return kong.response.exit(status, cjson.encode({ error = message }), { ["Content-Type"] = "application/json" })
end

local function strip_prefix(path, prefix)
  if path:sub(1, #prefix) == prefix then
    local rest = path:sub(#prefix + 1)
    if rest == "" then
      return "/"
    end
    return rest
  end
  return path
end

function CustomAuthHandler:access(conf)
  local content_type = kong.request.get_header("Content-Type") or ""
  if content_type:find("multipart/form%-data", 1, true) then
    return kong.response.exit(501, cjson.encode({
      error = "multipart/form-data payload encryption is not implemented in this POC — see docs/encryption-workflow.md"
    }), { ["Content-Type"] = "application/json" })
  end

  local authorization = kong.request.get_header("Authorization")
  local session_jwt = authorization and authorization:match("^Bearer%s+(.+)$") or nil

  local raw_body = kong.request.get_raw_body()
  local method = kong.request.get_method()
  local full_path = kong.request.get_path()
  local upstream_path = strip_prefix(full_path, "/pds/bff")
  local request_unique_id = kong.request.get_header("X-Client-Transaction-Id")
  local require_revocation_check = kong.request.get_header("X-Require-Revocation-Check") == "true"

  local httpc = http.new()
  httpc:set_timeout(conf.timeout_ms)

  -- Step 1 (verify with the PDS): sessionJwt validity, SEK lookup, payload
  -- decryption, envelope signature, apiId — everything the PDS alone can
  -- check, since only it (via Vault) ever touches key material.
  local verify_res, verify_err = httpc:request_uri(conf.pds_verify_url, {
    method = "POST",
    body = cjson.encode({
      sessionJwt = session_jwt,
      jwe = raw_body,
      method = method,
      upstreamPath = upstream_path,
      requestUniqueId = request_unique_id,
      requireRevocationCheck = require_revocation_check,
    }),
    headers = {
      ["Content-Type"] = "application/json",
      ["X-Auth-Caller"] = "kong",
    },
    keepalive = true,
  })

  if not verify_res then
    kong.log.err("PDS verify call failed: ", verify_err)
    return plaintext_error_exit(502, "auth service unavailable")
  end

  local verify_result, verify_decode_err = cjson.decode(verify_res.body)
  if not verify_result or verify_decode_err then
    kong.log.err("PDS verify returned an invalid response")
    return plaintext_error_exit(502, "invalid auth service response")
  end

  if verify_result.outcome ~= "authenticated" then
    return kong.response.exit(verify_result.httpStatus, verify_result.responseBody, {
      ["Content-Type"] = verify_result.responseContentType,
    })
  end

  -- Step 2 (forward the plaintext request to account-service ourselves).
  local plaintext_body = ""
  if verify_result.plaintextRequestBodyBase64 and verify_result.plaintextRequestBodyBase64 ~= "" then
    plaintext_body = ngx.decode_base64(verify_result.plaintextRequestBodyBase64) or ""
  end

  local account_headers = {
    ["X-User-ID"] = verify_result.userId or "",
    ["X-Client-ID"] = verify_result.clientId or "",
    ["X-User-Roles"] = table.concat(verify_result.roles or {}, ","),
    ["X-User-Scopes"] = table.concat(verify_result.scopes or {}, ","),
    ["X-Auth-Authenticated"] = "true",
  }
  local has_body = method ~= "GET" and method ~= "HEAD" and #plaintext_body > 0
  if has_body then
    account_headers["Content-Type"] = "application/json"
  end

  local acct_httpc = http.new()
  acct_httpc:set_timeout(conf.timeout_ms)
  local acct_res, acct_err = acct_httpc:request_uri(conf.account_service_url .. upstream_path, {
    method = method,
    body = has_body and plaintext_body or nil,
    headers = account_headers,
    keepalive = true,
  })

  local response_status
  local response_plaintext
  if not acct_res then
    kong.log.err("account-service call failed: ", acct_err)
    local is_timeout = acct_err and acct_err:find("timeout", 1, true) ~= nil
    response_status = is_timeout and 504 or 502 -- PDF p.5 steps 6.1/6.2
    response_plaintext = cjson.encode({ error = is_timeout and "upstream timeout" or "upstream unavailable" })
  else
    response_status = acct_res.status
    response_plaintext = acct_res.body or ""
  end

  -- Step 3 (re-encrypt the reply via the PDS — Kong never holds the SEK).
  local encrypt_res, encrypt_err = httpc:request_uri(conf.pds_encrypt_response_url, {
    method = "POST",
    body = cjson.encode({
      sessionId = verify_result.sessionId,
      requestUniqueId = verify_result.requestUniqueId,
      plaintextBodyBase64 = ngx.encode_base64(response_plaintext),
    }),
    headers = {
      ["Content-Type"] = "application/json",
      ["X-Auth-Caller"] = "kong",
    },
    keepalive = true,
  })

  if not encrypt_res or encrypt_res.status ~= 200 then
    kong.log.err("PDS encrypt-response call failed: ", encrypt_err or (encrypt_res and encrypt_res.status))
    return plaintext_error_exit(500, "response encryption failed")
  end

  local encrypt_result, encrypt_decode_err = cjson.decode(encrypt_res.body)
  if not encrypt_result or encrypt_decode_err or not encrypt_result.responseJwe then
    kong.log.err("PDS encrypt-response returned an invalid response")
    return plaintext_error_exit(500, "invalid auth service response")
  end

  return kong.response.exit(response_status, encrypt_result.responseJwe, {
    ["Content-Type"] = "application/jose",
  })
end

return CustomAuthHandler
