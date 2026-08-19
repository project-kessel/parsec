-- export_compliance.lua
--
-- Checks whether the authenticated user is subject to U.S. export restrictions.
-- Called from redhat_identity.cel via datasource("export_compliance") when
-- context_extensions.enable_compliance is "true" for SSO User jwt-auth only.
--
-- Config:
--   compliance_api (required) — full GET URL, e.g.
--     https://export-compliance.example.internal/v1/compliance
--
-- Behavior (fail-open):
--   - Any error, non-200 response, malformed JSON, or missing username returns
--     { result_code = "", synthetic = true } — the request is allowed through.
--   - Only real compliance service responses set synthetic = false.
--   - The caller (CEL) is responsible for acting on result_code values.
--
-- Headers sent (AC2):
--   - x-rh-identity (base64-encoded identity JSON)
--   - Accept: application/json;charset=UTF-8
--
-- Caching (AC6, AC7, AC8):
--   - Cache key is the resolved username (per-user cache, 24h TTL recommended).
--   - fetch_cache_key returns nil for synthetic results (AC7) — these are never
--     cached under the username key.
--   - fetch_cache_key returns nil when the request header
--     x-rh-insights-gateway-use-compliance-cache == "0" (AC8), bypassing both
--     reads and writes.
--
-- Identity (AC9):
--   - Compliance checks the ORIGINAL user identity, not any cross-account swap.
--   - CEL must call datasource("export_compliance") before cross-account logic.

local BYPASS_HEADER = "x-rh-insights-gateway-use-compliance-cache"

local function claim_str(claims, key)
  if claims == nil then return "" end
  local v = claims[key]
  if v == nil then return "" end
  return tostring(v)
end

local function org_field(claims, field)
  if claims == nil or claims.organization == nil then return "" end
  local v = claims.organization[field]
  if v == nil then return "" end
  return tostring(v)
end

-- resolve_username extracts the username from subject claims.
-- Supports console (preferred_username), rhsm/portal (username, sub) token shapes.
local function resolve_username(input)
  local claims = {}
  if input.subject ~= nil and input.subject.claims ~= nil then
    claims = input.subject.claims
  end
  local username = claim_str(claims, "preferred_username")
  if username == "" then username = claim_str(claims, "username") end
  if username == "" then username = claim_str(claims, "sub") end
  if username == "" and input.subject ~= nil and input.subject.subject ~= nil then
    username = tostring(input.subject.subject)
  end
  return username
end

-- resolve_org_and_account extracts org_id and account_number for the minimal
-- identity envelope. Supports console / rhsm / portal claim shapes.
local function resolve_org_and_account(input)
  local claims = {}
  if input.subject ~= nil and input.subject.claims ~= nil then
    claims = input.subject.claims
  end

  local account_number = org_field(claims, "account_number")
  if account_number == "" then account_number = claim_str(claims, "account_number") end
  if account_number == "" then account_number = claim_str(claims, "account_id") end

  local org_id = org_field(claims, "id")
  if org_id == "" then org_id = claim_str(claims, "org_id") end
  if org_id == "" then org_id = claim_str(claims, "rh-org-id") end
  if org_id == "" then org_id = account_number end

  return org_id, account_number
end

-- build_identity_envelope builds the minimal x-rh-identity JSON for the
-- compliance service.  Only the fields required by the compliance API are
-- included (AC2, Risk #1: claim-shape duplication mirrors user_entitlements).
local function build_identity_envelope(username, org_id, account_number)
  return {
    identity = {
      auth_type = "jwt-auth",
      account_number = account_number,
      org_id = org_id,
      type = "User",
      user = {
        username = username
      },
      internal = {
        org_id = org_id,
        cross_access = false
      }
    }
  }
end

-- fail_open returns the synthetic sentinel result used for any error path.
-- The result is JSON-encoded so the Go layer and CEL can access result_code.
local function fail_open()
  local encoded, _ = json.encode({ result_code = "", synthetic = true })
  return { data = encoded or '{"result_code":"","synthetic":true}', content_type = "application/json" }
end

-- cache_bypass returns true when the caller has signalled to skip the cache.
local function cache_bypass(input)
  if input.request_attributes == nil then return false end
  if input.request_attributes.headers == nil then return false end
  return input.request_attributes.headers[BYPASS_HEADER] == "0"
end

function fetch(input)
  local api = config.get("compliance_api")
  if api == nil or api == "" then
    -- Missing config is a misconfiguration; fail-open to avoid blocking all traffic.
    return fail_open()
  end

  local username = resolve_username(input)
  if username == "" then
    return fail_open()
  end

  local org_id, account_number = resolve_org_and_account(input)
  local envelope = build_identity_envelope(username, org_id, account_number)

  local encoded, enc_err = json.encode(envelope)
  if encoded == nil then
    return fail_open()
  end

  local identity_b64 = base64.encode(encoded)
  local response, err = http.get(api, {
    ["x-rh-identity"] = identity_b64,
    ["Accept"] = "application/json;charset=UTF-8"
  })

  if response == nil then
    return fail_open()
  end
  if response.status ~= 200 then
    return fail_open()
  end

  local decoded, dec_err = json.decode(response.body)
  if decoded == nil then
    return fail_open()
  end

  local result_code = ""
  if decoded.result_code ~= nil then
    result_code = tostring(decoded.result_code)
  end

  local encoded, enc_err2 = json.encode({ result_code = result_code, synthetic = false })
  if encoded == nil then
    return fail_open()
  end
  return { data = encoded, content_type = "application/json" }
end

function fetch_cache_key(input)
  -- Cache bypass header disables both reads and writes (AC8).
  if cache_bypass(input) then
    return nil
  end

  local username = resolve_username(input)
  if username == "" then
    -- No username means fetch will be synthetic; do not cache (AC7).
    return nil
  end

  return {
    subject = {
      claims = {
        preferred_username = username
      }
    }
  }
end
