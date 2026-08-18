-- user_entitlements.lua
--
-- Fetches entitlements from an external service for injection into the
-- x-rh-identity envelope. Called from redhat_identity.cel via
-- datasource("user_entitlements") when context_extensions.enable_entitlements
-- is "true" for eligible auth types (SSO User jwt-auth / cert-auth).
--
-- Config:
--   entitlements_api (required) — full GET URL, e.g.
--     http://localhost:3000/api/entitlements/v1/services
--     (entitlements-api-go GET /api/entitlements/v1/services)
--
-- Behavior (fail-closed):
--   - Sends only the x-rh-identity header (base64-encoded identity JSON)
--   - Non-200, transport errors, and malformed JSON all call error()
--   - Response body is returned verbatim (no schema validation)
--
-- Caching: fetch_cache_key masks to account_number / org_id / user_id / preferred_username.
-- Default TTL is 5m when caching.ttl is omitted in YAML.

local function claim_str(claims, key)
  if claims == nil then
    return ""
  end
  local v = claims[key]
  if v == nil then
    return ""
  end
  return tostring(v)
end

local function org_field(claims, field)
  if claims == nil or claims.organization == nil then
    return ""
  end
  local v = claims.organization[field]
  if v == nil then
    return ""
  end
  return tostring(v)
end

-- Resolve account / org / user from subject claims (console / rhsm / portal shapes).
local function identity_keys(claims)
  local account_number = org_field(claims, "account_number")
  if account_number == "" then
    account_number = claim_str(claims, "account_number")
  end
  if account_number == "" then
    account_number = claim_str(claims, "account_id")
  end

  local org_id = org_field(claims, "id")
  if org_id == "" then
    org_id = claim_str(claims, "org_id")
  end
  if org_id == "" then
    org_id = claim_str(claims, "rh-org-id")
  end
  if org_id == "" then
    org_id = account_number
  end

  local user_id = claim_str(claims, "user_id")
  if user_id == "" then
    user_id = claim_str(claims, "sub")
  end

  return account_number, org_id, user_id
end

local function build_identity_envelope(input)
  local claims = {}
  if input.subject ~= nil and input.subject.claims ~= nil then
    claims = input.subject.claims
  end

  local account_number, org_id, user_id = identity_keys(claims)
  local username = claim_str(claims, "preferred_username")
  if username == "" then
    username = claim_str(claims, "username")
  end
  if username == "" and input.subject ~= nil then
    username = tostring(input.subject.subject or "")
  end

  return {
    identity = {
      auth_type = "jwt-auth",
      account_number = account_number,
      org_id = org_id,
      type = "User",
      user = {
        username = username,
        user_id = user_id
      },
      internal = {
        org_id = org_id,
        cross_access = false
      }
    }
  }
end

function fetch(input)
  local api = config.get("entitlements_api")
  if api == nil or api == "" then
    error("entitlements_api is required in data source config")
  end

  local envelope = build_identity_envelope(input)
  local identity = envelope.identity
  local has_org = identity.account_number ~= "" or identity.org_id ~= ""
  local has_user = identity.user ~= nil and
    (identity.user.username ~= "" or identity.user.user_id ~= "")
  if not has_org and not has_user then
    error("cannot fetch entitlements: identity has no organization or user claims")
  end

  local encoded, enc_err = json.encode(envelope)
  if encoded == nil then
    error("failed to encode identity for entitlements request: " .. (enc_err or "unknown"))
  end

  local identity_b64 = base64.encode(encoded)
  local response, err = http.get(api, {
    ["x-rh-identity"] = identity_b64
  })

  if response == nil then
    error("entitlements request failed: " .. (err or "unknown error"))
  end

  if response.status ~= 200 then
    error("entitlements service returned status " .. tostring(response.status))
  end

  local decoded, dec_err = json.decode(response.body)
  if decoded == nil then
    error("entitlements response is not valid JSON: " .. (dec_err or "unknown"))
  end

  -- Attach verbatim; gateway does not inspect entitlements structure.
  return {
    data = response.body,
    content_type = "application/json"
  }
end

function fetch_cache_key(input)
  local envelope = build_identity_envelope(input)
  local identity = envelope.identity
  local user_id = ""
  local username = ""
  if identity.user ~= nil then
    user_id = identity.user.user_id or ""
    username = identity.user.username or ""
  end
  -- When no identity material is present at all, return nil so the caching
  -- layer uses the full input as the cache key. This prevents all anonymous
  -- requests from sharing a single serialised blank-fields cache entry.
  if identity.account_number == "" and identity.org_id == "" and user_id == "" and username == "" then
    return nil
  end
  return {
    subject = {
      claims = {
        account_number = identity.account_number,
        org_id = identity.org_id,
        user_id = user_id,
        preferred_username = username
      }
    }
  }
end
