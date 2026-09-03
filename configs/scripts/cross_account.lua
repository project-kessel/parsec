-- cross_account.lua
--
-- Validates browser cross-account cookies and checks RBAC for an approved
-- request. Called from redhat_identity.cel via datasource("cross_account")
-- on User jwt-auth branches after export compliance.
--
-- Return:
--   nil                         — no cross-account cookies (CEL no-op)
--   {status="forbidden", ...}   — not an internal employee
--   {status="denied", ...}      — no approved RBAC request
--   {status="allowed", ...}     — swap targets + employee originals
--   error(...)                  — RBAC unavailable / misconfig (CEL → 500)
--
-- Config:
--   rbac_api                 required once the DS is registered
--   requests_path            default /api/rbac/v1/cross-account-requests/
--   query_by                 "account" (default) or "org_id"
--   cookie_account           default cross_access_account_number
--   cookie_org               default cross_access_org_id
--   internal_email_suffix    default @redhat.com
--   bypass_is_internal       default false (email still required)
--   internal_idp_target      optional; matches claims.idp
--   role_fallback_enabled    default false; checks redhat:employees

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

local function ends_with(s, suffix)
  if s == nil or suffix == nil or suffix == "" then return false end
  return string.sub(s, -#suffix) == suffix
end

local function trim(s)
  if s == nil then return "" end
  return (string.gsub(s, "^%s*(.-)%s*$", "%1"))
end

local function unquote(s)
  if #s >= 2 and string.sub(s, 1, 1) == '"' and string.sub(s, -1) == '"' then
    return string.sub(s, 2, -2)
  end
  return s
end

local function parse_cookies(header)
  local cookies = {}
  if header == nil or header == "" then return cookies end
  for part in string.gmatch(header, "[^;]+") do
    local name, value = string.match(part, "^%s*([^=]+)=(.*)$")
    if name ~= nil then
      cookies[trim(name)] = unquote(trim(value))
    end
  end
  return cookies
end

local function cookie_header(input)
  if input.request_attributes == nil or input.request_attributes.headers == nil then
    return ""
  end
  local h = input.request_attributes.headers
  if h.cookie ~= nil then return tostring(h.cookie) end
  if h.Cookie ~= nil then return tostring(h.Cookie) end
  return ""
end

local function has_role(claims, role)
  if claims == nil or claims.realm_access == nil or claims.realm_access.roles == nil then
    return false
  end
  local roles = claims.realm_access.roles
  for i = 1, #roles do
    if roles[i] == role then return true end
  end
  return false
end

local function is_internal(claims)
  if config.get("bypass_is_internal") == true then
    return true
  end
  local idp_target = config.get("internal_idp_target", "")
  if idp_target ~= "" and claim_str(claims, "idp") == idp_target then
    return true
  end
  if claims ~= nil and claims.is_internal == true then
    return true
  end
  if config.get("role_fallback_enabled") == true and has_role(claims, "redhat:employees") then
    return true
  end
  return false
end

local function resolve_org_and_account(claims)
  local account_number = org_field(claims, "account_number")
  if account_number == "" then account_number = claim_str(claims, "account_number") end
  if account_number == "" then account_number = claim_str(claims, "account_id") end

  local org_id = org_field(claims, "id")
  if org_id == "" then org_id = claim_str(claims, "org_id") end
  if org_id == "" then org_id = account_number end
  return org_id, account_number
end

local function json_result(payload)
  local encoded, err = json.encode(payload)
  if encoded == nil then
    error("cross_account: failed to encode result: " .. tostring(err))
  end
  return { data = encoded, content_type = "application/json" }
end

local function join_url(base, path)
  if base == nil then base = "" end
  if path == nil then path = "" end
  if string.sub(base, -1) == "/" and string.sub(path, 1, 1) == "/" then
    return string.sub(base, 1, -2) .. path
  end
  if string.sub(base, -1) ~= "/" and string.sub(path, 1, 1) ~= "/" and path ~= "" then
    return base .. "/" .. path
  end
  return base .. path
end

function fetch(input)
  local cookie_account = config.get("cookie_account", "cross_access_account_number")
  local cookie_org = config.get("cookie_org", "cross_access_org_id")
  local cookies = parse_cookies(cookie_header(input))
  local target_account = cookies[cookie_account] or ""
  local target_org = cookies[cookie_org] or ""
  if target_account == "" and target_org == "" then
    return nil
  end

  local claims = {}
  if input.subject ~= nil and input.subject.claims ~= nil then
    claims = input.subject.claims
  end

  local suffix = config.get("internal_email_suffix", "@redhat.com")
  local email = claim_str(claims, "email")
  if not ends_with(email, suffix) or not is_internal(claims) then
    return json_result({ status = "forbidden" })
  end

  local rbac_api = config.get("rbac_api")
  if rbac_api == nil or rbac_api == "" then
    error("cross_account: rbac_api is not configured")
  end

  local employee_org, employee_account = resolve_org_and_account(claims)
  local query_by = config.get("query_by", "account")
  local path = config.get("requests_path", "/api/rbac/v1/cross-account-requests/")
  local rbac_url = join_url(rbac_api, path)

  if query_by == "org_id" then
    local org = target_org
    if org == "" then org = target_account end
    rbac_url = rbac_url .. "?query_by=target_org&org_id=" .. url.encode(org) .. "&approved_only=true"
  else
    local account = target_account
    if account == "" then account = target_org end
    rbac_url = rbac_url .. "?query_by=user_id&account=" .. url.encode(account) .. "&approved_only=true"
  end

  local envelope = {
    identity = {
      auth_type = "jwt-auth",
      account_number = employee_account,
      org_id = employee_org,
      type = "User",
      user = {
        username = claim_str(claims, "preferred_username"),
        email = email,
        is_internal = true
      },
      internal = {
        org_id = employee_org,
        cross_access = false
      }
    }
  }
  local encoded, enc_err = json.encode(envelope)
  if encoded == nil then
    error("cross_account: failed to encode identity: " .. tostring(enc_err))
  end

  local response, http_err = http.get(rbac_url, {
    ["x-rh-identity"] = base64.encode(encoded),
    ["Accept"] = "application/json"
  })
  if response == nil then
    error("cross_account: rbac request failed: " .. tostring(http_err))
  end
  if response.status >= 500 or response.status == 0 then
    error("cross_account: rbac unavailable: HTTP " .. tostring(response.status))
  end
  if response.status ~= 200 then
    return json_result({ status = "denied" })
  end

  local decoded, dec_err = json.decode(response.body)
  if decoded == nil then
    error("cross_account: rbac response decode failed: " .. tostring(dec_err))
  end

  local n = 0
  if type(decoded) == "table" and type(decoded.data) == "table" then
    n = #decoded.data
  end
  if n == 0 and type(decoded) == "table" and type(decoded.meta) == "table" and decoded.meta.count ~= nil then
    n = tonumber(decoded.meta.count) or 0
  end
  if n < 1 then
    return json_result({ status = "denied" })
  end

  return json_result({
    status = "allowed",
    target_account_number = target_account,
    target_org_id = target_org,
    employee_account_number = employee_account,
    employee_org_id = employee_org
  })
end

function fetch_cache_key(input)
  local cookie_account = config.get("cookie_account", "cross_access_account_number")
  local cookie_org = config.get("cookie_org", "cross_access_org_id")
  local header = cookie_header(input)
  local cookies = parse_cookies(header)
  if (cookies[cookie_account] or "") == "" and (cookies[cookie_org] or "") == "" then
    return nil
  end

  local claims = {}
  if input.subject ~= nil and input.subject.claims ~= nil then
    claims = input.subject.claims
  end
  local subject = ""
  if input.subject ~= nil and input.subject.subject ~= nil then
    subject = tostring(input.subject.subject)
  end

  return {
    subject = {
      subject = subject,
      claims = {
        email = claim_str(claims, "email"),
        is_internal = claims.is_internal,
        query_by = config.get("query_by", "account")
      }
    },
    request_attributes = {
      headers = {
        cookie = header
      }
    }
  }
end
