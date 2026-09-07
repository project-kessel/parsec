-- cross_account.lua
--
-- Validates Red Hat internal employee cross-account access (RHCLOUD-47320).
-- Called from redhat_identity.cel on User jwt-auth branches (console / rhsm /
-- portal) after export_compliance. cert-auth, registry-auth, service accounts,
-- and unsigned-json BOP paths must not call this datasource.
--
-- Config (mirror identity-policy where noted):
--   rbac_path                  — path or full URL (default /api/rbac/v1/cross-account-requests/)
--   approved_only              — RBAC query param (default "true")
--   internal_idp_target        — idp match for is_internal (same as identity-policy)
--   role_fallback_enabled      — realm_access.roles redhat:employees fallback
--   cross_access_bypass_is_internal — skip is_internal flag; email still required
--   cross_access_query_by      — "account" (default) or "org_id"
--   employee_email_suffix      — required email suffix (default "@redhat.com")
--
-- Returns (JSON in data):
--   { "active": false }                         — no cross_access_* cookies (CEL no-op)
--   { "error": "forbidden" }                    — non-internal employee (AC2)
--   { "error": "rbac_denied" }                  — no approved RBAC request (AC3)
--   { "error": "infra" }                        — RBAC/transport failure (CEL fail → 500)
--   { "active": true, "target_account_number", "target_org_id",
--     "employee_account_number", "employee_org_id" } — approved (AC1)
--
-- fetch() returns nil only when JSON encoding fails (unexpected).

local COOKIE_ACCOUNT = "cross_access_account_number"
local COOKIE_ORG = "cross_access_org_id"
local DEFAULT_RBAC_PATH = "/api/rbac/v1/cross-account-requests/"
local DEFAULT_EMAIL_SUFFIX = "@redhat.com"
local ROLE_EMPLOYEES = "redhat:employees"

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

local function resolve_claims(input)
  if input.subject ~= nil and input.subject.claims ~= nil then
    return input.subject.claims
  end
  return {}
end

local function resolve_user_id(claims)
  local user_id = claim_str(claims, "user_id")
  if user_id == "" then user_id = claim_str(claims, "sub") end
  return user_id
end

local function resolve_email(claims)
  return claim_str(claims, "email")
end

local function resolve_employee_account_org(claims)
  local account_number = org_field(claims, "account_number")
  if account_number == "" then account_number = claim_str(claims, "account_number") end
  if account_number == "" then account_number = claim_str(claims, "account_id") end

  local org_id = org_field(claims, "id")
  if org_id == "" then org_id = claim_str(claims, "org_id") end
  if org_id == "" then org_id = claim_str(claims, "rh-org-id") end
  if org_id == "" then org_id = account_number end

  return account_number, org_id
end

local function cookie_header(input)
  if input.request_attributes == nil or input.request_attributes.headers == nil then
    return ""
  end
  local headers = input.request_attributes.headers
  local cookie = headers.cookie
  if cookie == nil or cookie == "" then
    cookie = headers.Cookie
  end
  if cookie == nil then return "" end
  return tostring(cookie)
end

-- parse_cookie_value extracts the first value for a cookie name from a Cookie header.
local function parse_cookie_value(cookie_header, name)
  if cookie_header == nil or cookie_header == "" or name == nil or name == "" then
    return ""
  end
  for pair in string.gmatch(cookie_header, "[^;]+") do
    local k, v = pair:match("^%s*([^=]+)=(.*)$")
    if k ~= nil then
      k = k:match("^%s*(.-)%s*$")
      if k == name then
        local raw = v:match("^%s*(.-)%s*$")
        if raw == nil or raw == "" then return "" end
        if #raw >= 2 and raw:sub(1, 1) == '"' and raw:sub(-1) == '"' then
          raw = raw:sub(2, -2)
        end
        return raw
      end
    end
  end
  return ""
end

local function has_role(claims, role)
  if claims.realm_access == nil or claims.realm_access.roles == nil then
    return false
  end
  local roles = claims.realm_access.roles
  if type(roles) ~= "table" then return false end
  for _, r in ipairs(roles) do
    if tostring(r) == role then return true end
  end
  return false
end

local function config_bool(key, default)
  local v = config.get(key)
  if v == nil then return default end
  if type(v) == "boolean" then return v end
  if type(v) == "string" then
    return v == "true" or v == "1"
  end
  return default
end

local function resolve_is_internal(claims)
  if config_bool("cross_access_bypass_is_internal", false) then
    return true
  end

  local idp_target = config.get("internal_idp_target", "")
  local idp = claim_str(claims, "idp")
  if idp ~= "" and idp_target ~= "" then
    return idp == idp_target
  end

  local is_internal = claims.is_internal
  if is_internal ~= nil then
    return is_internal == true
  end

  if config_bool("role_fallback_enabled", false) then
    return has_role(claims, ROLE_EMPLOYEES)
  end

  return false
end

local function email_allowed(email)
  local suffix = config.get("employee_email_suffix", DEFAULT_EMAIL_SUFFIX)
  if suffix == nil or suffix == "" then suffix = DEFAULT_EMAIL_SUFFIX end
  if email == nil or email == "" then return false end
  if #email < #suffix then return false end
  return string.sub(email, -#suffix) == suffix
end

local function encode_result(payload)
  local encoded, err = json.encode(payload)
  if encoded == nil then return nil end
  return { data = encoded, content_type = "application/json" }
end

local function inactive()
  return encode_result({ active = false })
end

local function resolve_rbac_url(user_id, target_value, query_by)
  local path = config.get("rbac_path", DEFAULT_RBAC_PATH)
  if path == nil or path == "" then path = DEFAULT_RBAC_PATH end

  local approved_only = config.get("approved_only", "true")
  if approved_only == nil or approved_only == "" then approved_only = "true" end

  local param_name = "account"
  if query_by == "org_id" then param_name = "org_id" end

  local query = "?query_by=user_id"
    .. "&" .. param_name .. "=" .. url.encode(target_value)
    .. "&approved_only=" .. url.encode(tostring(approved_only))

  if string.find(path, "://", 1, true) then
    return path .. query
  end
  return path .. query
end

local function rbac_has_approved_request(user_id, target_value, query_by)
  local api_url = resolve_rbac_url(user_id, target_value, query_by)
  local response, err = http.get(api_url, {
    ["Accept"] = "application/json"
  })

  if response == nil then
    return nil, "infra"
  end

  if response.status >= 500 then
    return nil, "infra"
  end

  if response.status == 403 or response.status == 404 then
    return false, "rbac_denied"
  end

  if response.status ~= 200 then
    return nil, "infra"
  end

  local decoded, dec_err = json.decode(response.body)
  if decoded == nil then
    return nil, "infra"
  end

  if type(decoded) ~= "table" then
    return nil, "infra"
  end

  local data = decoded.data
  if data == nil then
    return false, "rbac_denied"
  end
  if type(data) ~= "table" then
    return nil, "infra"
  end

  if #data > 0 then
    return true, nil
  end

  return false, "rbac_denied"
end

function fetch(input)
  local claims = resolve_claims(input)
  local cookie_hdr = cookie_header(input)

  local target_account = parse_cookie_value(cookie_hdr, COOKIE_ACCOUNT)
  local target_org = parse_cookie_value(cookie_hdr, COOKIE_ORG)

  if target_account == "" and target_org == "" then
    return inactive()
  end

  if not resolve_is_internal(claims) then
    return encode_result({ error = "forbidden" })
  end

  local email = resolve_email(claims)
  if not email_allowed(email) then
    return encode_result({ error = "forbidden" })
  end

  local user_id = resolve_user_id(claims)
  if user_id == "" then
    return encode_result({ error = "infra" })
  end

  local query_by = config.get("cross_access_query_by", "account")
  if query_by == nil or query_by == "" then query_by = "account" end

  local target_value = target_account
  if query_by == "org_id" then
    target_value = target_org
  end

  if target_value == "" then
    return encode_result({ error = "rbac_denied" })
  end

  local approved, err_kind = rbac_has_approved_request(user_id, target_value, query_by)
  if err_kind == "infra" then
    return encode_result({ error = "infra" })
  end
  if not approved then
    return encode_result({ error = "rbac_denied" })
  end

  local employee_account, employee_org = resolve_employee_account_org(claims)

  return encode_result({
    active = true,
    target_account_number = target_account,
    target_org_id = target_org,
    employee_account_number = employee_account,
    employee_org_id = employee_org
  })
end

function fetch_cache_key(input)
  local claims = resolve_claims(input)
  local cookie_hdr = cookie_header(input)

  local target_account = parse_cookie_value(cookie_hdr, COOKIE_ACCOUNT)
  local target_org = parse_cookie_value(cookie_hdr, COOKIE_ORG)

  if target_account == "" and target_org == "" then
    return nil
  end

  local user_id = resolve_user_id(claims)
  if user_id == "" then
    return nil
  end

  return {
    subject = {
      claims = {
        sub = user_id
      }
    },
    request_attributes = {
      headers = {
        cookie = COOKIE_ACCOUNT .. "=" .. target_account .. "; " .. COOKIE_ORG .. "=" .. target_org
      }
    }
  }
end
