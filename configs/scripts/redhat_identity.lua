-- Red Hat Identity Transformation (Lua)
--
-- Lua translation of redhat_identity.cel. Transforms JWT claims into
-- a Red Hat x-rh-identity envelope: { identity = { ... }, entitlements = {} }

local function has_role(c, role_name)
  if c == nil then return false end
  local ra = c["realm_access"]
  if ra == nil then return false end
  local roles = ra["roles"]
  if roles == nil then return false end
  for _, r in ipairs(roles) do
    if r == role_name then return true end
  end
  return false
end

local function is_service_account_token(c)
  if c == nil then return false end
  local pu = c["preferred_username"]
  if type(pu) ~= "string" then return false end
  return pu:sub(1, 16) == "service-account-"
end

local function is_console_api_token(c)
  if c == nil then return false end
  local scope = c["scope"]
  if type(scope) ~= "string" then return false end
  return scope:find("api.console", 1, true) ~= nil
end

local function safe_to_string(val)
  if val == nil then return "" end
  return tostring(val)
end

local function contains_audience(aud, target)
  if aud == nil then return false end
  for _, a in ipairs(aud) do
    if a == target then return true end
  end
  return false
end

local function get_org(c)
  if c == nil then return nil end
  return c["organization"]
end

local function auth_time(c)
  if c ~= nil and c["iat"] ~= nil then
    return c["iat"] * 1000
  end
  return now_ms()
end

local function is_internal_console_api(c, policy)
  local idp = c["idp"]
  if idp == policy.internal_idp_target then
    return true
  end
  if c["is_internal"] ~= nil then
    return c["is_internal"]
  end
  if policy.role_fallback_enabled then
    return has_role(c, "redhat:employees")
  end
  return false
end

local function is_internal_audience_based(c, policy)
  if c["idp"] ~= nil then
    return c["idp"] == policy.internal_idp_target
  end
  if c["is_internal"] ~= nil then
    return c["is_internal"]
  end
  if policy.role_fallback_enabled then
    return has_role(c, "redhat:employees")
  end
  return false
end

local function string_claim(c, key)
  if c == nil then return "" end
  local v = c[key]
  if type(v) == "string" then return v end
  return ""
end

local function first_string(c, k1, k2)
  local v = string_claim(c, k1)
  if v ~= "" then return v end
  return string_claim(c, k2)
end

local function first_safe_string(c, k1, k2)
  if c[k1] ~= nil then return safe_to_string(c[k1]) end
  if c[k2] ~= nil then return safe_to_string(c[k2]) end
  return ""
end

function map(input)
  local sub = input.subject
  local c = nil
  if sub ~= nil then c = sub.claims end

  -- Impersonation guard
  if c ~= nil and c["impersonated"] == true then
    invalid_subject("impersonated tokens are not accepted")
  end

  -- Registry Auth
  if sub ~= nil and sub.issuer ~= nil
     and string.find(sub.issuer, "container-registry-authorizer", 1, true)
     and string.find(sub.issuer, "api.redhat.com", 1, true) then
    local org_id = nil
    if c ~= nil then org_id = c["org_id"] end
    return {
      identity = {
        auth_type = "registry-auth",
        org_id = org_id,
        type = "User",
        user = { username = sub.subject or "" },
        internal = {
          org_id = org_id,
          cross_access = false,
          auth_time = now_ms(),
        },
      },
      entitlements = {},
    }
  end

  -- Service Account
  if c ~= nil and is_service_account_token(c) then
    local org = get_org(c)
    local org_id = string_claim(c, "rh-org-id")
    if org_id == "" then org_id = string_claim(org, "id") end

    local client_id = string_claim(c, "client_id")
    if client_id == "" then client_id = string_claim(c, "clientId") end
    if client_id == "" then fail("missing_client_id") end

    return {
      identity = {
        auth_type = "jwt-auth",
        account_number = string_claim(org, "account_number"),
        org_id = org_id,
        type = "ServiceAccount",
        service_account = {
          username = string_claim(c, "preferred_username"),
          client_id = client_id,
          user_id = string_claim(c, "sub"),
          scope = string_claim(c, "scope"),
        },
        internal = {
          org_id = org_id,
          cross_access = false,
          auth_time = auth_time(c),
        },
      },
      entitlements = {},
    }
  end

  -- Console API: missing idp guard
  if c ~= nil and is_console_api_token(c) and c["idp"] == nil then
    invalid_subject("claim 'idp' is required")
  end

  -- Console API
  if c ~= nil and is_console_api_token(c) then
    local policy = datasource.get("identity-policy")
    local org = get_org(c)
    local org_id = string_claim(org, "id")

    return {
      identity = {
        auth_type = "jwt-auth",
        account_number = string_claim(org, "account_number"),
        org_id = org_id,
        type = "User",
        user = {
          username = string_claim(c, "preferred_username"),
          email = string_claim(c, "email"),
          first_name = string_claim(c, "given_name"),
          last_name = string_claim(c, "family_name"),
          is_active = true,
          is_org_admin = has_role(c, "admin:org:all"),
          is_internal = is_internal_console_api(c, policy),
          locale = string_claim(c, "locale"),
          user_id = safe_to_string(c["user_id"]),
        },
        internal = {
          org_id = org_id,
          cross_access = false,
          auth_time = auth_time(c),
        },
      },
      entitlements = {},
    }
  end

  -- RHSM API
  if sub ~= nil and contains_audience(sub.audience, "rhsm-api") then
    local policy = datasource.get("identity-policy")
    local org = get_org(c)

    local org_id = string_claim(org, "id")
    if org_id == "" then org_id = safe_to_string(c["org_id"]) end
    if org_id == "" then org_id = safe_to_string(c["account_id"]) end

    return {
      identity = {
        auth_type = "jwt-auth",
        account_number = safe_to_string(c["account_id"]),
        org_id = org_id,
        type = "User",
        user = {
          username = first_string(c, "preferred_username", "username"),
          email = string_claim(c, "email"),
          first_name = first_string(c, "given_name", "firstName"),
          last_name = first_string(c, "family_name", "lastName"),
          is_active = true,
          is_org_admin = has_role(c, "admin:org:all"),
          is_internal = is_internal_audience_based(c, policy),
          locale = first_string(c, "locale", "lang"),
          user_id = first_safe_string(c, "sub", "user_id"),
        },
        internal = {
          org_id = org_id,
          cross_access = false,
          auth_time = auth_time(c),
        },
      },
      entitlements = {},
    }
  end

  -- Customer Portal
  if sub ~= nil and contains_audience(sub.audience, "customer-portal") then
    local policy = datasource.get("identity-policy")
    local org = get_org(c)

    local account_number = safe_to_string(c["account_number"])
    if account_number == "" then account_number = string_claim(org, "account_number") end

    local org_id = string_claim(org, "id")
    if org_id == "" then org_id = safe_to_string(c["org_id"]) end

    return {
      identity = {
        auth_type = "jwt-auth",
        account_number = account_number,
        org_id = org_id,
        type = "User",
        user = {
          username = first_string(c, "username", "preferred_username"),
          email = string_claim(c, "email"),
          first_name = first_string(c, "firstName", "given_name"),
          last_name = first_string(c, "lastName", "family_name"),
          is_active = true,
          is_org_admin = has_role(c, "admin:org:all"),
          is_internal = is_internal_audience_based(c, policy),
          locale = first_string(c, "lang", "locale"),
          user_id = first_safe_string(c, "user_id", "sub"),
        },
        internal = {
          org_id = org_id,
          cross_access = false,
          auth_time = auth_time(c),
        },
      },
      entitlements = {},
    }
  end

  unsupported_token_type("unsupported_token_type")
end
