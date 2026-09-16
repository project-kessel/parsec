-- BOP (Back Office Proxy) user enrichment data source.
--
-- Fetches user details from BOP /v1/users for a given user id (queryBy=userId),
-- returning org_id, account_number, email, and other profile fields
-- needed by the CEL claim mapper to build x-rh-identity.
--
-- If input.subject.subject is prefixed "redhat:user:sso:", the prefix is
-- stripped before the lookup so txn-token subs stay namespaced.
-- Unprefixed subjects are sent as-is.
--
-- Fail-closed semantics:
--   nil              → infrastructure error (HTTP failure, decode error, ambiguous match)
--   {error=...}     → user not found or missing required fields (client error)
--   {data=..., ...} → enriched user profile
--
-- The HTTP client injecting x-rh-clientid and x-rh-apitoken headers is
-- configured at the http_clients level via http_auth.type: headers.
--
-- Config values:
--   bop_url     (required) BOP base URL, e.g. "https://backoffice-proxy.example.com"
--   users_path  (optional) path for user lookup, defaults to "/v1/users"
--   bop_env     (optional) x-rh-insights-env value, defaults to "stage"

function fetch(input)
  local username = input.subject.subject
  if username == nil or username == "" then
    return nil
  end

  -- Namespaced SSO subjects keep the prefix on Result.Subject (for txn-token
  -- uniqueness) but BOP looks up the bare user id.
  local prefix = "redhat:user:sso:"
  if string.sub(username, 1, #prefix) == prefix then
    username = string.sub(username, #prefix + 1)
    if username == "" then
      return nil
    end
  end

  local bop_url = config.get("bop_url")
  if bop_url == nil or bop_url == "" then
    audit.record({
      source = "data_source",
      operation = "user_enrichment",
      outcome = "failure",
      reason_code = "supplemental_user_data_failure",
    })
    return nil
  end

  local users_path = config.get("users_path", "/v1/users")
  local bop_env = config.has("bop_env") and config.get("bop_env") or "stage"

  local url = bop_url .. users_path .. "?queryBy=userId"

  local body = json.encode({ users = { username } })

  local headers = {
    ["x-rh-insights-env"] = bop_env,
    ["Content-Type"]      = "application/json",
    ["Accept"]            = "application/json"
  }

  local response, err = http.post(url, body, headers)

  if response == nil then
    audit.record({
      source = "data_source",
      operation = "user_enrichment",
      outcome = "failure",
      reason_code = "supplemental_user_data_failure",
    })
    return nil
  end

  if response.status ~= 200 then
    audit.record({
      source = "data_source",
      operation = "user_enrichment",
      outcome = "failure",
      reason_code = "supplemental_user_data_failure",
    })
    return nil
  end

  local users, decode_err = json.decode(response.body)
  if users == nil then
    audit.record({
      source = "data_source",
      operation = "user_enrichment",
      outcome = "failure",
      reason_code = "supplemental_user_data_failure",
    })
    return nil
  end

  if type(users) ~= "table" then
    audit.record({
      source = "data_source",
      operation = "user_enrichment",
      outcome = "failure",
      reason_code = "supplemental_user_data_failure",
    })
    return nil
  end

  -- BOP returns a JSON array; we require exactly one match.
  -- Distinguish "user not found" from infrastructure errors so callers
  -- can return an appropriate OAuth error code.
  if #users == 0 then
    return {
      data = json.encode({ error = "user_not_found" }),
      content_type = "application/json"
    }
  end

  if #users ~= 1 then
    return nil
  end

  local user = users[1]

  if user.org_id == nil or user.id == nil or user.is_active == nil then
    return {
      data = json.encode({ error = "user_not_found" }),
      content_type = "application/json"
    }
  end

  local result = {
    org_id         = tostring(user.org_id),
    account_number = user.account_number,
    email          = user.email,
    first_name     = user.first_name,
    last_name      = user.last_name,
    is_org_admin   = user.is_org_admin,
    is_internal    = user.is_internal,
    is_active      = user.is_active,
    locale         = user.locale,
    user_id        = tostring(user.id),
    username       = user.username
  }

  return {
    data = json.encode(result),
    content_type = "application/json"
  }
end

function fetch_cache_key(input)
  return {
    subject = {
      subject = input.subject.subject
    }
  }
end
