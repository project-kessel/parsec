-- BOP user resolver: resolves a plain username to a full user object by
-- calling BOP's /v1/users endpoint.
--
-- This validator fires for opaque bearer tokens (plain usernames). The JWT
-- validator runs first by registration order and rejects non-JWT tokens.
--
-- Config values:
--   bop_url       (required) BOP base URL
--   users_path    (required) path to the users endpoint (e.g. "/v1/users")
--   trust_domain  (required) trust domain for validated results
--   api_token     (required) x-rh-apitoken header value
--   client_id     (required) x-rh-clientid header value
--   environment   (required) x-rh-insights-env header value

function validate(input)
  local bop_url = config.get("bop_url")
  if bop_url == nil or bop_url == "" then
    error("bop_url config is required")
  end
  local api_token = config.get("api_token")
  if api_token == nil or api_token == "" then
    error("api_token config is required")
  end

  local username = input.credential.token
  if username == nil or username == "" then
    return nil
  end

  local url = bop_url .. config.get("users_path") .. "?queryBy=userId"
  local body = json.encode({users = {username}})

  local response, err = http.post(url, body, {
    ["x-rh-apitoken"]     = config.get("api_token"),
    ["x-rh-clientid"]     = config.get("client_id"),
    ["x-rh-insights-env"] = config.get("environment"),
    ["Content-Type"]      = "application/json",
    ["Accept"]            = "application/json"
  })

  if response == nil then
    error("BOP service call failed: " .. (err or "unknown error"))
  end

  if response.status ~= 200 then
    error("BOP returned HTTP " .. tostring(response.status))
  end

  local users = json.decode(response.body)
  if users == nil or #users ~= 1 then
    return nil
  end

  local user = users[1]
  if user.org_id == nil or user.id == nil then
    return nil
  end

  return {
    subject = tostring(user.id),
    issuer = config.get("bop_url"),
    trust_domain = config.get("trust_domain"),
    claims = {
      org_id         = tostring(user.org_id),
      account_number = tostring(user.account_number),
      email          = user.email,
      first_name     = user.first_name,
      last_name      = user.last_name,
      is_org_admin   = user.is_org_admin,
      is_internal    = user.is_internal,
      is_active      = user.is_active,
      locale         = user.locale,
      user_id        = tostring(user.id),
      username       = user.username,
      identity_source = "bop"
    }
  }
end

function validate_cache_key(input)
  return {
    credential = {
      type = input.credential.type,
      token = input.credential.token
    }
  }
end
