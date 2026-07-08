-- Registry auth validator: authenticates Basic Auth credentials against an
-- external registry authorization service.
--
-- Config values:
--   registry_url      (required) HTTPS endpoint that accepts POST {"credentials":{...}}
--   trust_domain      (required) trust domain for validated results
--   username_pattern   (optional) Lua pattern that username must match

function validate(input)
  local registry_url = config.get("registry_url")
  local trust_domain = config.get("trust_domain")
  local username_pattern = config.get("username_pattern")

  local username = input.credential.username
  local password = input.credential.password

  if username == nil or username == "" or password == nil or password == "" then
    return nil
  end

  if username_pattern and not string.match(username, username_pattern) then
    return nil
  end

  local pipe_pos = string.find(username, "|", 1, true)
  if pipe_pos == nil then
    return nil
  end

  local org_id = string.sub(username, 1, pipe_pos - 1)
  local parsed_username = string.sub(username, pipe_pos + 1)

  if parsed_username == "" then
    return nil
  end

  local body = json.encode({
    credentials = {
      username = username,
      password = password
    }
  })

  local response, err = http.post(registry_url, body, {
    ["Content-Type"] = "application/json"
  })

  if response == nil then
    error("registry service call failed: " .. (err or "unknown error"))
  end

  if response.status ~= 200 then
    return nil
  end

  local auth_resp = json.decode(response.body)
  if auth_resp == nil or auth_resp.access == nil or auth_resp.access.pull ~= "granted" then
    return nil
  end

  local claims = {}
  if org_id ~= "" then
    claims.org_id = org_id
  end

  return {
    subject = parsed_username,
    issuer = registry_url,
    trust_domain = trust_domain,
    claims = claims
  }
end

function validate_cache_key(input)
  return {
    credential = {
      type = input.credential.type,
      username = input.credential.username,
      password = input.credential.password
    }
  }
end
