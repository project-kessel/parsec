-- Example Lua script that fetches data from multiple sources
-- This demonstrates conditional logic, multiple HTTP calls, and data merging

function fetch(input)
  local subject = input.subject.subject
  local user_type = input.subject.claims.user_type or "standard"
  
  -- Different data sources based on user type
  if user_type == "admin" then
    return fetch_admin_data(subject)
  elseif user_type == "service" then
    return fetch_service_data(subject)
  else
    return fetch_standard_user_data(subject)
  end
end

function fetch_admin_data(subject)
  local api_key = config.get("api_key")
  local base_url = config.get("api_endpoint")
  
  -- Fetch both user profile and admin permissions
  local profile = fetch_json(base_url .. "/users/" .. subject, api_key)
  local permissions = fetch_json(base_url .. "/admin/permissions/" .. subject, api_key)
  
  if profile == nil or permissions == nil then
    return nil
  end
  
  -- Merge the data
  local result = {
    profile = profile,
    permissions = permissions,
    user_type = "admin"
  }
  
  return {
    data = json.encode(result),
    content_type = "application/json"
  }
end

function fetch_service_data(subject)
  local api_key = config.get("api_key")
  local base_url = config.get("api_endpoint")
  
  -- Service accounts need different data
  local service_info = fetch_json(base_url .. "/services/" .. subject, api_key)
  
  if service_info == nil then
    return nil
  end
  
  service_info.user_type = "service"
  
  return {
    data = json.encode(service_info),
    content_type = "application/json"
  }
end

function fetch_standard_user_data(subject)
  local api_key = config.get("api_key")
  local base_url = config.get("api_endpoint")
  
  local profile = fetch_json(base_url .. "/users/" .. subject, api_key)
  
  if profile == nil then
    return nil
  end
  
  profile.user_type = "standard"
  
  return {
    data = json.encode(profile),
    content_type = "application/json"
  }
end

-- Helper function to fetch and parse JSON
function fetch_json(url, api_key)
  local headers = {
    ["Authorization"] = "Bearer " .. api_key,
    ["Accept"] = "application/json"
  }
  
  local response, err = http.get(url, headers)
  
  if response == nil then
    print("HTTP error: " .. err)
    return nil
  end
  
  if response.status ~= 200 then
    print("Non-200 status: " .. response.status)
    return nil
  end
  
  local data, err = json.decode(response.body)
  if data == nil then
    print("JSON decode error: " .. err)
    return nil
  end
  
  return data
end

-- Cache based on subject and user type
function fetch_cache_key(input)
  return {
    subject = {
      subject = input.subject.subject,
      claims = {
        user_type = input.subject.claims.user_type
      }
    }
  }
end

