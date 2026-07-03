-- Example Lua script for fetching user data from an external API
-- This demonstrates how to use the HTTP, JSON, and Config services

function fetch(input)
  -- Get configuration values
  local api_endpoint = config.get("api_endpoint", "https://api.example.com")
  local api_key = config.get("api_key")
  local timeout = config.get("timeout", 30)
  
  if api_key == nil then
    error("api_key is required in config")
  end
  
  -- Extract subject information
  local subject = input.subject.subject
  local issuer = input.subject.issuer
  
  -- Build the URL
  local url = api_endpoint .. "/users/" .. subject
  
  -- Prepare headers
  local headers = {
    ["Authorization"] = "Bearer " .. api_key,
    ["Content-Type"] = "application/json",
    ["Accept"] = "application/json"
  }
  
  -- Make HTTP request
  local response, err = http.get(url, headers)
  
  if response == nil then
    error("Failed to fetch user data: " .. err)
  end
  
  -- Handle non-200 responses
  if response.status == 404 then
    -- User not found is not fatal, just return nil
    return nil
  elseif response.status ~= 200 then
    error("API returned status " .. response.status)
  end
  
  -- Parse JSON response
  local user_data, err = json.decode(response.body)
  if user_data == nil then
    error("Failed to decode JSON response: " .. err)
  end
  
  -- Enhance the data with additional context
  user_data.fetched_at = os.time()
  user_data.source_issuer = issuer
  user_data.data_source = "lua-user-data"
  
  -- Return the enriched data
  return {
    data = json.encode(user_data),
    content_type = "application/json"
  }
end

-- Optional: Define cache key function for caching support
-- This tells the caching layer what parts of the input affect the result
function fetch_cache_key(input)
  -- We only cache based on the subject identifier
  -- Changes to other fields (like request attributes) won't affect the result
  return {
    subject = {
      subject = input.subject.subject
    }
  }
end

