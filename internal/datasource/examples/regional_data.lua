-- Example Lua script that fetches region-specific data
-- This demonstrates using request attributes for routing

function fetch(input)
  local subject = input.subject.subject
  
  -- Determine region from request attributes
  local region = "us-east-1"  -- default
  
  if input.request_attributes ~= nil and input.request_attributes.headers ~= nil then
    local region_header = input.request_attributes.headers["X-Region"]
    if region_header ~= nil then
      region = region_header
    end
  end
  
  -- Get region-specific endpoint
  local base_url = config.get("api_endpoint")
  local api_key = config.get("api_key")
  
  -- Build region-specific URL
  local url = string.format("%s/%s/users/%s", base_url, region, subject)
  
  local headers = {
    ["Authorization"] = "Bearer " .. api_key,
    ["X-Region"] = region
  }
  
  local response = http.get(url, headers)
  
  if response == nil or response.status ~= 200 then
    -- Try fallback to default region
    print("Failed to fetch from " .. region .. ", trying default region")
    url = string.format("%s/us-east-1/users/%s", base_url, subject)
    response = http.get(url, headers)
    
    if response == nil or response.status ~= 200 then
      return nil
    end
  end
  
  local data = json.decode(response.body)
  if data == nil then
    return nil
  end
  
  -- Add region information to response
  data.region = region
  data.fetched_at = os.time()
  
  return {
    data = json.encode(data),
    content_type = "application/json"
  }
end

-- Cache based on subject AND region
function fetch_cache_key(input)
  local region = "us-east-1"  -- default
  
  if input.request_attributes ~= nil and input.request_attributes.headers ~= nil then
    local region_header = input.request_attributes.headers["X-Region"]
    if region_header ~= nil then
      region = region_header
    end
  end
  
  return {
    subject = {
      subject = input.subject.subject
    },
    request_attributes = {
      headers = {
        ["X-Region"] = region
      }
    }
  }
end

