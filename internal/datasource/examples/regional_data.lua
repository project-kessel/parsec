-- Example Lua script that fetches region-specific data
-- This demonstrates using request attributes for routing
--
-- The X-Region header and the subject are caller-controlled, so both are
-- escaped with url.path_escape before being placed in the URL path. The host
-- comes from the HTTP client's base_url, never from request input.

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
  
  local escaped_subject = url.path_escape(subject)

  -- Build region-specific relative URL (resolved against the client base_url)
  local path = string.format("/%s/users/%s", url.path_escape(region), escaped_subject)
  
  local headers = {
    ["X-Region"] = region
  }
  
  local response = http.get(path, headers)
  
  if response == nil or response.status ~= 200 then
    -- Try fallback to default region
    print("Failed to fetch from " .. region .. ", trying default region")
    path = "/us-east-1/users/" .. escaped_subject
    response = http.get(path, headers)
    
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

