-- Example Lua script for fetching user data from an external API
-- This demonstrates how to use the HTTP, JSON, URL, and Config services
--
-- Security notes (see ../LUA_DATASOURCE.md, "Security Model"):
--   * The host is fixed by the HTTP client's base_url. The script only builds a
--     relative path, so token claims can never change which host is called.
--   * The subject comes from a token and is untrusted. url.path_escape keeps it
--     inside a single path segment ("/", "?", "#", "." and ".." are encoded).
--   * Credentials are injected by the HTTP client (http_auth), not by the
--     script, which also forces base_url to use https.
--
-- Example configuration:
--
--   data_sources:
--     - name: user_data
--       type: lua
--       script_file: ./scripts/user_data.lua
--       http:
--         timeout: 5s
--         base_url: "https://api.example.com"
--         http_auth:
--           type: bearer
--           token: "${USER_API_TOKEN}"
--       max_response_bytes: 65536

function fetch(input)
  -- Extract subject information
  local subject = input.subject.subject
  local issuer = input.subject.issuer

  if subject == nil or subject == "" then
    return nil
  end

  -- Build a relative URL. The base_url on the HTTP client supplies scheme and
  -- host; the escaped subject cannot add path segments, a query, or a fragment.
  local path = "/users/" .. url.path_escape(subject)

  local headers = {
    ["Accept"] = "application/json"
  }

  -- Make HTTP request. Returns (nil, err) on transport errors, URL validation
  -- errors, or when the body exceeds max_response_bytes.
  local response, err = http.get(path, headers)

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
  local user_data, decode_err = json.decode(response.body)
  if user_data == nil then
    error("Failed to decode JSON response: " .. decode_err)
  end

  -- Enhance the data with additional context
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
