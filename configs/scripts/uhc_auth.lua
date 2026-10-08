-- UHC auth validator: authenticates OpenShift in-cluster operators that present
-- an OCM cluster token.
--
-- The credential is the pair (Authorization, User-Agent): the token cannot be
-- validated locally, and the cluster id travels in the User-Agent rather than
-- in the token, so both headers are part of the credential.
--
-- The cluster's own token is the only secret involved; there is no gateway-side
-- credential, so the HTTP client needs no http_auth.
--
-- Config values:
--   current_account_url  (required) OCM current_account endpoint (absolute URL)
--   trust_domain         (required) trust domain for validated results
--   issuer               (required) issuer URI for validated results (uhc://...)

-- Operators allowed to authenticate this way. The credential source matches a
-- looser pattern as a cheap routing decision; this table is the authoritative
-- allowlist.
local ALLOWED_PREFIXES = {
  "insights-operator/",
  "cost-mgmt-operator/",
  "marketplace-operator/",
  "acm-operator/",
  "assisted-installer-operator/",
  "cryostat-operator/",
  "openshift-lightspeed-operator/",
  "jws-operator/",
  "runtimes-inventory-operator/",
}

local function is_allowed_operator(agent)
  for i = 1, #ALLOWED_PREFIXES do
    local prefix = ALLOWED_PREFIXES[i]
    if string.sub(agent, 1, #prefix) == prefix then
      return true
    end
  end
  return false
end

-- Parses "<operator>/<version> cluster/<id>" and returns the cluster id, or nil
-- when the User-Agent does not identify an allowed operator's cluster.
local function parse_cluster_id(user_agent)
  if user_agent == nil or user_agent == "" then
    return nil
  end

  local space_pos = string.find(user_agent, " ", 1, true)
  if space_pos == nil then
    return nil
  end

  local agent = string.sub(user_agent, 1, space_pos - 1)
  local cluster = string.sub(user_agent, space_pos + 1)

  if not is_allowed_operator(agent) then
    return nil
  end

  if string.sub(cluster, 1, 8) ~= "cluster/" then
    return nil
  end

  local cluster_id = string.sub(cluster, 9)
  if cluster_id == "" then
    return nil
  end

  return cluster_id
end

function validate(input)
  local current_account_url = config.get("current_account_url")
  local trust_domain = config.get("trust_domain")
  local issuer = config.get("issuer")

  local headers = input.credential.headers
  if headers == nil then
    return nil
  end

  -- A distributed cache fills from the cache key alone, so validate also has
  -- to accept the key's shape, which carries the cluster id directly. The
  -- header credential source only captures the headers named in its config,
  -- so a cluster_id sent by a client never reaches here.
  local cluster_id = headers["cluster_id"] or parse_cluster_id(headers["user-agent"])
  if cluster_id == nil then
    return nil
  end

  local authorization = headers["authorization"]
  if authorization == nil then
    return nil
  end

  local token = string.match(authorization, "^Bearer%s+(.+)$")
  if token == nil or token == "" then
    return nil
  end

  -- OCM authenticates cluster tokens under a custom scheme; this is not a
  -- Bearer passthrough.
  local response, err = http.get(current_account_url, {
    ["Authorization"] = "AccessToken " .. cluster_id .. ":" .. token,
    ["Accept"] = "application/json",
    ["Content-Type"] = "application/json",
  })

  if response == nil then
    error("OCM current_account call failed: " .. (err or "unknown error"))
  end

  if response.status ~= 200 then
    return nil
  end

  local account = json.decode(response.body)
  if account == nil or account.organization == nil then
    return nil
  end

  local org_id = account.organization.external_id
  if org_id == nil or org_id == "" or org_id == "null" then
    return nil
  end

  local claims = {
    org_id = org_id,
    cluster_id = cluster_id,
  }

  -- Legitimately empty for organizations without an EBS account.
  local account_number = account.organization.ebs_account_id
  if account_number ~= nil and account_number ~= "" then
    claims.account_number = account_number
  end

  return {
    subject = cluster_id,
    issuer = issuer,
    trust_domain = trust_domain,
    claims = claims
  }
end

function validate_cache_key(input)
  local headers = input.credential.headers or {}
  return {
    credential = {
      type = input.credential.type,
      headers = {
        ["authorization"] = headers["authorization"],
        ["cluster_id"] = parse_cluster_id(headers["user-agent"]),
      }
    }
  }
end
