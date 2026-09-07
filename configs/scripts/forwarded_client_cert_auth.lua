-- Cert auth validator: authenticates certificate credentials against an
-- external back office proxy (BOP) service.
--
-- The HTTP client injecting x-rh-clientid and x-rh-apitoken headers is
-- configured at the http_clients level via http_auth.type: headers.
--
-- Config values:
--   bop_url                 (required) BOP base URL (e.g., https://bop.api.redhat.com)
--   trust_domain            (required) trust domain for validated results
--   issuer_host             (required) RHSM host for the issuer URI (e.g., "rhsm.stage.redhat.com", "rhsm.redhat.com")
--   bop_certauth_secret     (required) proxy proof secret for x-rh-insights-certauth-secret header
--   bop_env                 (required) environment value for x-rh-insights-env header (e.g., "stage", "prod")

function validate(input)
  local bop_url = config.get("bop_url")
  local trust_domain = config.get("trust_domain")
  local issuer_host = config.get("issuer_host")
  local bop_certauth_secret = config.get("bop_certauth_secret")
  local bop_env = config.has("bop_env") and config.get("bop_env") or "stage"

  local cn = input.credential.subject
  local cert_issuer = input.credential.issuer

  if cn == nil or cn == "" then
    return nil
  end

  if cert_issuer == nil or cert_issuer == "" then
    return nil
  end

  -- Extract the CN value from the subject string.
  -- Handles formats like "/CN=abc123" or "/O=foo/CN=abc123/I=bar".
  local cn_value = string.match(cn, "/CN=([^/]+)")
  if cn_value == nil then
    cn_value = cn
  end

  local response, err = http.get(bop_url .. "/v1/auth", {
    ["x-rh-insights-certauth-secret"] = bop_certauth_secret,
    ["x-rh-insights-env"] = bop_env,
    ["x-rh-certauth-cn"] = cn,
    ["x-rh-certauth-issuer"] = cert_issuer,
  })

  if response == nil then
    error("BOP service call failed: " .. (err or "unknown error"))
  end

  if response.status ~= 200 then
    return nil
  end

  local auth_resp = json.decode(response.body)
  if auth_resp == nil then
    return nil
  end

  if auth_resp.user == nil then
    return nil
  end

  local user = auth_resp.user
  local claims = {}
  if user.account_number ~= nil then
    claims.account_number = user.account_number
  end
  if user.org_id ~= nil then
    claims.org_id = user.org_id
  end
  if user.type ~= nil then
    claims.cert_type = user.type
  end
  claims.cn = cn_value

  return {
    subject = cn_value,
    issuer = "x509://" .. issuer_host .. "/" .. url.encode(cert_issuer),
    trust_domain = trust_domain,
    claims = claims
  }
end

function validate_cache_key(input)
  return {
    credential = {
      type = input.credential.type,
      subject = input.credential.subject,
      issuer = input.credential.issuer
    }
  }
end
