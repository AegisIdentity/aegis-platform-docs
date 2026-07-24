# Aegis Platform — Security Review

**Date:** 2026-07-24
**Scope:** All 13 repositories in the Aegis identity platform (`authserver/aegis-*`)
**Method:** Source-level audit of `src/main`, `application.yml`, Dockerfiles, `pom.xml`, Terraform, Helm, Docker Compose, and CI. `target/` build output excluded. Every finding below was verified by reading the cited file.

---

## Executive summary

The platform is **security-conscious by design** — PKCE mandatory, no implicit/ROPC grants, per-tenant RSA signing keys (RS256, no `alg:none`), Argon2id password hashing, tenant-scoped repositories, verified-email federation guards, TLS-forced Postgres, IMDSv2-only nodes, RBAC-only Key Vault, and strong connector-token hygiene (256-bit random, SHA-256 stored). Most services run as non-root with `health`-only actuator exposure.

The findings concentrate in three themes:

1. **Fail-open defaults that ship known credentials to production** — the single most dangerous class here. Two independent seeders bake publicly-known secrets/passwords into any deploy that forgets a flag.
2. **Secrets stored in plaintext at rest** — TOTP seeds, upstream IdP client secrets, and (because Terraform state backends are disabled) database master credentials in local state files.
3. **Incomplete authorization boundaries** — cross-tenant reads, an overloaded `tenant:admin` scope, and an implicit `SUPER_ADMIN` grant that nullify the fine-grained RBAC.

No finding is *unconditionally* exploitable against a correctly-configured prod deployment, which is why nothing is rated Critical outright. But the top two High items are one missing environment variable away from being a Critical, unauthenticated backdoor — they should be treated as release blockers.

### Counts

| Severity | Count |
|---|---|
| Critical | 0 (2 High items become Critical if their prod overrides are omitted — see H1/H2) |
| High | 12 |
| Medium | 23 |
| Low / Informational | 20+ |

### Fix first (release blockers)

1. **H1 / H2** — Guard the two credential seeders; never ship known secrets. *(core auth)*
2. **H8 / H9** — Enable Terraform state backends and prod AKS Entra RBAC before any stage/prod apply. *(infra)*
3. **H3 / H4** — Close the cross-tenant IDOR and split the `tenant:admin` scope. *(tenant service)*
4. **H10** — Pin `trivy-action@master` to a SHA in privileged CI. *(infra supply chain)*

---

## HIGH

### H1 — OAuth2 clients with known/default secrets are seeded unconditionally in every environment
**Repo:** aegis-authorization-server
**File:** `config/AuthorizationServerConfig.java:157` (`devClientSeeder`), secret at `:212` (`.clientSecret("{noop}dev-only-change-me")`)

The `devClientSeeder` `ApplicationRunner` has **no `@Profile` / `@ConditionalOnProperty` guard** (unlike `DevDataSeeder`, which at least has an annotation — verified). On every startup, **including production**, it upserts `aegis-dev-m2m` with the hardcoded plaintext secret `{noop}dev-only-change-me`. Because the client uses a stable ID, `save` upserts — so even if an operator edits the row, the next restart restores the known secret.

**Why it must be fixed:** The secret is in source anyone can read. `aegis-dev-m2m` carries `tenant=dev` + `client_credentials` grant with scopes `identity:users:read`, `tenant:read`. An attacker mints a valid access token for the `dev` tenant and reads its users with zero user interaction. Scoped to the `dev` tenant (hence High not Critical), but combined with H2 it is a coherent, shipped-by-default backdoor.
**Fix:** Guard with `@Profile("dev")`. Never seed a `{noop}` secret. Require `AEGIS_M2M_CLIENT_SECRET` with no default; fail startup if unset outside dev.

### H2 — Dev admin seeder is on by default (fail-open) with a known password
**Repo:** aegis-identity-service
**File:** `config/DevDataSeeder.java:18` — `@ConditionalOnProperty(name = "aegis.identity.seed-dev-admin", havingValue = "true", matchIfMissing = true)`

The seeder runs **unless explicitly disabled**, creating org `dev` / user `dev-user` with password `dev-only-change-me`.

**Why it must be fixed:** A prod deploy that forgets `aegis.identity.seed-dev-admin=false` gets a live admin account with a publicly-known password. Fail-open is the wrong default for a credential seeder.
**Fix:** Flip to `matchIfMissing = false` (opt-in) or gate on `@Profile("dev")`. Never seed a fixed password.

### H3 — Cross-tenant IDOR: tenant lookup/resolve endpoints are not scoped to the caller's tenant
**Repo:** aegis-tenant-service
**Files:** `web/TenantController.java:34-43`, `config/SecurityConfig.java:29-30`

`GET /api/v1/tenants/{slug}` and `/api/v1/tenants:resolve` accept an arbitrary slug/domain and return the matching tenant, gated **only** by `SCOPE_tenant:read` — with no ownership check against the caller's JWT `tenant` claim. (The sibling `CustomDomainController` does this correctly via `tenantOf(caller)`.)

**Why it must be fixed:** Any tenant admin can read **any other tenant's** metadata (id, name, slug, primaryDomain, status) by enumerating human-readable slugs or probing domains. This directly violates the platform's stated "No cross-tenant reads" non-negotiable — textbook broken object-level authorization (OWASP API1).
**Fix:** Derive the tenant from the JWT and 404 when the slug/domain isn't the caller's, unless the caller holds a distinct platform-operator scope.

### H4 — Overloaded `tenant:admin` scope lets any tenant admin create arbitrary top-level tenants
**Repo:** aegis-tenant-service
**Files:** `web/TenantController.java:27-32`, `config/SecurityConfig.java:28,35`

`POST /api/v1/tenants` (create a whole organization) requires the **same** `tenant:admin` scope that a tenant uses for its own self-service custom-domain management.

**Why it must be fixed:** A regular tenant admin can create new top-level tenants — squatting issuer slugs (slugs become per-tenant OIDC issuer paths `/{slug}`) or claiming a competitor's `primaryDomain` string, or mass-creating tenants. Privilege-boundary violation between tenant-level and platform-level administration.
**Fix:** Gate tenant creation behind a dedicated platform-operator scope, distinct from per-tenant `tenant:admin`.

### H5 — TOTP shared secrets stored in plaintext at rest
**Repo:** aegis-mfa-webauthn-service
**File:** `domain/TotpCredential.java:34-36` (`secret_base32` plain String), written at `service/TotpService.java:39,42`

TOTP seeds are persisted unencrypted (the entity Javadoc admits this is a known follow-up).

**Why it must be fixed:** A TOTP seed is a permanent second factor. Any DB read access (SQL injection elsewhere, stolen backup, compromised replica, over-broad DBA) yields every user's seed, letting an attacker generate valid codes indefinitely and silently defeat MFA. Unlike a password hash, there is **no** one-way protection here.
**Fix:** Envelope-encrypt the seed (KMS-wrapped data key) or an AES-GCM `AttributeConverter` keyed from a secret manager.

### H6 — No brute-force / rate limiting on MFA verification
**Repo:** aegis-mfa-webauthn-service
**Files:** `service/TotpService.java:63-72`, `web/InternalMfaController.java:64-68`

`validate()` accepts unlimited guesses. With 6 digits and `allowedSkewSteps=1` (3 valid windows at any instant) there is no lockout and no per-subject throttle.

**Why it must be fixed:** An attacker holding the first factor (password) scripts TOTP guesses against `/api/v1/mfa/internal/totp/validate`. At a few hundred req/s the ~333k-guess expectation to land one of the 3 valid codes within a 30s window is reachable — full second-factor bypass. Rate-limiting TOTP verification is the standard, non-optional control.
**Fix:** Per-(tenant,subject) failed-attempt counter with exponential backoff/lockout after ~5 failures; reset on success; plus an edge rate limit.

### H7 — Expired WebAuthn assertion challenges are never garbage-collected
**Repo:** aegis-mfa-webauthn-service
**File:** `service/WebAuthnService.java:258-260` (assertion challenge saved), no `@Scheduled` cleanup / no `deleteExpired` (verified absent)

Assertion challenge rows are only removed on a *matching* verify; abandoned ceremonies leave rows forever.

**Why it must be fixed:** An authenticated AS-scoped caller (or a login-UI bug) can create challenge rows without bound — storage-exhaustion / DoS against the MFA store, and stale challenge material outlives its 300s TTL. (Replay is *not* the issue — verify checks expiry and consumes one-time.)
**Fix:** Scheduled job or DB TTL deleting `expiresAt < now()`; delete stale assertion challenges as registration challenges already are.

### H8 — All eight Terraform remote-state backends are commented out while state holds live secrets
**Repo:** aegis-platform-infra
**Files:** every `terraform/{aws,azure}/envs/*/backend.tf:1-11` (empty `terraform {}` blocks)

Secrets that land in state: the Redis AUTH token (`modules/aws/redis/main.tf:23-38`) and the Azure Postgres admin password (`modules/azure/stack/main.tf:124-128` — whose comment claims it "lands only in encrypted remote state," currently false).

**Why it must be fixed:** A prod `apply` today writes the production DB master credential path and cache AUTH token into an **unencrypted local `terraform.tfstate`** on whatever laptop/runner ran it — outside any access control, backup, or locking. Workstation loss = credential loss; no locking also risks state corruption on concurrent applies.
**Fix:** Bootstrap the S3 bucket / Azure storage account and uncomment the backends *before* any stage/prod apply. Make "backend enabled" a hard CI gate.

### H9 — "Hardened" prod/stage AKS ships with local admin accounts enabled and no Entra ID RBAC
**Repo:** aegis-platform-infra
**Files:** `terraform/azure/envs/{prod,stage}/main.tf:20-27` never pass `admin_group_object_ids` (default `[]`); `modules/azure/aks/main.tf:22` makes `local_account_disabled` and the AAD RBAC block conditional on that being non-empty.

**Why it must be fixed:** Prod gets `local_account_disabled = false` and no Azure RBAC — so anyone with `listClusterAdminCredential` rights obtains a static, non-expiring, non-auditable cluster-admin kubeconfig for the **production identity platform**. The variable's own description says non-empty is "recommended for stage/prod," yet the env roots silently ship the insecure default.
**Fix:** Make `admin_group_object_ids` required (validation/precondition) when `profile == "hardened"`; set real group IDs in stage/prod.

### H10 — `aquasecurity/trivy-action@master` — unpinned mutable action in privileged CI jobs
**Repo:** aegis-platform-infra
**Files:** `ci/service-ci.yml:70`, `ci/frontend-ci.yml:48`; the service image job runs with `packages: write` + `id-token: write` (`ci/service-ci.yml:52-55`)

**Why it must be fixed:** A compromise of that action's `master` branch runs attacker code in a job that can push images to GHCR (which prod clusters pull) and mint OIDC tokens — exactly the supply-chain pattern behind the 2025 `tj-actions/changed-files` incident.
**Fix:** Pin to a full commit SHA. Pin all other actions to SHAs too (see L-series).

### H11 — Admin console stores OAuth access + refresh tokens in localStorage with broad admin scopes
**Repo:** aegis-admin-console
**File:** `src/auth/userManager.ts:16` — `WebStorageStateStore({ store: window.localStorage })`; scopes at `src/config.ts:20-23`

**Why it must be fixed:** Any XSS anywhere in the console (including a build-time compromised npm dep) can read `localStorage` and exfiltrate an admin access token carrying `identity:users:write`, `tenant:admin`, `applications:admin`, `idp:admin`. With `automaticSilentRenew` the theft yields a long-lived admin session — enough to create users, change IdPs, take over the tenant. localStorage persists across restarts, widening the window.
**Fix:** In-memory/`sessionStorage` at minimum; preferably a BFF with HttpOnly, Secure, SameSite cookies. Pair with a real CSP (M-console).

### H12 — nginx `add_header` inheritance silently drops security headers on the HTML shell
**Repo:** aegis-admin-console
**File:** `nginx.conf:13-19` (server-level headers) vs `:22-24` (per-location `add_header Cache-Control`)

In nginx, a server-level `add_header` is inherited by a `location` **only if that location defines no `add_header` of its own**. `location = /index.html` and `location /assets/` each set `Cache-Control`, cancelling `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy`. Since SPA routing falls back to `/index.html`, **every rendered HTML page ships with no `X-Frame-Options`**.

**Why it must be fixed:** The admin console can be framed by any site → clickjacking of admin actions (delete user, change auth policy) against a logged-in admin.
**Fix:** Repeat the three headers inside each location (or `include security-headers.conf;`); verify with `curl -I /`.

---

## MEDIUM

### Authorization server & identity service

- **M-core-1 — Timing-based username enumeration.** `identity/service/UserService.java:207-211` returns `BAD_CREDENTIALS` immediately (no hashing) for unknown usernames, but runs slow Argon2id for existing ones. Identical body, different latency. Defeats the anti-enumeration non-negotiable. **Fix:** hash against a dummy Argon2id hash on the not-found path.
- **M-core-2 — Unauthenticated tenant-existence oracle.** `web/OnboardingController.java:40-46` (`permitAll`) returns 409 for existing slugs vs success for fresh ones — unauthenticated, unthrottled. **Fix:** neutral response + email-verified onboarding token + rate limit.
- **M-core-3 — Session fixation on passkey login.** `web/PasskeyLoginController.java:58-75` saves an authenticated context with no session-ID rotation. **Fix:** `changeSessionId()` / `SessionFixationProtectionStrategy` before saving context.
- **M-core-4 — No throttle on MFA step-up.** `web/MfaController.java:57-66` allows unlimited TOTP guesses per pending step-up. **Fix:** cap attempts, invalidate pending state, force re-auth. (Pairs with H6.)
- **M-core-5 — `ddl-auto: update` on the credential store.** `identity-service/application.yml:13-14`. **Fix:** ship `validate`/`none` by default.
- **M-core-6 — Weak secret defaults start successfully.** Both services' `application.yml:10` fall back to `dev-only-change-me` with no fail-fast. **Fix:** remove inline secret defaults so startup fails when unset outside dev.

### Edge gateway, tenant service, SAML

- **M-edge-1 — Missing JWT audience (`aud`) validation.** `tenant-service/config/ResourceServerJwtConfig.java:31-35` and the SAML default decoder validate issuer+timestamp only. Enables token replay across services if scope sets overlap. **Fix:** add an `aud` validator asserting each resource server's own identifier.
- **M-edge-2 — JWKS fetched over plaintext HTTP.** `ResourceServerJwtConfig.java:28-30` / `application.yml:21-22` default to `http://…/oauth2/jwks`. A network MitM can substitute signing keys → token forgery → auth bypass. **Fix:** HTTPS/mTLS for the in-network JWKS URI.
- **M-edge-3 — No rate limiting at the edge.** `gateway/GatewayRoutesConfig.java` routes `/oauth2/**`, `/login`, MFA/WebAuthn with no `RequestRateLimiter`. Enables credential stuffing / OTP brute force platform-wide. **Fix:** Redis-backed rate limiter (per-IP and per-tenant).
- **M-edge-4 — Client-controlled `Host` drives tenant resolution + issuer reconstruction, no allowlist.** `gateway/TenantResolutionWebFilter.java:29-51` + `preserveHostHeader()`. A forged `Host` makes the gateway emit `X-Aegis-Tenant: victim` and the AS advertise an attacker-chosen issuer. (Credit: inbound `X-Aegis-Tenant` is correctly stripped first.) **Fix:** validate the resolved host against registered tenants/verified domains; reject unknown hosts.
- **M-edge-5 — Inbound `X-Forwarded-*` not sanitized.** Gateway strips `Origin` only; default SCG appends to client-supplied forwarded headers. Downstream host/redirect/issuer construction and audit source-IP can be spoofed. **Fix:** drop/normalize inbound `X-Forwarded-*` at the edge.

### MFA, SCIM, social broker, admin API

- **M-svc-1 — WebAuthn UV not enforced + counter regression not rejected.** `mfa/service/WebAuthnService.java:345-357` builds `AuthenticationParameters` with `userVerificationRequired=false` unconditionally (ignores tenant config) and unconditionally overwrites signCount. Weakens step-up to "presence only" and undermines clone detection. **Fix:** pass the tenant's `userVerification`; explicitly reject + audit non-increasing counters.
- **M-svc-2 — Social broker upstream IdP client secrets stored plaintext; resolve endpoint returns them.** `social/domain/IdentityProvider.java:56-57`, returned by `web/InternalProviderController.java:37-48`. DB compromise exposes every tenant's federation client secret → RP impersonation against Google/Entra/Apple/GitHub. **Fix:** encrypt at rest; ensure `/internal` is TLS/mTLS-only.
- **M-svc-3 — `tenant:admin` scope silently confers SUPER_ADMIN.** `admin/service/AdminRoleService.java:88-89` resolves any `tenant:admin` holder with no explicit role to `Permission.ALL`, nullifying the USER_ADMIN/HELP_DESK/AUDITOR least-privilege catalog. **Fix:** require explicit SUPER_ADMIN assignment; at minimum audit-log every fallback grant.
- **M-svc-4 — SCIM connector tokens never expire and cannot be rotated.** `scim/service/ScimConnectorService.java:40-45`, `web/ScimConnectorAuthFilter.java:74-79`; no rotate endpoint. A leaked token grants full tenant-scoped user CRUD until manually deleted. **Fix:** add `expiresAt`, rotation with grace-overlap, last-used-at. (Token *strength* is good.)
- **M-svc-5 — SCIM token compare not constant-time end-to-end.** `web/ScimConnectorAuthFilter.java:74`. Borderline Low — the compared value is a hash of an unknown 256-bit secret, so timing isn't steerable. **Fix (optional):** `MessageDigest.isEqual`.

### Infrastructure

- **M-infra-1 — Dev/test EKS API server public to `0.0.0.0/0` by default.** `modules/aws/stack/main.tf:16` + `endpoint_public_access_cidrs` default `["0.0.0.0/0"]`; dev/test roots don't narrow it. The K8s API of a cluster running the same codebase/secrets is one auth bug from the internet. **Fix:** make the CIDR required when public access is on; set office/VPN CIDRs.
- **M-infra-2 — MSK client IRSA role trusts every service account in the namespace.** `modules/aws/stack/main.tf:243` (`service_account = "*"` → `StringLike sub = system:serviceaccount:aegis:*`). Any pod (incl. a compromised admin-console nginx) can assume the events role and read/write all topics. **Fix:** per-service IRSA / split topic prefixes.
- **M-infra-3 — Helm NetworkPolicy is ingress-only; "default-deny egress" is not implemented.** `templates/service-hpa-netpol.yaml:56` sets `policyTypes: [Ingress]` despite the values comment. A compromised pod (holding token-signing material) can exfiltrate anywhere. **Fix:** add `Egress` with allowlisted destinations.
- **M-infra-4 — No account-level detection/audit anywhere.** No CloudTrail, GuardDuty, Config, Security Hub; no Azure Defender or `azurerm_monitor_diagnostic_setting` — notably **no Key Vault audit logging** for the vault holding tenant signing keys. An attacker using stolen cloud creds is invisible. **Fix:** add an audit module wired into the hardened profile, or document that a landing-zone repo owns it.
- **M-infra-5 — admin-console pod runs as root with writable root filesystem.** `helm/…/values-admin-console.yaml:20-26` (`runAsNonRoot: false`, `readOnlyRootFilesystem: false`). Internet-facing SPA server; an nginx RCE lands as in-container root, chaining with M-infra-2/3. **Fix:** `nginxinc/nginx-unprivileged` (port 8080), restore hardened defaults.
- **M-infra-6 — Compose publishes unauthenticated data stores on all host interfaces.** `compose/docker-compose.yml:16-17,30-31,42-43` — Postgres (weak pw), Redis (no AUTH), Kafka (PLAINTEXT) bound to `0.0.0.0`. Anyone on the LAN reads/writes dev identity data. Dev-only but needlessly host-exposed. **Fix:** bind `127.0.0.1:` for the data stores.
- **M-infra-7 — Image signing claimed but disabled.** `ci/service-ci.yml:55` requests `id-token: write` "for cosign keyless signing" but the `cosign sign` at `:86` is commented out and nothing verifies signatures. Advertises a control it doesn't enforce. **Fix:** enable signing + admission verification (Kyverno/policy-controller), or drop the permission.

### Frontend & commons

- **M-console-1 — No Content-Security-Policy for the SPA.** `nginx.conf` and `index.html` set none — while the backend `SecurityHardening.java:30-32` sets a strict CSP for the Java services. CSP is the primary mitigation for the exact token-exfiltration attack that makes H11 exploitable. **Fix:** add `default-src 'self'; script-src 'self'; connect-src 'self' <gateway> <oidc>; frame-ancestors 'none'; object-src 'none'; base-uri 'self'`.
- **M-console-2 — nginx container runs as root, no HSTS.** `Dockerfile:19-24`. Container escape starts at uid 0; no HSTS allows SSL-stripping. **Fix:** `nginx-unprivileged`; add `Strict-Transport-Security` at the TLS tier.
- **M-commons-1 — No shared JWT/JWKS validation or issuer-allowlist helper in aegis-security-commons.** `SecurityHardening.java:40-54` leaves resource-server/issuer wiring to each service, so per-tenant issuer validation and JWKS TLS/allowlisting are re-implemented independently everywhere — exactly where a mistake causes cross-tenant privilege escalation. Project memory already records tenant-service issuer allowlisting as TODO. **Fix:** add an `AegisJwtDecoderFactory` enforcing https-only issuer/JWKS, an explicit issuer allowlist, and `iss`+`aud`+tenant-claim validation.

---

## LOW / INFORMATIONAL

**Authorization server / identity service**
- **L-core-1** — Floating Docker base image `eclipse-temurin:21-jre` (both). Pin by digest.
- **L-core-2** — Verify AS login/session cookie flags (`Secure`/`SameSite`/`HttpOnly`) — the AS is the stateful login host; not verifiable in-repo (`DefaultSecurityConfig.java:37-90`).
- **L-core-3** — No `aud` validation on identity-service decoder (`ResourceServerJwtConfig.java:38-42`). Defense-in-depth.
- **L-core-4** — `aegis-dev-spa` grants every console user full admin scopes (`AuthorizationServerConfig.java:185-197`); gate scope issuance on role before prod.
- **L-core-5** — Wildcard CORS on tenant-app endpoints (`TenantAppSecurityConfig.java:53-59`) — acceptable while `allowCredentials=false`.
- **L-core-6** — Usernames/orgs in login-failure logs (`IdentityClient.java:54-63`) — low-grade PII; no passwords/tokens logged (good).

**Edge / tenant / SAML**
- **L-edge-1** — Dev-default DB password (`tenant-service/application.yml:10`) — env override, fail-fast in prod.
- **L-edge-2** — `ddl-auto: update` (tenant-service). Use `validate` in prod.
- **L-edge-3** — Gateway↔service traffic over plaintext HTTP (`gateway/application.yml:41-47`) — mTLS on the mesh for prod (pairs with M-edge-2).
- **L-edge-4** — Permissive CORS on per-tenant OAuth paths — mitigated by `allowCredentials=false`; catch-all is correctly locked to the console origin.
- **SAML note:** `aegis-saml-idp-service` is a resource-server scaffold — no OpenSAML code, XML parsers, or key material yet. XML-signature/XXE/assertion checks are **not assessable**; re-audit when the IdP runtime lands.

**MFA / SCIM / social / admin**
- **L-svc-1** — Dev-default client/DB secrets in `application.yml` (all four) — fail-fast on non-dev profiles.
- **L-svc-2/3** — SCIM auth-filter context handling and pagination reviewed — sound.
- **L-svc-4** — `ddl-auto: update` (all four). Override to `validate` in prod.
- **L-svc-5** — Docker base images not digest-pinned (otherwise non-root, minimal JRE — good).
- **L-svc-6** — TOTP uses HMAC-SHA1 — **not a vulnerability** (RFC 6238 standard); verification is constant-time and windowed. Noted only because scanners flag SHA1.
- **Recovery codes** are unimplemented — account recovery for a lost second factor is unbuilt (flag for design).

**Infrastructure**
- **L-infra-1** — GitHub Actions pinned to mutable major tags (`@v4`/`@v3`). Pin to SHAs (lower risk than H10 — first-party).
- **L-infra-2** — `npm audit` non-blocking (`continue-on-error: true`) — labeled; ensure the ratchet-to-false happens (Trivy is a blocking backstop).
- **L-infra-3** — Hardcoded dev creds in compose (`dev-only-change-me`) — labeled dev-only; generate the SCIM client secret per-checkout.
- **L-infra-4** — Helm images by mutable tag `0.1.0` on GHCR (mutable) + SA token always mounted. Digest-pin prod; `automountServiceAccountToken: false` where unused.
- **L-infra-5** — `enable_cluster_creator_admin_permissions = true` — acceptable bootstrap; prefer a break-glass role for prod.
- **L-infra-6** — Event Hubs SAS keys not disabled (`modules/azure/eventhubs/main.tf:2-15`) — set `local_authentication_enabled = false` if workloads use Workload Identity.

**Frontend / commons / BOM**
- **L-commons-1** — `CorsConfigFactory` doesn't reject the `"null"` origin or non-https origins (`CorsConfigFactory.java:23-33`). Reject `"null"` and require `https://` (dev-flag `http://localhost`).
- **L-commons-2** — `ApiExceptionHandler` reflects raw `IllegalArgumentException` messages (incl. echoed input) to clients (`ApiExceptionHandler.java:30-33`). Map to generic message; log detail only.
- **L-commons-3** — Auth-failure audit records the attempted principal name (`AuthenticationAuditListener.java:35-41`) — users type passwords into the username field, so cleartext passwords can reach the audit trail. Hash/guard the actor on failure.
- **L-commons-4** — `TenantContextFilter` catch block swallows downstream IAEs (`TenantContextFilter.java:33-43`) — validate the header before invoking the chain.
- **L-console-1** — Dockerfile bakes plain-`http` OIDC/API defaults (`Dockerfile:11-13`) — make ARGs mandatory / fail on non-`https` outside dev.
- **BOM** — `failBuildOnCVSS=7` lets CVSS 4.0–6.9 CVEs pass; dependency-check/spotbugs are `pluginManagement`-only. Confirm CI actually invokes `dependency-check:check` and `spotbugs:check`.
- **CVE coverage gap:** both core-auth POMs inherit versions from `aegis-platform-parent:0.1.0`, which is **not in the repos** — no CVE assessment was possible there. Run OWASP Dependency-Check against the resolved build with the parent POM present.

---

## Confirmed-good controls (not findings)

PKCE mandatory; no implicit/ROPC; refresh-token rotation; Argon2id; per-tenant RS256 keys with no `alg:none`; single-use TTL-bounded constant-time PKCE interaction codes; verified-email-only federation account-linking (blocks unverified-email takeover); tenant isolation by construction (acting tenant from token, never request body); MFA step-up enforced by a protocol-chain filter; strict SCIM filter parsing (no injection); SCIM PATCH limited to `active` (no mass assignment); connector tokens 256-bit random + SHA-256 stored + shown once; `X-Aegis-Tenant` stripped before injection; DNS-TXT custom-domain ownership verification; homograph-blocking ASCII hostname regex; issuer allowlist not prefix-bypassable; `health`-only actuator across services; TLS-forced Postgres; `rds.force_ssl=1` + AWS-managed master password; Azure PG `public_network_access_enabled=false` in all profiles; Key Vault RBAC-only; IMDSv2-only nodes; immutable scan-on-push ECR; no wildcard-resource IAM; no `0.0.0.0/0` in Terraform SGs; non-root Dockerfiles throughout.
