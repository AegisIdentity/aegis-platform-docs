# Aegis Identity Platform — codebase map

An independent read of the workspace (2026-08-18), verified against source rather than the
project's own docs. Where code and docs disagree, this file states what the **code** does.

The workspace root is not a git repo; it holds 14 sibling repos, all currently on branch
`security/remediation-2026-07-24` with clean working trees.

---

## 1. What this is

A multi-tenant, Okta-class IAM platform: Spring Boot 4.1 / Spring Security 7, Java 21, Maven,
PostgreSQL, React 19 console. Polyrepo — one git repo per deployable unit, sharing a Maven parent
and five commons libraries as versioned artifacts.

**Naming trap:** the repo directory `aegis-platform-bom/` contains the artifact
`io.aegis:aegis-platform-parent:0.1.0` (packaging `pom`). Every other module declares *that*
artifact as its `<parent>`. The dir name and the artifact name differ; the build graph is correct.
(The project's own security review claims this parent is "not in the repos" — that claim is wrong.)

Build order: `aegis-platform-bom` → `aegis-platform-commons` → any service.

---

## 2. Repo inventory (verified counts)

| Repo | Java files (src) | Role | Actually built? |
|---|---:|---|---|
| `aegis-platform-docs` | — | specs, ADRs, threat model, security review + remediation | docs only |
| `aegis-platform-bom` | — | Maven parent + BOM, CVE gate | yes |
| `aegis-platform-commons` | 28 | 5 libs: security / tenant-context / web / audit / testing | yes |
| `aegis-authorization-server` | 51 | OIDC/OAuth2 provider, login, federation, tenant-app tokens | **deep** |
| `aegis-identity-service` | 45 | users, credentials, groups, policy, branding, system log | **deep** |
| `aegis-mfa-webauthn-service` | 36 | WebAuthn + TOTP, encryption, lockout | **substantial** |
| `aegis-scim-provisioning-service` | 26 | SCIM 2.0 inbound server + connectors | **real** |
| `aegis-social-broker-service` | 24 | per-tenant IdP *registry* (not a broker — see §5) | **registry only** |
| `aegis-admin-api-service` | 18 | admin RBAC role catalog + assignments | thin |
| `aegis-tenant-service` | 18 | tenants, custom domains, DNS verification | **real** |
| `aegis-edge-gateway` | 6 | routing, tenant derivation, rate limit | thin but complete |
| `aegis-saml-idp-service` | **3** | SAML IdP | **stub — no OpenSAML at all** |
| `aegis-admin-console` | 43 TS | admin console + end-user portal + branded sign-in | **substantial** |
| `aegis-platform-infra` | — | compose, Terraform (AWS+Azure), Helm, CI | yes |

**14 repos total**, of which **10 are deployable runtime units** (9 Spring Boot services + 1 SPA);
the other 4 are docs, the Maven parent, the commons libraries, and infra. The architecture doc's
"Twelve deployable units" matches neither count. Only **8 Spring services run in docker-compose** —
`saml-idp-service` is absent from the stack entirely.

---

## 3. Test evidence (independently corroborated)

`target/` dirs are present, so surefire + failsafe reports could be checked without rebuilding.
Combined totals vs. the remediation doc's claims: **9 of 10 match exactly.**

| Repo | surefire | failsafe | total | doc claim |
|---|---:|---:|---:|---:|
| authorization-server | 38 | 17 | 55 | 55 ✓ |
| commons | 55 | 0 | 55 | 55 ✓ |
| mfa-webauthn | 13 | 34 | 47 | 47 ✓ |
| identity | 7 | 24 | 31 | 31 ✓ |
| tenant | 0 | 15 | 15 | 15 ✓ |
| admin-api | 4 | 11 | 15 | 15 ✓ |
| scim | 14 | 10 | 15* | 15 ✓ |
| edge-gateway | 13 | 0 | 13 | 13 ✓ |
| social-broker | 6 | 7 | 13 | 13 ✓ |
| saml-idp | 3 | 0 | 3 | 2 (one extra probe test) |

\* raw sum is 24: `ScimProvisioningIT` is picked up by both surefire (9) and failsafe (10). Distinct
total is 15 (`ScimSecurityTest` 5 + `ScimProvisioningIT` 10).

All recorded runs are green. **Caveat:** identity-service's `UserService.java` (13:01) is newer than
its newest test report (12:56) — that repo's 31 green tests were not run against the final source.

---

## 4. How it actually works

### Tenancy
- **Derivation (edge):** `TenantResolutionWebFilter` (gateway, `@Order(-1)`) takes the `Host` header,
  strips any client-supplied `X-Aegis-Tenant` and all `X-Forwarded-*`, then derives the tenant from
  the **first DNS label** (`acme.aegis.io` → `acme`) and injects the trusted header. Optional host
  allowlist (`aegis.gateway.allowed-hosts`); **empty list = allow all**.
  *(As of 2026-08-18, §9)* it now optionally resolves via tenant-service (`TenantResolver`, cached)
  when `aegis.gateway.tenant-resolution.enabled=true`; subdomain derivation is the fallback.
- **Enforcement (services):** every repository method takes an explicit `tenantId`
  (`findByTenantIdAndUsername`, …). Acting tenant comes from the JWT `tenant` claim, never the body.
  This is **isolation by convention**, not the framework-enforced predicate the docs describe: there
  is no Hibernate filter, no tenant-aware repository base class, no Postgres RLS.
- `TenantContextFilter` / `TenantContext` from commons are built and tested but **used by no service**.

### Tokens & keys
- Per-tenant issuer via Spring AS `multipleIssuersAllowed`: `<base>/{tenant}`.
- `TenantJwkSource` mints an **RSA-2048 key per tenant** — *(as of 2026-08-18, §9)* persisted
  encrypted in Postgres via `TenantKeyStore`, not the process-local `ConcurrentHashMap` described next.
  `kid` gets a random suffix precisely so restarts self-heal resource-server caches.
- `/internal/jwks` serves the **aggregate** of all keys this process has generated; resource servers
  point at that single in-network URI and validate `iss` against an allowlist.
- **No KMS/Key Vault integration exists anywhere in the application** — not in Java (no `KmsClient`,
  `SecretClient`, AWS/Azure SDK), and not via config either (no `spring.config.import`, no
  secretsmanager/keyvault property source in any `application.yml` or pom). Secrets arrive as plain
  environment variables. ADR-0007 (KMS-wrapped, persisted, rotated-with-overlap keys) is entirely
  unimplemented; the class javadoc admits this. Terraform *does* provision a KMS module — nothing
  consumes it.

### Resource-server validation ("split-horizon")
Each service has its own copy of `ResourceServerJwtConfig`: fetch JWKS from a reachable in-network
URI, validate signature + timestamp + an **issuer allowlist** (prefix-safe: `equals(base) ||
startsWith(base + "/")`), plus optional `aud`. This solves the Docker split-horizon problem where a
browser-facing issuer and an in-network issuer can't both satisfy one `issuer-uri`.
`aegis-security-commons` gained `AegisJwtDecoderFactory` to centralise exactly this — **no service
adopts it.** The duplication the helper was written to remove is still present in every service
(tenant-service's copy even carries a "should eventually move to commons" comment).

### Login & MFA
Interactive login at the AS (`/login`, Thymeleaf) → `IdentityAuthenticationProvider` →
`IdentityClient` calls identity-service `users:authenticate` → Argon2id verify
(`Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8`). Unknown usernames are hashed against a
dummy hash so timing doesn't leak account existence. Step-up MFA is enforced by
`MfaPendingGateFilter` in the protocol chain; TOTP/WebAuthn live in mfa-webauthn-service, whose TOTP
seeds are AES-GCM encrypted via an `AttributeConverter`.

### Audit — two independent trails
1. **Automatic, log-based.** `AegisSecurityAutoConfiguration` is registered via
   `META-INF/spring/…AutoConfiguration.imports`, so every service depending on
   `aegis-security-commons` (all 9 Java services except the reactive edge-gateway) silently gets a
   `LoggingAuditEventPublisher` + `AuthenticationAuditListener`. Spring authentication
   success/failure events are bridged to structured JSON on an `AUDIT` logger, at WARN for
   failure/denied. No service names these beans — they arrive by autoconfiguration, and a service can
   override `AuditEventPublisher` (e.g. a Kafka adapter) and the default backs off. **None does.**
2. **Explicit, DB-backed.** identity-service additionally has its own JPA `AuditEvent` entity +
   `AuditService`, written on user/password/auth events and surfaced via `SystemLogController`.
   This is what the console's System Log page reads.

So audit is real, but split: authentication events go to logs platform-wide, while the queryable
System Log is one service's private table. There is no aggregation across services.

---

## 5. Doc-vs-code deltas worth knowing

1. **Kafka does not exist in code.** No `spring-kafka`, no producer/consumer, no topic anywhere.
   The compose stack runs a Kafka broker nothing connects to, and Terraform provisions MSK /
   Event Hubs. ARCHITECTURE §4.4's whole event backbone (`identity.user.*`, `auth.login.*`) is
   unbuilt; audit is logs + a per-service table.
2. **Redis is used only by the edge-gateway** (rate limiter). No Spring Session, no Redis in the AS.
3. **No mTLS anywhere.** ADR-0008's east-west mTLS is unimplemented; the only hits for "client auth"
   are OAuth `ClientAuthenticationMethod.CLIENT_SECRET_BASIC/NONE`.
4. **No `device_code` grant** despite the catalog listing it. Configured grants are
   `authorization_code`, `refresh_token`, `client_credentials` only.
5. **SAML IdP is a 3-class stub** (App, SecurityConfig, InfoController). No OpenSAML dependency, no
   XML handling, no keys. The platform's hardest differentiator does not exist, and the service is
   absent from docker-compose.
6. **social-broker is an IdP registry, not a broker.** It stores per-tenant provider config and
   exposes internal resolve endpoints. The *actual* federation runs in the authorization-server
   (`federation/BrokerClientRegistrationRepository`, `BrokerRelyingPartyRegistrationRepository`,
   `FederatedLoginSuccessHandler`, `Saml2LoginSuccessHandler`). Architecture inverted vs. the docs.
7. **Web UIs are declared out of scope** (ARCHITECTURE §1.2) yet `aegis-admin-console` ships an
   admin console, an end-user portal, sign-in/sign-up, and an in-app documentation hub with code
   samples. The most-developed frontend in the workspace is formally out of scope.
8. **Maturity labels are stale.** mfa (36 files, real assertion verification), scim (26, working
   inbound server), social (24), admin-api (18) are all still labelled "scaffold".
9. **Tenant isolation is convention, not construction** (see §4) — ADR-0006 overstates the mechanism.
10. **Schema management:** the AS uses `ddl-auto: none` + Postgres-adapted `spring.sql.init` scripts;
    other services were moved to `ddl-auto: validate` with **no Flyway/Liquibase anywhere**, so they
    validate against a schema nothing creates. This is a known open item.

---

## 6. The one finding that blocks deployment as shipped

> **⚠️ FIXED in the 2026-08-18 session — see §9.** Signing keys now persist (encrypted) in Postgres
> and session/interaction-code state moved to Redis, so the AS is horizontally scalable. This section
> is retained as the record of the original finding.

**The authorization-server is process-stateful in three ways, but its Helm chart runs 2–8 replicas
with no session affinity.**

- `TenantJwkSource` — per-tenant RSA keys in a `ConcurrentHashMap`, generated on demand.
- HTTP login session — plain servlet session; no Spring Session, no Redis (AS pom has neither).
- `InteractionCodeStore` — in-memory; its javadoc notes Redis "is a documented follow-up".

Meanwhile `helm/aegis-service/values.yaml` sets `replicaCount: 2` and `autoscaling.minReplicas: 2 /
maxReplicas: 8`, and the Service is a plain `ClusterIP` with **no `sessionAffinity`**. There is one
generic chart for all services; its header comment implies per-service value files
(`-f values-identity.yaml`) but the only one that exists is `values-admin-console.yaml`. **No
authorization-server values file exists**, so the AS would deploy on the 2–8 replica defaults.

Consequences with ≥2 replicas: pod A and pod B mint *different* signing keys for the same tenant, so
a token signed by A fails validation against B's aggregate `/internal/jwks`; and a login started on
A breaks when the next request lands on B. This is not merely the documented "production wraps keys
in KMS" TODO — the shipped deployment artifacts are internally inconsistent with the shipped code.
Neither the architecture doc nor the project's security review mentions it.

Minimum fixes: run the AS at `replicaCount: 1` until keys are persisted (DB or KMS) *and* session +
interaction-code state moves to Redis; or implement those three before enabling the HPA.

---

## 7. Security posture (context)

`aegis-platform-docs/SECURITY-REVIEW-2026-07-24.md` (12 High / 23 Medium / ~20 Low) and
`SECURITY-REMEDIATION-2026-07-24.md` are genuine and largely corroborated by the test evidence in §3.
Real controls in code: PKCE-only public clients, no implicit/ROPC, Argon2id + timing equalisation,
per-tenant RS256 keys, AES-GCM field encryption for TOTP seeds and upstream IdP secrets,
`StartupSecretsGuard` fail-fast on non-dev profiles, SCIM token expiry/rotation with
`MessageDigest.isEqual`, dev seeders gated to `@Profile("dev")`, shared hardening headers/CSP.

Carry-forwards to keep in view:
- Three controls are **implemented but off by default** — `AEGIS_JWT_AUDIENCE` (aud validation),
  `aegis.ratelimit.enabled` (edge rate limiting), `AEGIS_ALLOWED_HOSTS` (host allowlist). Unset in
  prod = unmitigated.
- M-commons-1 is "fixed" by a helper **nobody uses** (§4).
- Legacy plaintext TOTP / IdP-secret rows stay plaintext until re-saved (backfill owed).
- MFA lockout is per-instance, so it weakens under the same multi-replica assumption as §6.

---

## 8. Where to start reading

1. `aegis-platform-docs/architecture/ARCHITECTURE.md` — intent (read §5 of this file alongside it).
2. `aegis-platform-infra/compose/docker-compose.yml` — the executable architecture: 8 Spring
   services + console + Postgres + Redis + Kafka, all on `SPRING_PROFILES_ACTIVE=dev`.
   Note which service is missing (saml-idp) and which backends are unused (Kafka).
3. `aegis-edge-gateway` — 4 classes; the entire tenant-derivation story.
4. `aegis-authorization-server/.../auth/TenantJwkSource.java` + `web/JwksController.java` — the
   per-tenant issuer/key model, and §6's problem.
5. `aegis-platform-commons/aegis-security-commons` — the baseline, plus the unadopted helper.

---

## 9. Changes in the 2026-08-18 session (build-out + pen test)

Delivered on top of the map above. Every change is verified by tests (323 total across the 10 Java repos, up from ~261) and the
full stack was run (`docker compose up`, 12 containers healthy).

**Deployment blocker closed — the AS is now horizontally scalable (was §6's finding):**
- Per-tenant signing keys persist in Postgres (`tenant_signing_key`), AES-256-GCM encrypted at rest,
  KMS-ready. A partial unique index makes concurrent creation across replicas converge. `TenantKeyStore`
  is the seam a KMS impl drops into. (`keys/*`, `TenantKeyPersistenceTest`, `TenantSigningKeyIT`)
- Login session → Redis (Spring Session); interaction codes → Redis with `GETDEL` atomic single-use.
  Redis is now REQUIRED (no silent in-memory fallback). (`session/*`, `tenantapp/Redis*`)
- `values-authorization-server.yaml` created — its absence was why the 2-replica defaults applied.

**New functionality (built + tested):**
- `device_code` grant (RFC 8628) — client, converter/provider for public-client auth (which SAS does
  not ship), `/activate` page, per-subject brute-force throttle. (`device/*`, `DeviceGrantIT`)
- Gateway host→tenant resolution via tenant-service (cached, fail-open to subdomain), so white-label
  custom domains resolve. Gateway uses a `tenant:resolve`-only client. (`gateway/TenantResolver*`)
- Flyway baselines for the six `ddl-auto:validate` services (generated from the entities; tests now
  validate against the migration-built schema, not a Hibernate-built one).

**Pen test (`PENTEST-2026-08-18.md`) — 8 findings, most fixed:**
- F1 (High): identity + tenant services failed to START in the shipped stack (CORS https rule, no dev
  escape hatch). Fixed + `CorsStartupIT`.
- F2 (High): forged Host → issuer spoofing (allowlist empty by default). Set in compose, verified.
- F6 (High): admin-console unreachable (unprivileged nginx on 8080, compose mapped :80) + a broken
  IPv6 healthcheck. Both fixed, verified healthy.
- F3/F8: rate limiting + JWT `aud` off by default — confirmed exploitable, operator actions.
- Token security held under active attack: `alg:none`, RS→HS confusion, claim tampering, cross-tenant
  reads, cross-tenant kid all rejected.
- **Three July "remediations" had shipped a stack that could not run** (F1, F6) — the recurring theme
  is self-certifying remediation validated by unit tests that never exercised the deployed config.

**Docs added at workspace root:** `PENTEST-2026-08-18.md`, `DESIGN-ROADMAP-deferred-capabilities.md`
(SAML IdP / Kafka / KMS / mTLS — designed, not built, per decision), `PRODUCT-AND-HOSTING.md`
(market differentiation + SaaS hosting plan + operator checklist).
