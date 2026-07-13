# Aegis Service Catalog

Per-service contract: responsibility, key endpoints, datastore, upstream/downstream, and maturity.
All services inherit `aegis-platform-bom` and use `aegis-platform-commons`. All are Spring Boot 4.1 /
Java 21 / Maven. All non-gateway services are **OAuth2 resource servers** (validate JWTs against the
per-tenant issuer) for their management/API surface.

Legend — **Maturity:** `core` = deep TDD implementation · `functional` = working baseline ·
`scaffold` = secured, health-checked, test-harnessed skeleton ready for feature work.

---

## authorization-server  ·  Maturity: core
**Repo:** `aegis-authorization-server` · **Store:** PostgreSQL + Redis · **Port:** 9000
The OIDC/OAuth2 provider and interactive login host. The heart of the platform.
- **Standards endpoints:** `/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/token`,
  `/oauth2/jwks`, `/userinfo`, `/oauth2/revoke`, `/oauth2/introspect`, `/connect/logout`.
- **Login:** server-rendered `/login` (Thymeleaf, reference UI), password verified against
  `identity-service`; optional social redirect to `social-broker-service`; optional MFA step-up to
  `mfa-webauthn-service`.
- **Grants:** authorization_code + PKCE, client_credentials (M2M), refresh_token (rotated), device.
- **Data:** `JdbcRegisteredClientRepository`, `JdbcOAuth2AuthorizationService`,
  `JdbcOAuth2AuthorizationConsentService` (Spring-shipped schemas). Redis: sessions, auth-request
  state, JWKS cache, revocation.
- **Per tenant:** issuer `https://<host>/t/{tenantId}`, signing key (`kid`) from KMS.
- **Tests:** code+PKCE end-to-end (Testcontainers), unregistered client rejected, wrong redirect_uri
  rejected, JWKS + discovery well-formed, client_credentials issues scoped token.

## tenant-service  ·  Maturity: core
**Repo:** `aegis-tenant-service` · **Store:** PostgreSQL · **Port:** 9101
Control plane for organizations/tenants.
- **API:** CRUD `/api/v1/tenants`, `/api/v1/tenants/{id}/domains`, `/api/v1/tenants/{id}/config`,
  resolution `/api/v1/tenants:resolve?domain=…` (used by edge-gateway).
- **Model:** tenant → domains (custom/verified) → config (branding, password policy, MFA policy,
  token lifetimes, allowed providers) → signing-key references.
- **Events:** `tenant.created|updated|suspended|deleted` (Kafka) → triggers key provisioning.
- **Tests:** tenant CRUD, domain uniqueness, resolve-by-domain, config defaults, cross-tenant read
  denied.

## identity-service  ·  Maturity: core
**Repo:** `aegis-identity-service` · **Store:** PostgreSQL · **Port:** 9102
Universal directory. Crown-jewel data — tightest network policy.
- **API:** `/api/v1/users` CRUD, `/api/v1/users:authenticate` (verify credential — called by
  authorization-server), `/api/v1/users/{id}/credentials`, `/api/v1/groups`, membership.
- **Credentials:** Argon2id hashing, per-tenant policy, bcrypt legacy import w/ upgrade-on-login,
  account lockout counters.
- **Events:** `identity.user.created|updated|deactivated|deleted`.
- **Tests:** Argon2 hash/verify, wrong password rejected, lockout after N failures, tenant-scoped
  uniqueness of username/email, cross-tenant user access denied.

## edge-gateway  ·  Maturity: functional
**Repo:** `aegis-edge-gateway` · **Store:** Redis · **Port:** 8080 (public)
Spring Cloud Gateway (reactive). TLS termination, tenant resolution (domain/issuer → tenantId, signed
internal header), routing to services, Redis-backed rate limiting, request validation, WAF hooks.
- **Tests:** route resolves to correct service, tenant header derived not trusted-from-client, rate
  limit returns 429, unknown host rejected.

## mfa-webauthn-service  ·  Maturity: scaffold → incremental
**Repo:** `aegis-mfa-webauthn-service` · **Store:** PostgreSQL · **Port:** 9103
Passkeys (WebAuthn/FIDO2) + TOTP, primary-passwordless and step-up MFA.
- **API:** `/webauthn/register/options`, `/webauthn/register`, `/webauthn/authenticate/options`,
  `/login/webauthn`; `/mfa/totp/enroll`, `/mfa/totp/verify`.
- **Custom schema** (Spring ships none): credential(public key, **sign counter**, user handle,
  transports), totp_secret(encrypted). `rpId`/`allowedOrigins` per tenant domain.
- **Tests (when implemented):** credential round-trips, second device adds not replaces, replayed
  challenge rejected, sign-counter regression rejected, rpId mismatch rejected.
- **Flag:** youngest Spring Security surface; no official WebAuthn+AuthServer recipe → from-scratch,
  TDD-first.

## saml-idp-service  ·  Maturity: scaffold → incremental
**Repo:** `aegis-saml-idp-service` · **Store:** PostgreSQL · **Port:** 9104
**Custom SAML 2.0 Identity Provider on OpenSAML 5** — Spring provides only SP support, so being an IdP
is bespoke. Needs the Shibboleth Maven repo (`build.shibboleth.net`) for OpenSAML.
- **API:** `/saml2/idp/metadata`, `/saml2/idp/sso` (Redirect+POST bindings, SP- and IdP-initiated),
  `/saml2/idp/slo`; admin: SP registration + metadata import.
- **Security core:** XXE disabled, signature-wrapping defenses, DEFLATE-bomb size limits, signed
  (optionally encrypted) assertions, per-tenant signing certs (KMS-wrapped).
- **Flag:** highest-effort service; v1 = SP-initiated SSO + signed assertion.

## social-broker-service  ·  Maturity: scaffold → incremental
**Repo:** `aegis-social-broker-service` · **Store:** PostgreSQL + Redis · **Port:** 9105
Inbound federation hub.
- **Social login:** OAuth2 *client* to Google/Microsoft/Apple/GitHub/Facebook → JIT provision/link
  in identity-service. Per-tenant provider registrations (dynamic, from tenant-service — not static
  yaml).
- **Inbound SAML/OIDC:** act as SP (`spring-security-saml2-service-provider`) / OIDC RP to a
  corporate IdP, broker into an Aegis session.
- **Tests:** state/nonce/PKCE validation, JIT link idempotency, provider config resolved per tenant.

## scim-provisioning-service  ·  Maturity: scaffold
**Repo:** `aegis-scim-provisioning-service` · **Store:** PostgreSQL · **Port:** 9106
SCIM 2.0 inbound (customer IdP provisions users into Aegis) and outbound (Aegis provisions into
downstream apps). Consumes `identity.user.*` events for outbound.

## admin-api-service  ·  Maturity: scaffold
**Repo:** `aegis-admin-api-service` · **Store:** PostgreSQL · **Port:** 9107
Admin/console backend: policy management, admin RBAC, API tokens, tenant settings, System-Log query
API over the audit event store.

---

## Cross-service contracts
- **AuthN of management APIs:** every service (except gateway) validates JWT bearer tokens issued by
  `authorization-server` against the per-tenant issuer; scopes gate operations
  (`identity:users:read`, `tenant:admin`, …).
- **Tenant propagation:** `tenant-context` library; `X-Aegis-Tenant` internal header only trusted on
  mTLS-authenticated internal connections.
- **Events:** Avro/JSON schemas versioned in `aegis-platform-docs/api/events/`; published via
  `audit-commons`.
