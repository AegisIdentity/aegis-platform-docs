# Architecture Decision Records

Each ADR: context → decision → consequences. Status `Accepted` unless noted. Superseding an ADR adds
a new one; ADRs are not edited away.

---

## ADR-0001 — Polyrepo, one repository per deployable unit
**Context:** The platform is many independently-scaling, independently-owned services with different
release cadences and blast radii. **Decision:** One git repo per service, per shared library group,
and for infra/docs. Shared code is consumed as **versioned Maven artifacts** (`aegis-platform-bom`,
`aegis-platform-commons`), never as source coupling. **Consequences:** (+) true independent
lifecycle, isolated CI, least-privilege access per repo; (−) cross-cutting changes span repos and
need coordinated releases — mitigated by a stable BOM/commons contract and semantic versioning. In
this workspace, repos are sibling directories, each independently `git init`-ed; downstream builds
resolve upstream artifacts from `~/.m2` locally and from ECR/ACR-adjacent Maven registries in CI.

## ADR-0002 — Database-per-service, no shared schema
**Context:** Shared databases couple release cycles and dissolve the tenant-isolation boundary.
**Decision:** Each stateful service owns a private PostgreSQL database; services integrate via APIs
and Kafka events, never by reading each other's tables. **Consequences:** (+) independent evolution,
clean isolation, per-service encryption/network policy; (−) no cross-service JOINs (use API
composition / events) and eventual consistency across services — accepted deliberately.

## ADR-0003 — PostgreSQL as system-of-record; Redis for state; Kafka for events
**Context:** Identity data is deeply relational and must be transactionally correct; protocol state
is transient and shared across pods; services must decouple side effects. **Decision:** PostgreSQL
for records (ACID, JSONB, RLS, managed on both clouds), Redis for sessions/transient-protocol-state/
rate-limit/revocation, Kafka for domain + audit events. **Consequences:** three stateful backends to
operate — justified by fit; all three have managed AWS and Azure equivalents.

## ADR-0004 — OAuth 2.1 posture: no Implicit, no Resource-Owner-Password grant
**Context:** Okta historically exposed password grant; modern guidance and Spring Authorization
Server both drop it. **Decision:** Support only `authorization_code`+PKCE, `client_credentials`,
`refresh_token`, `device_code`. "Password auth" = interactive login at our page during the code flow,
not a token endpoint accepting raw passwords. **Consequences:** (+) removes a major credential-
exposure class and matches Spring AS's implemented grants; (−) clients that assumed ROPC must adopt
the code flow — treated as correct, not a regression.

## ADR-0005 — SAML IdP is custom-built on OpenSAML 5 (Spring provides only SP)
**Context:** Okta *is* a SAML Identity Provider for downstream apps. Spring Security ships only
`spring-security-saml2-service-provider` (relying-party/SP side). There is no Spring turn-key SAML
**IdP**. **Decision:** Build `saml-idp-service` directly on OpenSAML 5 (the library beneath Spring's
SP support), isolated in its own process/network policy because it parses attacker-influenced XML.
Inbound SAML (acting as SP to a corporate IdP) uses the Spring SP support in `social-broker-service`.
**Consequences:** (+) real IdP capability, blast-radius isolation for XML attacks; (−) highest-effort
service, security-critical XML hardening is on us (XXE, signature-wrapping, DEFLATE bombs) — hence
TDD-heavy and phased.

## ADR-0006 — Multi-tenancy: shared services, isolation enforced at the data layer
**Context:** SaaS economics need shared infrastructure; security needs hard tenant boundaries.
**Decision:** Logical multi-tenancy — shared services, mandatory `tenant_id` predicate enforced in
the repository base (application code *cannot* issue a non-tenant-scoped query), per-tenant signing
keys, optional Postgres RLS and optional dedicated-schema/instance for premium tenants without app
changes. **Consequences:** (+) cost-efficient with a defense-in-depth boundary; (−) every query path
and test must prove tenant scoping — enforced by a negative "cross-tenant access denied" test per
service.

## ADR-0007 — Per-tenant token signing keys, KMS-wrapped, rotated with overlap
**Context:** One global signing key means one compromise forges tokens for every tenant, and no clean
rotation. **Decision:** Per-tenant asymmetric keys, private material wrapped by cloud KMS (envelope
encryption), never regenerated on restart, rotated with overlapping validity (new `kid` in JWKS
before it signs; old `kid` verifiable until its tokens expire). **Consequences:** (+) blast-radius
containment + clean rotation; (−) key-management complexity and a KMS dependency on the token path —
mitigated by brief in-memory caching of unwrapped keys.

## ADR-0008 — mTLS + scoped client-credentials for east-west, derived-not-trusted tenant header
**Context:** Internal calls need both "who is calling" and "may they do this," and the tenant header
must not be forgeable. **Decision:** Service-to-service uses mTLS (mesh SVIDs) for peer identity plus
a `client_credentials` bearer token for scopes; `X-Aegis-Tenant` is honoured only on mTLS-verified
internal connections and always *derived* (never client-supplied) at the public edge.
**Consequences:** (+) layered authZ, no ambient trust; (−) mesh/cert-rotation machinery to operate.

## ADR-0009 — Java 21 (LTS) + Spring Boot 4.1 + Maven
**Context:** Verified live against Spring Initializr on 2026-07-13: Boot 4.1.0 is current default;
Java 21 is the current LTS (JDK 23 present but non-LTS). Team chose Maven. **Decision:** Compile-
target Java 21 for production stability, Spring Boot 4.1.0 / Spring Security 7 line, Maven with a
committed wrapper per repo. **Consequences:** widest security-doc coverage, LTS support runway;
re-verify the patch level of Boot/Security before each release cut (new CVEs land continuously).
