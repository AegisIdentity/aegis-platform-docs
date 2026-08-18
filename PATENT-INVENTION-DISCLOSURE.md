# Aegis Identity Platform — Invention Disclosure (for patent counsel)

**Status:** DRAFT for review by patent counsel · **Date:** 2026-08-18
**Prepared by:** engineering · **Not legal advice.**

> **How to use this document.** This is an engineering disclosure, not a filing. Before spending on
> prosecution, counsel must run a **professional prior-art search** — the mechanisms below are
> described specifically so a search can confirm or kill each one quickly. Software claims live or
> die on **35 U.S.C. §101 (*Alice*)**: an "identity platform" or "a method of authenticating users"
> is an abstract idea and is **not** worth filing. Each candidate below is therefore framed as a
> *specific technical mechanism that improves how a computer network functions* — the only framing
> that survives §101. Realistically, **most of the platform is prior art** (OIDC/OAuth2/SAML, RBAC,
> SCIM, WebAuthn, Argon2, KMS envelope encryption, Kafka audit trails, database-per-service); those
> are explicitly out of scope for filing.

## Recommended filing strategy

File **one provisional application** now (cheap, establishes a 12-month priority date) covering
Invention A as the independent claim and B, C as dependent/alternative claims. Use the 12 months to
run the prior-art search and convert to a non-provisional only if A survives. Do **not** file on the
"confirmed-good but well-known" list in the appendix.

---

## Invention A — Coordination-free, self-healing propagation of per-tenant token-signing keys across a split-horizon validation mesh *(primary claim — strongest §101 story)*

### Technical problem
In a multi-tenant identity platform deployed as a service mesh, three facts collide:

1. **Split-horizon issuer identity.** A JWT's `iss` (issuer) value differs by network vantage point.
   A browser reaches the authorization server at a public host (`https://login.acme.com`); an
   in-network resource server reaches it at an internal host (`http://authorization-server:9000`).
   A resource server configured with a single expected `issuer-uri` therefore **rejects tokens
   presented from the other vantage point** — a silent, hard-to-diagnose `401`.
2. **Per-tenant signing keys.** For cryptographic tenant isolation, each tenant signs with its own
   key (distinct `kid`), so a token minted for tenant A is un-forgeable for tenant B. But the
   authorization server's *root* JWKS (JSON Web Key Set) does **not** contain any given tenant's key,
   so a resource server fetching the standard JWKS **cannot validate** a per-tenant token.
3. **Stateless, uncoordinated validators.** Resource servers are horizontally scaled and stateless;
   they cache JWKS. Rotating or (re)creating a tenant key normally requires a **coordination
   protocol** (cache-bust broadcast, versioned key endpoints, distributed cache invalidation) to
   propagate the change to every validator, or tokens signed by the new key are rejected until caches
   expire.

Existing systems solve at most one of these; the naïve combination produces intermittent
authentication failures that scale with the number of tenants and validators.

### The mechanism (claim-shaped steps)
A method comprising:

1. **Aggregate internal key-set endpoint.** The authorization server exposes a network-internal
   endpoint that returns the **union of the public keys of every tenant** it currently serves (public
   material only), such that any stateless validator resolves the verification key for *any* tenant's
   token from a **single** URI, independent of the token's issuer host.
2. **Issuer validation decoupled from key retrieval.** Each validator validates the token `iss`
   against an **allow-list** of accepted issuer values (containing both the public-vantage and
   internal-vantage forms), performed **independently** of key retrieval — so a token minted under
   either issuer identity validates against the same aggregated key set.
3. **Key-identifier regeneration as implicit cache invalidation.** When a tenant's signing key is
   created or rotated, the system assigns it a **new, unique key identifier (`kid`)**. Because a
   stateless validator keys its cache by `kid`, encountering a token with a previously-unseen `kid`
   causes the validator to **re-fetch the aggregate key set automatically** — propagating the new key
   to every validator **with no coordination message, broadcast, or distributed-cache protocol**. The
   cache "self-heals" as a side effect of normal validation.
4. **First-writer-wins convergence.** When multiple authorization-server replicas concurrently create
   the first key for a new tenant, a single-active-key constraint (e.g. a partial unique index on
   `(tenant) WHERE active`) causes the replicas to **converge on one key**, so the aggregate key set
   is consistent across replicas without a leader election or lock service.

### Why it is a technical improvement (not an abstract idea)
The claim improves **the reliability and scalability of distributed token validation** — a concrete
technical metric — by *eliminating* a class of failure (split-horizon `401`s, per-tenant-key
validation gaps, and post-rotation rejection windows) and *removing* the coordination protocol that
prior approaches require. It is rooted in the specific technology of stateless JWKS-caching
validators in a mesh; it is not a mental process or a business method.

### Prior-art delta counsel should probe
JWKS aggregation, issuer allow-lists, and `kid`-based cache lookup each exist individually. The
non-obvious element is **step 3 used deliberately as the propagation mechanism** — regenerating the
`kid` specifically so that stateless caches invalidate themselves without any coordination — combined
with steps 1, 2, and 4 to make per-tenant keys validate across a split-horizon mesh. Search: JWKS
rotation propagation, `kid` rotation, multi-tenant token validation, coordination-free cache
invalidation.

---

## Invention B — Unified single-emission event fabric with per-event fate separation *(secondary claim)*

### Technical problem
A platform needs both (a) a **forensic/compliance audit trail** that must never be lost and (b) a
**business-integration event stream** that must reliably *drive* other services. Naïvely publishing
both to one stream forces a single delivery guarantee, retention policy, and failure mode on two
requirements that are in tension: a broker outage that is acceptable for a best-effort integration
retry is **not** acceptable for a compliance record, and a retention purge that is correct for audit
data would **drop** integration events.

### The mechanism (claim-shaped steps)
A method wherein a single typed domain emission at a service is routed, **per event**, to:

1. a **durable append-only forensic store** via a path whose **floor is a synchronous local durable
   write** (structured log) performed **before** any network streaming, so the forensic record
   survives a message-broker failure; and
2. a **business-integration bus** on a **per-domain topic** with **at-least-once** delivery and
   idempotent consumers, whose delivery guarantee is selected **per flow** by whether the flow has an
   independent **correctness floor** (best-effort publish) or not (a **transactional-outbox** write in
   the same database transaction as the state change);

such that the two consumers have **independent fate** (retention, delivery, ownership) while being
derived from **one producer contract**, and neither the forensic path nor the integration path can
suppress the other.

### Why it is a technical improvement
It improves **data-integrity guarantees under partial failure** in a distributed system: it
provably preserves the compliance record across broker outages *and* provably delivers integration
events, from a single emission, without the double-publish/dual-contract complexity that forces one
guarantee on both. The per-flow floor-vs-outbox selection is a concrete technical rule, not a policy
preference.

### Prior-art delta counsel should probe
Transactional outbox, dual writes, event sourcing, and CQRS are known. The candidate novelty is the
**explicit per-event fate separation from one emission** with the **floor-vs-outbox delivery rule
keyed on the presence of an independent correctness floor**. Search: outbox pattern, audit vs domain
events, guaranteed delivery with best-effort fallback.

---

## Invention C — Transparent per-tenant isolation tiering with zero application change *(secondary claim)*

### Technical problem
Multi-tenant SaaS wants shared infrastructure for cost, but some tenants (regulated, premium) require
stronger isolation — a dedicated schema, a dedicated database instance, or a dedicated signing key.
Normally, moving a tenant to a stronger isolation tier requires an application change or redeploy.

### The mechanism (claim-shaped steps)
A method wherein, for each request, the persistence datasource **and** the cryptographic signing key
are **resolved from the request's tenant identity** through an indirection layer, such that a tenant
can be promoted from (i) shared-schema to dedicated-schema to dedicated-instance and (ii) shared to
dedicated signing key, by **configuration/data change alone**, with **no change to application code
or query logic**, and with the row-level tenant predicate remaining enforced in the shared tiers.

### Why it is a technical improvement
It improves **isolation-vs-cost configurability** of a multi-tenant datastore at runtime without
recompilation or redeployment — a concrete operational/technical capability.

### Prior-art delta counsel should probe
Per-tenant routing datasources exist (e.g. Hibernate multi-tenancy strategies). The candidate novelty
is the **unified per-request resolution of both datasource tier and signing-key tier from one tenant
identity**, spanning storage and cryptography, promotable by data change alone. Search: Hibernate
multi-tenancy, per-tenant datasource routing, schema-per-tenant promotion.

---

## Appendix — explicitly NOT to be claimed (prior art / table stakes)

Do not spend on these; they are well-known and will not survive novelty/§103/§101:

OIDC / OAuth 2.1 flows (auth-code+PKCE, client-credentials, refresh rotation, device grant), being a
SAML IdP, SCIM 2.0 provisioning, WebAuthn/passkeys, TOTP, Argon2id hashing, per-tenant OIDC issuers,
RBAC / method security, KMS envelope encryption of secrets, Kafka-based audit/CloudTrail logging,
database-per-service, edge rate limiting, mTLS service mesh, JWT `aud`/`iss` validation, refresh-token
reuse detection, tenant `X-*` header stripping at the edge.

## Appendix — evidence pointers (source, for counsel)

- Invention A: `aegis-authorization-server` — `auth/TenantJwkSource`, `web/JwksController`
  (`/internal/jwks`), `keys/JpaTenantKeyStore` (partial unique index), each service's
  `ResourceServerJwtConfig` (issuer allow-list).
- Invention B: `aegis-audit-commons` — `AuditEventPublisher`/`CompositeAuditEventPublisher`
  (log floor + Kafka), `events/DomainEventPublisher`; `aegis-platform-docs/api/events/README.md`
  (floor-vs-outbox rule).
- Invention C: `ARCHITECTURE.md §5.2` (isolation tiers) — note: the *transparent-promotion* mechanism
  is specified but only partially implemented; counsel should confirm reduction-to-practice before
  relying on it.
