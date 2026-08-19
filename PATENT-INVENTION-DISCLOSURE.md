# Aegis Identity Platform — Invention Disclosure (for patent counsel)

**Status:** DRAFT v2 (elaborated; every mechanism below re-verified against source on 2026-08-19)
**Prepared by:** engineering · **Not legal advice.** · **CONFIDENTIAL — do not publish or demo publicly before filing.**

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

## Record-keeping and confidentiality (read before doing anything else)

- **No public disclosure has been made.** The code lives in private repositories; nothing below has
  been published, demoed publicly, offered for sale, or posted. Keep it that way until a priority
  date exists: a public disclosure starts the US 12-month grace clock and **immediately destroys
  most foreign filing rights** (EU, China have no grace period).
- Concretely: do not host the platform publicly, publish blog posts / conference talks / web pages
  describing the key-propagation or event-fabric mechanisms, or share this document outside
  counsel + named inventors, until counsel says otherwise.
- **Inventorship** must be determined by counsel from contribution records (git history in the
  private repos identifies when each mechanism was authored). US inventorship is a legal
  determination, not a courtesy credit; getting it wrong can invalidate the patent.
- Dates that matter, from the repos: durable per-tenant key store + first-writer-wins convergence
  and the aggregate internal JWKS were implemented and tested by 2026-07; the unified event fabric
  with fate separation by 2026-08; the transactional-outbox flow (Invention B reduction to
  practice) on 2026-08-18.

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
   so a resource server fetching the standard JWKS **cannot validate** a per-tenant token. Worse,
   the set of tenants is **unbounded and changes at runtime** — tenants are created by API call —
   so any solution requiring per-tenant validator configuration fails structurally.
3. **Stateless, uncoordinated validators.** Resource servers are horizontally scaled and stateless;
   they cache verification keys, indexed by the token's `kid` header. Rotating or creating a tenant
   key normally requires a **coordination protocol** (cache-bust broadcast, versioned key endpoints,
   distributed cache invalidation, or a shared cache service) to propagate the change to every
   validator, or tokens signed by the new key are rejected until caches expire. The authorization
   server itself is also replicated, so even *creating* the first key for a tenant is a distributed
   race: two replicas can each mint a different "first" key, and tokens signed by one replica then
   fail against the other's key set.

Existing systems solve at most one of these; the naïve combination produces intermittent
authentication failures that scale with the number of tenants and validators.

### The mechanism (claim-shaped steps)

A method comprising:

1. **Aggregate internal key-set endpoint.** The authorization server exposes a network-internal
   endpoint that returns the **union of the active public keys of every tenant** it currently serves
   (public material only), such that any stateless validator resolves the verification key for *any*
   tenant's token from a **single, fixed** URI, independent of the token's issuer host and of the
   number of tenants. The per-tenant standards-compliant JWKS (`/{tenant}/oauth2/jwks`) is retained
   unchanged for external validators doing ordinary OIDC discovery — the aggregate endpoint is an
   *additional* projection of the same key material, not a replacement, so the mechanism is invisible
   to standard clients.
2. **Issuer validation decoupled from key retrieval, with structural tenant acceptance.** Each
   validator validates the token `iss` against an **allow-list of issuer base values** (containing
   both the public-vantage and internal-vantage forms), accepting an issuer that either (a) exactly
   equals an allowed base or (b) is a **`/{tenant}` sub-path** of one. Issuer validation is thereby
   performed **independently of key retrieval**, and the allow-list size is proportional to the
   number of network vantage points — **not** to the number of tenants — so an unbounded, runtime-
   changing tenant population is accepted with a fixed configuration. Signature and expiry
   validation remain fully enforced.
3. **Key-identifier lifecycle as implicit cache invalidation.** Every signing key carries a key
   identifier of the form `aegis-<tenant>-<random suffix>` with two deliberate properties:
   - **stable** for as long as the key is unchanged (so validator caches stay warm across
     authorization-server restarts — the key material is durable, see step 4), and
   - **globally unique across creations and rotations** (the random suffix guarantees a
     never-before-seen `kid` whenever key material changes).
   Because a stateless validator keys its cache by `kid` and re-fetches its configured key-set URI
   on an unrecognized `kid` (the standard behavior of JWKS-caching JWT libraries), any key change
   **propagates to every validator automatically, on first use, with no coordination message,
   broadcast, or distributed-cache protocol**. The cache "self-heals" as a side effect of normal
   validation; the aggregate endpoint of step 1 guarantees the re-fetch actually contains the new
   tenant's key.
4. **First-writer-wins convergence with adopt-don't-retry recovery.** Signing keys are held in a
   shared durable store with a **partial unique index** enforcing at most one *active* key per
   tenant (`UNIQUE (tenant) WHERE active` — partial, so any number of *retired* keys per tenant
   remain legal). When multiple authorization-server replicas concurrently create the first key for
   a new tenant, exactly one insert can commit; a losing replica **catches the constraint violation
   and adopts the winner's key** in a single round — no leader election, no lock service, no retry
   loop. The insert runs in its **own transaction** so the expected violation cannot poison an
   enclosing transaction (which would otherwise make the recovery read fail). Replicas serve keys
   from a **short-TTL snapshot** that bounds cross-replica staleness, with the rule that a lookup
   miss **always falls through to the store before generating** — so a stale snapshot can never
   cause a duplicate key.

### Detailed operation (enablement walk-through)

Tenant `acme` is created at runtime. The first time a token must be signed for `acme` (or eagerly,
on consuming a `tenant.created` event), an authorization-server replica looks up `acme` in its
snapshot, misses, falls through to the store, misses, generates an RSA key with
`kid = aegis-acme-3f9c21ab`, and inserts it. If a second replica raced it, the partial unique index
rejects one insert and that replica adopts the committed key. A user of `acme` signs in; the token
is signed with `aegis-acme-3f9c21ab` and carries `iss = https://login.example.com/acme` (browser
vantage) or `http://authorization-server:9000/acme` (service vantage). A resource server receiving
the token checks `iss` against its two-entry allow-list — `/acme` is a sub-path of an allowed base,
accepted — then looks up `aegis-acme-3f9c21ab` in its key cache, misses (this `kid` has never
existed before), re-fetches the aggregate endpoint `/internal/jwks`, finds the key, validates the
signature, and caches it. Every other validator replica does the same on its own first encounter.
No component told any validator that `acme` exists. On a later rotation, a new
`kid = aegis-acme-77d0e4c2` repeats the same propagation automatically.

### Reduction to practice — what is built vs. specified (counsel must know this)

- **Fully implemented and test-verified:** aggregate endpoint; allow-list validation with sub-path
  acceptance; durable store with the partial unique index; first-writer-wins adoption (including
  the separate-transaction recovery); TTL snapshot with fall-through; unique-`kid` generation;
  eager provisioning from `tenant.created` events; private key halves stored envelope-encrypted
  (AES-256-GCM, KMS-wrappable data key).
- **Specified but NOT yet implemented:** an operator-facing *rotation operation*. The schema
  supports retirement (`active` flag, `retired_at`, and the partial index deliberately permits many
  retired rows so superseded keys can be kept verifiable), and the `kid` scheme guarantees rotation
  would propagate — but no rotate API exists yet, and the aggregate endpoint currently serves
  **active keys only**, so the overlap window in which a retired key remains served for
  already-issued tokens is design intent, not code. Claims should treat rotation as an embodiment;
  the *creation* path is the reduced-to-practice core.

### Dependent-claim candidates

- The `kid` naming scheme (`prefix-tenant-randomsuffix`) allowing the tenant index to be
  reconstructed from the key set itself.
- Envelope encryption of the stored private key halves with a KMS-wrapped data key, public halves
  deliberately in the clear.
- The snapshot-TTL staleness bound combined with the always-fall-through-on-miss rule.
- Pre-warming the default key on aggregate-endpoint fetch so an early-booting validator never
  caches an empty key set.
- Eager per-tenant key provisioning driven by a tenant-creation event, so the first user login pays
  no key-generation latency.
- Retention of retired keys for verification-overlap during rotation (the specified embodiment).

### Why it is a technical improvement (not an abstract idea)

The claim improves **the reliability and scalability of distributed token validation** — a concrete
technical metric — by *eliminating* a class of failure (split-horizon `401`s, per-tenant-key
validation gaps, post-rotation rejection windows, and replica key-divergence) and *removing* the
coordination protocol that prior approaches require. Configuration is O(vantage points) where prior
approaches are O(tenants × validators). It is rooted in the specific technology of stateless
JWKS-caching validators in a service mesh; it is not a mental process or a business method.

### Prior-art delta counsel should probe

JWKS aggregation, issuer allow-lists, and `kid`-based cache lookup each exist individually. The
non-obvious element is **step 3 used deliberately as the propagation mechanism** — engineering the
`kid` lifecycle (stable while unchanged, guaranteed-fresh on change) specifically so that stateless
caches invalidate themselves without any coordination — **combined** with steps 1, 2, and 4 to make
per-tenant keys validate across a split-horizon mesh with fixed-size configuration. Search: JWKS
rotation propagation, `kid` rotation cache invalidation, multi-tenant token validation, issuer
allow-list sub-path, coordination-free cache invalidation, partial unique index leader-free
convergence. Adjacent art to distinguish: Keycloak realms (per-realm JWKS, validators configured
per realm — O(tenants) config), Auth0/Okta custom domains (single-tenant issuer aliasing, not
per-tenant keys from one aggregate), Kubernetes-style shared caches (a coordination component the
claim removes).

---

## Invention B — Unified single-emission event fabric with per-event fate separation *(secondary claim)*

### Technical problem

A platform needs both (a) a **forensic/compliance audit trail** that must never be lost and (b) a
**business-integration event stream** that must reliably *drive* other services. Naïvely publishing
both to one stream forces a single delivery guarantee, retention policy, and failure mode on two
requirements that are in tension: a broker outage that is acceptable for a best-effort integration
retry is **not** acceptable for a compliance record, and a retention purge that is correct for audit
data would **drop** integration events. Running two fully separate emission systems doubles producer
code and lets the two records drift.

### The mechanism (claim-shaped steps)

A method wherein a single typed domain emission at a service is routed, **per event**, to:

1. a **durable append-only forensic path** whose **floor is a synchronous local durable write**
   (structured log) performed **before** any network streaming is attempted, with each downstream
   delegate **failure-isolated** so a message-broker outage cannot suppress the logged record; the
   streamed copies land on a **single platform-wide audit topic** consumed into a queryable,
   retention-managed audit store; and
2. a **business-integration path** on **per-domain topics** with **at-least-once** delivery and
   idempotent consumers, whose producer-side delivery guarantee is selected **per flow** by a
   defined rule: if the flow has an independent **correctness floor** (a mechanism by which the
   system converges to the correct state even if the event is lost — e.g. lazy on-demand creation),
   the event is published **best-effort after commit**; if it has **no floor** (a lost event means a
   permanently missed side effect), the event is staged by a **transactional outbox** — written in
   the **same database transaction** as the state change and relayed to the broker by a poller that
   marks rows published **only after broker acknowledgment**;

such that the two paths have **independent fate** (retention, delivery guarantee, ownership,
consumer population) while being derived from **one producer-side emission contract**, and neither
path can suppress the other.

### Detailed operation (enablement walk-through)

Two contrasting live flows, both implemented:

- **Floored flow (best-effort):** `tenant.created` is emitted once; the forensic path logs it
  synchronously and streams a copy to the audit topic; the business path publishes it to the tenant
  domain topic, where the authorization server consumes it to eagerly provision the tenant's
  signing key. If that business publish is lost, nothing breaks — the key is lazily created on
  first use (the floor). Best-effort is therefore *correct*, and outbox machinery would be waste.
- **Floor-less flow (outbox):** `identity.user.created` must drive outbound SCIM provisioning; no
  lazy mechanism will ever re-derive it, so a lost event is a user who silently never provisions.
  The user row and the outbox row commit **atomically**; a relay publishes the row to the identity
  domain topic and marks it published only on broker ack (at-least-once). The consumer is
  idempotent by unique constraint on the user id, converting redelivery into a no-op — including
  under concurrent redelivery, where the constraint violation is caught and treated as success.

### Reduction to practice

Fully implemented and verified live: the composite forensic path (log floor first, delegate
isolation), the platform-wide audit topic with queryable sink and scheduled retention purge, both
delivery modes of the business path (best-effort `tenant.created` → key provisioning; outbox
`identity.user.created` → SCIM task), integration-tested against a real broker including the
lost-broker case (floor survives) and the redelivery case (consumer idempotent).

### Dependent-claim candidates

- The floor-vs-outbox selection rule itself, keyed on presence of an independent correctness floor.
- Delegate failure-isolation ordering (durable local write strictly before any network attempt).
- Outbox rows marked published only on broker acknowledgment (crash between ack and mark yields
  redelivery, resolved by consumer idempotency — at-least-once end-to-end).
- Consumer idempotency implemented as a database unique constraint with race-tolerant
  violation-as-success handling, rather than consumer-side dedup state.
- A prohibition rule on the forensic path's schema: audit events never carry secret material.

### Why it is a technical improvement

It improves **data-integrity guarantees under partial failure** in a distributed system: it
provably preserves the compliance record across broker outages *and* provably delivers integration
events, from a single emission, without the double-publish/dual-contract complexity that forces one
guarantee on both. The per-flow floor-vs-outbox selection is a concrete technical rule, not a policy
preference.

### Prior-art delta counsel should probe

Transactional outbox, dual writes, event sourcing, CQRS, and change-data-capture are known. The
candidate novelty is the **explicit per-event fate separation from one emission** with the
**floor-vs-outbox delivery rule keyed on the presence of an independent correctness floor**. Search:
outbox pattern, audit vs domain events, guaranteed delivery with best-effort fallback, CloudTrail
architecture, Debezium outbox router (distinguish: CDC relays *one* stream; it does not fate-split
one emission into forensic + integration paths with per-flow guarantees).

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

### Reduction to practice — split status (counsel must know this)

- **Implemented:** the cryptographic half — per-tenant signing keys resolved per request from the
  tenant identity (Invention A's store *is* this indirection layer for keys), plus row-level
  tenant predicates in the shared tier.
- **Design-only:** the datasource-routing half (shared-schema → dedicated-schema → dedicated-
  instance promotion). It is specified in the architecture document but **no routing-datasource
  code exists yet**. Claim only as an embodiment/dependent claim unless implemented before filing;
  A + B are the reduction-to-practice core of the disclosure.

### Prior-art delta counsel should probe

Per-tenant routing datasources exist (e.g. Hibernate multi-tenancy strategies, AWS SaaS-factory
tiering patterns). The candidate novelty is the **unified per-request resolution of both datasource
tier and signing-key tier from one tenant identity**, spanning storage and cryptography, promotable
by data change alone. Search: Hibernate multi-tenancy, per-tenant datasource routing,
schema-per-tenant promotion, SaaS tenant tiering silo/pool.

---

## Proposed figures (for the provisional; renderable versions in the companion deep-dive doc)

- **FIG. 1** — Deployment topology: browser vantage vs in-network vantage of the same authorization
  server; split-horizon issuer values; validators fetching one aggregate key-set URI.
- **FIG. 2** — Sequence: tenant creation → racing key generation on two replicas → partial-index
  arbitration → adoption by the losing replica.
- **FIG. 3** — Sequence: token with never-before-seen `kid` → validator cache miss → aggregate
  re-fetch → validation success (self-healing propagation, no coordination message).
- **FIG. 4** — Event fabric: one emission fanning to the forensic path (synchronous durable floor →
  audit topic → queryable sink with retention) and the business path (per-domain topics).
- **FIG. 5** — Flowchart: the floor-vs-outbox selection rule; outbox sequence with
  ack-before-mark and idempotent consumption.
- **FIG. 6** — Isolation tiering: tenant identity resolving both datasource tier and signing-key
  tier through one indirection layer.

---

## Appendix — explicitly NOT to be claimed (prior art / table stakes)

Do not spend on these; they are well-known and will not survive novelty/§103/§101:

OIDC / OAuth 2.1 flows (auth-code+PKCE, client-credentials, refresh rotation, device grant), being a
SAML IdP, SCIM 2.0 provisioning, WebAuthn/passkeys, TOTP, Argon2id hashing, per-tenant OIDC issuers,
RBAC / method security, KMS envelope encryption of secrets, Kafka-based audit/CloudTrail logging,
database-per-service, edge rate limiting, mTLS service mesh, JWT `aud`/`iss` validation, refresh-token
reuse detection, tenant `X-*` header stripping at the edge, the transactional-outbox pattern *as
such*, JWKS caching and re-fetch-on-unknown-`kid` *as such*.

## Appendix — evidence pointers (source, verified 2026-08-19)

- **Invention A:**
  `aegis-authorization-server/src/main/java/io/aegis/authorizationserver/auth/TenantJwkSource.java`
  (snapshot TTL, fall-through rule, unique-`kid` generation, generation lock);
  `.../web/JwksController.java` (`/internal/jwks` aggregate, default-key pre-warm);
  `.../keys/JpaTenantKeyStore.java` (`saveIfAbsent` adopt-don't-retry in `REQUIRES_NEW`);
  `src/main/resources/db/postgresql/tenant-signing-key-schema.sql`
  (`uk_tenant_signing_key_one_active_per_tenant … WHERE active` — the partial unique index; also
  the retirement columns evidencing the rotation embodiment);
  `.../keys/TenantLifecycleConsumer.java` (eager provisioning from `tenant.created`);
  each service's `ResourceServerJwtConfig.java` (issuer allow-list with `/{tenant}` sub-path
  acceptance — e.g. `aegis-identity-service/src/main/java/io/aegis/identity/config/`).
- **Invention B:**
  `aegis-platform-commons/aegis-audit-commons/src/main/java/io/aegis/commons/audit/`
  (`CompositeAuditEventPublisher` — floor-first ordering + delegate isolation;
  `KafkaAuditEventPublisher`, `LoggingAuditEventPublisher`, `AuditRecorder`);
  `io/aegis/commons/events/DomainEventPublisher.java` (business path, per-domain topics);
  `aegis-identity-service/.../outbox/` (`OutboxWriter`, `OutboxRelay` — ack-before-mark;
  `V2__outbox_event.sql`);
  `aegis-scim-provisioning-service/.../outbound/IdentityUserConsumer.java` (idempotent consumer,
  violation-as-success race handling);
  `aegis-admin-api-service/.../audit/` (queryable sink + `AuditLogRetentionService`);
  `aegis-platform-docs/api/events/README.md` (the floor-vs-outbox rule, stated as contract).
- **Invention C:** `aegis-platform-docs/architecture/ARCHITECTURE.md` §5.2 (isolation tiers —
  design); implemented half evidenced by Invention A's per-tenant key resolution; **datasource
  routing not yet in code** (no routing-datasource implementation exists as of 2026-08-19).
