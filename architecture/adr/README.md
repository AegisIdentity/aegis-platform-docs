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

## ADR-0010 — Delegation chain is a first-class, **additive** audit and token construct
**Context:** `AuditEvent` (aegis-audit-commons) carries a single `actor` and a single `target`
string. Agent authority is irreducibly a chain — *human H authorized agent A, which invoked tool T on
server S against resource R* — and a one-actor schema can neither express it, authorize on it, nor
feed anomaly detection with it. Critically, `AuditEvent`'s own javadoc states records are "streamed
to customer SIEMs": the schema is a **customer-facing contract**, not an internal record.
**Decision:** Extend the chain **additively only**. `actor` keeps its exact present meaning — the
*effective* actor, i.e. the last hop — so every existing SIEM parser keeps working unchanged. New
optional fields: `onBehalfOf` (the root human/service subject), `delegationChain` (ordered hops,
nearest-last), `agentInstanceId`, `toolInvocationId`. Semantics mirror RFC 8693: the **subject never
changes** while the **actor chain grows**. Redefining `actor` is explicitly forbidden.
**Consequences:** (+) zero downstream breakage; the chain becomes available to the PDP and to
detection; forensic record and authorization decision agree because both derive from the same
structure. (−) Two representations must stay in sync (a token's nested `act` claim vs. the audit
chain) — mitigated by *deriving* the audit chain from the presented token rather than re-deriving it
independently.

## ADR-0011 — Protocol-agnostic agent identity core, with per-protocol adapters
**Context:** The agent protocol landscape is churning faster than any release cycle we can match. In
roughly twelve months MCP moved to revision `2026-07-28` and **deprecated Dynamic Client
Registration** in favour of Client ID Metadata Documents; A2A reached 1.0 (Jan 2026) and added signed
Agent Cards; AP2 (Agent Payments) is at 0.2.0 (Apr 2026). Binding the identity model to any one
protocol — or to any vendor SDK — guarantees a rewrite.
**Decision:** The core domain (`AgentPrincipal`, `DelegationChain`, `ToolDescriptor`, `Mandate`,
`AgentCapability`) is defined in `aegis-agent-commons` and knows **nothing** about MCP, A2A or AP2.
Each protocol gets a thin adapter that translates its wire format into the core model. Protocol churn
is contained inside adapters; the AS, PDP, registry and detection pipeline never see protocol types.
**Consequences:** (+) multiple protocols supported simultaneously and independently versioned; a
protocol revision is an adapter change, not a platform change. (−) an indirection layer, and a real
risk of lowest-common-denominator modelling — mitigated by allowing each adapter to attach
namespaced protocol-specific attributes that pass through opaquely.

## ADR-0012 — RFC 8693 token exchange is the delegation primitive; ID-JAG for enterprise-managed MCP
**Context:** The platform ships `authorization_code`+PKCE, `client_credentials`, `refresh_token` and
`device_code` — none of which can express "mint a narrower token for a downstream hop while
preserving who the human was." Separately, MCP's **Enterprise-Managed Authorization** extension is
*stable* and already adopted by Okta, Microsoft Entra and Auth0; it is the surface on which
enterprise agent deals are currently won or lost, and Aegis cannot participate without it.
**Decision:** (a) Enable RFC 8693 token exchange — Spring Authorization Server 7.1.0 ships
`OAuth2TokenExchangeAuthenticationProvider`, so this is configuration plus claim customization
(`act` nesting, `may_act` pre-authorization, audience narrowing on every hop). (b) Build a custom
**RFC 7523 `jwt-bearer` grant** — verified absent from SAS 7.1.0, so it is ours to write — to redeem
an Identity Assertion JWT Authorization Grant (**ID-JAG**). (c) Act as the enterprise IdP that
*issues* ID-JAGs after evaluating tenant policy, so access to MCP servers is centrally granted and
centrally revoked.
**Consequences:** (+) standards-based delegation with an auditable exchange record; downstream
services never see the original user token; EMA interop unlocks the enterprise agent story;
revocation becomes a single control-plane action. (−) the `jwt-bearer` provider is ours to maintain
and it sits on the token path — hence TDD-first with explicit negative tests.

## ADR-0013 — Tool identity is content-addressed; consent pins a definition hash
**Context:** A tool's *description* is the instruction surface the model reads. A server can
therefore change what a tool means without changing its name — the "tool poisoning" / "rug pull"
class, which has no analogue in human IAM. Our existing `JdbcOAuth2AuthorizationConsentService` is
**scope**-granular and cannot express "I approved *this version* of this tool."
**Decision:** Tool identity is the triple `(server_id, tool_name, definition_hash)` where
`definition_hash` is a canonical digest over the tool's semantic definition (name, description,
input schema) — deliberately excluding cosmetic fields. Consent records **pin** the hash. A hash
change invalidates consent and forces re-approval before the tool may be invoked again.
**Consequences:** (+) post-approval redefinition becomes *detectable* rather than silent, and the
detection is cheap (a digest comparison). (−) benign edits can force re-consent — mitigated by
hashing only semantically meaningful fields, and by a tenant policy switch for auto-re-approval of
cosmetic-only drift.

## ADR-0014 — Agent threat analysis is sequence-shaped and runs off the audit fabric, never inline
**Context:** Human risk heuristics do not transfer. Impossible-travel, login cadence and device
fingerprinting are meaningless for a principal that legitimately makes hundreds of calls per minute
from a datacentre IP. What is anomalous about an agent is the *shape of its behaviour over time*.
**Decision:** Detection consumes the `aegis.audit.events` Kafka topic asynchronously and scores
sequences: tool-call entropy, high-risk tool *pairings* (read-credentials → external-network-write is
the signal, not either call alone), delegation-chain depth and drift, scope escalation relative to
the root subject's own grants, and deviation from a declared task envelope. It **never** sits on the
synchronous token-issuance path.
**Consequences:** (+) zero added latency to authentication; the stream is replayable so detectors can
be retrained and backtested against real history. (−) detection is post-hoc *by design* — it cannot
block the first bad call. The synchronous controls that *can* are the PDP (ADR-0013) and gateway
quotas; detection's job is fast revocation and blast-radius limitation, and this ADR states that
division of labour so nobody mistakes detection for prevention.

## ADR-0015 — HashiCorp Vault is the per-tenant key & secret substrate (supersedes ADR-0007 in part)
> **Status: Accepted — migration NOT yet executed (as of 2026-08-26).** `aegis-vault-commons` is
> built and tested, but the authorization server still signs using the ADR-0007 KMS path. Until the
> migration in `VAULT-ARCHITECTURE.md` §7 runs, this ADR describes the **target**, and ADR-0007's
> key-wrapping mechanism remains the one in force. Read the decision below as intent, not as a
> description of the running system.

**Context:** ADR-0007 wrapped per-tenant signing keys with **cloud KMS** envelope encryption. Three
problems have surfaced. It is cloud-specific, so AWS and Azure deployments diverge exactly where they
must not; local development has no faithful equivalent, so the most security-critical path is the
least-tested one; and it cannot be offered *to* tenants, only used on their behalf.
**Decision:** Adopt HashiCorp Vault as the uniform substrate. **Transit** performs key generation,
signing and rotation with private material that never leaves Vault; **KV v2** stores secrets with
versioning; **PKI** issues short-lived workload certificates (which also unblocks the mTLS work in
ADR-0008). Per-tenant isolation uses a Vault **namespace** per tenant on Enterprise, or a
path-plus-policy convention (`aegis/{tenant}/…`) on OSS, selected by configuration so the code path is
identical. Cloud KMS is **demoted** from an application dependency to Vault's *auto-unseal* provider.
**Consequences:** This **supersedes the key-wrapping mechanism of ADR-0007** while preserving its
intent (per-tenant keys, no regeneration on restart, overlapping rotation). (+) one API across local,
AWS and Azure; genuine per-tenant cryptographic isolation; private keys never enter application
memory at all — a strict improvement on "unwrapped and briefly cached"; local dev finally exercises
the real path. (−) Vault becomes a tier-0 dependency on the token path — mitigated by an HA Raft
cluster (ADR-0016), short-lived local caching of *public* material only, and a documented degraded
mode in which already-cached verification keys keep serving while signing fails closed.

## ADR-0016 — Vault runs HA everywhere and is exposed as a tenant-facing service
**Context:** Making Vault tier-0 (ADR-0015) means a single-node Vault is no longer acceptable even in
development, or the dev topology stops predicting production behaviour. Separately, tenants of an
identity platform repeatedly ask for exactly what Vault provides — managed secrets and managed keys —
and the platform already operates it.
**Decision:** (a) Vault runs as an **integrated-storage (Raft) HA cluster** in every topology: 3
nodes in Docker Compose locally, 3–5 replicas via Helm on EKS/AKS, with auto-unseal by AWS KMS /
Azure Key Vault and Raft snapshots to object storage. (b) Vault is offered as a product surface —
**Key Management as a Service** and **Secrets Management as a Service** — through
`admin-api-service` at `/api/v1/tenants/{id}/vault/**`. Access is **brokered**: tenants never receive
a raw Vault token; the platform mints short-lived, path-scoped child tokens per request. (c) The
platform **uses the same engines for its own secrets and keys**, and this dogfooding is documented
explicitly rather than left implicit.
**Consequences:** (+) one operational model everywhere; dev/prod parity on the most security-critical
component; a genuine product surface at near-zero marginal cost; internal and external consumers
exercise the same code, so tenant-facing bugs surface internally first. (−) the broker becomes a
high-value target — mitigated by strict server-side path templating (no tenant-supplied paths ever
reach Vault), per-tenant policy generation, and a mandatory negative cross-tenant test; and HA Vault
is materially more to operate than a KMS API call, which is accepted as the cost of the parity.

## ADR-0017 — Agent principals must hold sender-constrained tokens
**Context:** A bearer token is a bearer token: whoever holds it may use it. For a human in a browser
the exposure surface is well understood. An agent is different in kind — it processes attacker-
influenced content (documents, tool results, web pages) inside the same context that holds its
credentials, so prompt injection can exfiltrate a bearer token through an entirely legitimate-looking
tool call. MCP's 2026-07-28 revision moved the same direction, making audience binding mandatory and
forbidding servers from accepting or transiting foreign tokens.
**Decision:** Tokens issued to **agent** principals MUST be sender-constrained — DPoP
(proof-of-possession, `cnf.jkt`) by default, or mTLS-bound (`cnf.x5t#S256`) where the agent is a
mesh workload. Human interactive sessions may continue to use bearer. Every token exchange hop
re-binds to the *presenting* key, so a stolen intermediate token is unusable.
**Consequences:** (+) an exfiltrated agent token is inert without the corresponding private key,
which converts the most likely agent compromise from "silent, durable account takeover" into "a
failed request." (−) agent clients must implement DPoP — an acceptable cost because agent
integrations are new code being written now, not a legacy estate being retrofitted.
