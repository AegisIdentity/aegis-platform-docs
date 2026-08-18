# Aegis — design & roadmap for the deferred large capabilities

> **UPDATE 2026-08-18 (second session):** two of these four are now **BUILT and verified**, not
> deferred:
> - **Kafka event backbone → DONE.** Platform-wide, CloudTrail-style capture is live: a shared
>   `KafkaAuditEventPublisher` (composed with the log floor) streams every service's security events
>   to one topic; an audit **sink** in `admin-api-service` consumes them into an append-only
>   `audit_log` store, queryable via `/api/v1/admin/system-log` (tenant-scoped). Proven end-to-end on
>   the running stack (auth success/failure, authz denials, and identity/tenant/admin domain events
>   all captured; failed-login actors hashed) and by a Testcontainers Kafka IT (`AuditSinkIT`, Confluent broker).
> - **KMS envelope encryption → DONE.** Tenant signing keys' data key can be KMS-wrapped: a
>   `DataKeyProvider` seam (static vs KMS-envelope), an `AwsKmsKeyUnwrapper` (AWS SDK v2), unwrapped
>   at startup. Proven against **real LocalStack KMS** (`AwsKmsUnwrapIT`) — the actual SDK Decrypt
>   path, no cloud account. Off by default (`aegis.crypto.kms.enabled`); the static-key posture
>   remains the interim default.
>
> **Still deferred:** the SAML IdP (§1) and mTLS/mesh (§4) — unchanged, for the reasons below.

---

## 1. SAML 2.0 Identity Provider — ⛔ not started · highest effort · highest risk

**What exists:** `aegis-saml-idp-service` is a 3-class Spring Boot resource-server scaffold
(`SamlApplication`, `SecurityConfig`, `InfoController`). No OpenSAML dependency, no XML handling, no
signing keys. It is not in the docker-compose stack.

**Why it is not built in haste.** This service parses XML that an attacker fully controls (the SAML
`AuthnRequest`, and SP metadata). The vulnerability classes here are the ones that have repeatedly
broken real IdPs:
- **XML signature wrapping (XSW)** — the signature validates over one element while the processor
  reads another. The defence is to validate the signature over the *exact* element subsequently
  consumed, using a schema-aware, ID-resolved reference — not "does a valid signature exist somewhere
  in the document".
- **XXE** — external entity resolution must be disabled on every parser instance, and this must be
  proven by a test that feeds a billion-laughs / external-entity payload and asserts rejection.
- **DEFLATE decompression bombs** — the Redirect binding base64-decodes then inflates; an inflate
  with no size cap is a memory-exhaustion DoS. A hard decompressed-size limit is mandatory.
- **Comment truncation of `NameID`** — XML-canonicalisation differences let `admin@evil.com<!--
  -->.example.com` be read as two different identities by signer and consumer.

None of these is defensible by "be careful"; each needs a specific control plus a specific negative
test. Building the happy path first and hardening later is how IdPs get breached.

**Target design.**
- Built directly on **OpenSAML 5** (requires the Shibboleth Maven repo `build.shibboleth.net`).
  Spring Security provides only SP support, so the IdP is bespoke — this is ADR-0005.
- Endpoints: `/saml2/idp/metadata`, `/saml2/idp/sso` (Redirect + POST bindings, SP-initiated first,
  IdP-initiated later), `/saml2/idp/slo`; admin: SP registration + metadata import.
- Per-tenant signing certificates, **KMS-wrapped** (shares the key-management design in §3).
- **Process/network isolation is the containment story** (ADR-0005 / ARCHITECTURE §3.1): a
  compromise in the XML parser must not sit in the same address space as the credential store. Ship
  it with its own restrictive `NetworkPolicy` and no reach to identity-service's database.

**v1 scope:** SP-initiated SSO + signed assertion, with the four XML hardening controls above and a
negative test for each. IdP-initiated flows and assertion *encryption* follow in v2.

**Effort:** the largest single build in the platform — estimate a multi-sprint effort dominated by
the security test suite, not the happy path. **Sequence it after** rate limiting and audience
validation are live, so it is never the least-hardened thing in production.

---

## 2. Kafka event backbone — ✅ BUILT (2026-08-18) · was: seam exists

**What exists:** the `audit-commons` library already defines the seam — `AuditEventPublisher` (SPI)
with a `LoggingAuditEventPublisher` that every service gets by autoconfiguration. Events are emitted
today; they just go to a structured `AUDIT` log rather than a bus. There is **no** `spring-kafka`,
producer, consumer, or topic anywhere; the compose stack runs a Kafka broker nothing connects to.

**Why the seam matters.** Because the publisher is an interface with a `@ConditionalOnMissingBean`
default, adding Kafka is *additive*: a service declares a `KafkaAuditEventPublisher` that decorates
the logging one, and the default backs off. No call site changes. This is the cheapest of the four
to build precisely because the abstraction was put in first.

**Target design.**
- Domain + audit events per ARCHITECTURE §4.4: `identity.user.created|updated|deactivated|deleted`,
  `auth.login.succeeded|failed`, `auth.token.issued|revoked`, `authz.access.denied`,
  `tenant.created|suspended`.
- Schemas versioned in `aegis-platform-docs/api/events/` (Avro or JSON Schema), validated on consume.
- Consumers: an **audit sink** (append-only store → customer SIEM, the Okta System Log analogue) and
  **SCIM outbound** provisioning driven by `identity.user.*`.
- Managed equivalents: AWS MSK / Azure Event Hubs (Kafka endpoint) — both already provisioned in
  Terraform.
- **Delivery semantics:** audit events are security records, so at-least-once with idempotent
  consumers (dedupe on event id). Never let a Kafka outage block the request path — publish
  asynchronously and fall back to the log publisher, which is exactly what the SPI decoration gives.

**Effort:** moderate. The seam removes most of the risk. **Sequence:** early — it unlocks the
System Log product surface and cross-service provisioning, and de-risks the SCIM outbound build.

---

## 3. KMS / envelope encryption for signing keys — ✅ BUILT (2026-08-18) · was: KMS-ready

**What exists (as of this session):** per-tenant signing keys are now **persisted and encrypted at
rest** (`tenant_signing_key`, AES-256-GCM via a single application-held key). The store is behind the
`TenantKeyStore` interface. There is no cloud-KMS call anywhere; the field-encryption key is an env
var. Terraform provisions a KMS module that nothing consumes.

**Why the data model is already KMS-ready.** The private key is stored as ciphertext with a `v1:`
scheme prefix, and unwrapping goes through one method (`JpaTenantKeyStore#toRsaKey`). A KMS-backed
implementation is a new `TenantKeyStore` (or a new `FieldEncryption` whose key-encryption-key is a
KMS-wrapped data key) — **no schema migration**, because "encrypted blob + version prefix" already
describes envelope encryption; only the source of the key-encryption-key changes.

**Target design (ADR-0007).**
- Envelope encryption: a per-tenant (or per-region) **data key** generated by and wrapped with a
  cloud **KMS CMK** (AWS KMS / Azure Key Vault). The wrapped data key is stored; the CMK never leaves
  KMS. Unwrap on demand, cache the plaintext data key briefly in memory.
- **Rotation with overlap** (already modelled in the schema via `active` + the partial unique index):
  publish a new `kid` in JWKS *before* it signs; keep the old `kid` verifiable until its tokens
  expire; retire, don't delete. A scheduled, audited job drives it.
- The `v1:` prefix becomes the migration lever: a `v2:` (KMS-wrapped) scheme can coexist with `v1:`
  rows, re-encrypting lazily on next save.

**Critical operational note already enforced in code:** losing the field-encryption key makes every
stored tenant key undecryptable. Under KMS the equivalent is the CMK — it must have deletion
protection, key rotation, and cross-region replication for DR. This is called out in
`values-authorization-server.yaml`.

**Effort:** small-to-moderate (one new `TenantKeyStore` impl + rotation job). **Sequence:** before
GA, after the event backbone. The current AES-GCM-at-rest posture is a legitimate interim state, not
a hole — it just holds the KEK in a secret manager rather than a dedicated HSM/KMS.

---

## 4. mTLS east-west + workload identity — ⛔ not started

**What exists:** nothing. ADR-0008 specifies mTLS for service-to-service peer authentication plus a
scoped `client_credentials` bearer token for authorization; today the gateway→service and
service→service hops are plaintext HTTP (`http://identity-service:9102`, etc.), and the only "client
auth" in the codebase is OAuth `CLIENT_SECRET_BASIC`, not TLS.

**Why this is deliberately a platform/mesh concern, not application code.** Doing mTLS *in* each
Spring service (custom `SSLContext`, cert loading, rotation) is the wrong layer — it couples every
service to certificate lifecycle and is easy to get subtly wrong. The right design delegates it to
the deployment substrate:
- A **service mesh** (Istio / Linkerd) or SPIFFE/SPIRE issues short-lived workload SVIDs and
  terminates mTLS in a sidecar, so peer identity is established *below* the application. The service
  keeps doing token-scope authorization; the mesh proves "who is calling".
- **Two layers, unchanged from ADR-0008:** mTLS = *who you are* (workload identity), token scope =
  *what you may do*. A call is accepted only if *both* the mTLS peer is a known workload *and* the
  token scope permits the operation.
- The `X-Aegis-Tenant` internal header is honoured only on mTLS-verified internal connections — the
  mesh peer identity is what makes that trust decision sound.

**What the application must still provide:** the services already assume they sit behind a trusted
hop (the gateway strips client-supplied `X-Aegis-Tenant` and `X-Forwarded-*`). The remaining app-side
work is small: accept a mesh-provided peer-identity header, and gate the internal endpoints on it.

**Effort:** low in application code, moderate in platform (mesh install, cert automation, policy).
**Sequence:** an infra/platform workstream that can run in parallel; the app-side changes are a thin
follow-on. Until then, the network-policy isolation (default-deny, owner-only DB access) is the
interim containment, and L-edge-3 documents the plaintext hop as a known prod-gate.

---

## Recommended build order

1. **Kafka event backbone** — cheapest (seam exists), unlocks System Log + SCIM outbound.
2. **KMS envelope encryption** — small, data-model-ready, needed before GA.
3. **mTLS / mesh** — parallel platform workstream, thin app follow-on.
4. **SAML IdP** — last and largest; must not be the least-hardened thing in prod, so it follows rate
   limiting, audience validation, and the mesh.
