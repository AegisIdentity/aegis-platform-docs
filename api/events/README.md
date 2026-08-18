# Aegis event contracts

Two distinct event fabrics run on Kafka. They look similar (both are JSON on Kafka) but are
deliberately **separate concerns** — different topics, delivery semantics, ownership, and retention.
Conflating them is an anti-pattern.

## 1. Audit / observability events — `aegis.audit.events`

The forensic trail (the CloudTrail / Okta System-Log analogue). Every service publishes
security-relevant events here through the shared `AuditEventPublisher`; the `admin-api` **audit sink**
consumes them into the append-only, retention-bounded `audit_log` store, queryable at
`/api/v1/admin/system-log`, and the same stream is tee-able to a customer SIEM.

- **One topic**, many producers, one sink consumer.
- **Best-effort streaming with a durable log floor** — the structured `AUDIT` log is written first and
  always, so a broker outage never suppresses a compliance record. Audit is allowed to *degrade*,
  never to *break* a request.
- **Forensic format**, not an inter-service contract. Fields: `type, action, outcome, tenantId,
  actor, target, correlationId, at, attributes` (see `io.aegis.commons.audit.AuditEvent`).
- Retention: purged beyond `aegis.audit.retention.days` (default 365); archive-before-purge for
  long-term cold storage.

## 2. Business / integration events — per-domain topics (e.g. `aegis.tenant.lifecycle`)

The **choreography backbone** (ARCHITECTURE §4.4 / ADR-0003). A domain state change is published so
*other services can react*, decoupling side effects from the originating request.

- **Per-domain topics**, so a consumer subscribes to the domain it cares about rather than filtering
  one firehose. Keyed by aggregate id (tenant, user) for per-aggregate ordering.
- **At-least-once delivery; consumers MUST be idempotent.** These events *drive* behaviour, so they
  cannot be silently dropped the way an audit stream copy can.
- **A versioned contract between services** — schemas live here (`*.v1.json`). Consumers read
  tolerantly (unknown fields ignored). A breaking change is a new version, never an edit to a
  published schema.
- Published via `io.aegis.commons.events.DomainEventPublisher` (distinct from the audit publisher).

### Why not one topic for both?

- **Fate.** A compliance record must survive a broker hiccup (log floor); a provisioning event must
  actually be delivered (outbox / at-least-once). They must not share fate.
- **Retention.** Audit has a compliance TTL and is purged; a business event is a transient signal.
- **Ownership.** Audit is owned by the audit pipeline; a business event is a contract owned by the
  producing domain.

### Delivery guarantee per flow — floor vs outbox

- A flow with an **independent correctness floor** can use best-effort publishing: a lost event is a
  missed *optimization*, not a lost side effect. Example: `tenant.created → eager key provisioning`
  — the authorization-server still provisions the key lazily on first use if the event is lost, so
  best-effort is sufficient.
- A flow with **no floor** (e.g. outbound provisioning to a downstream app) MUST use the
  **transactional outbox** pattern — persist the event in the same DB transaction as the state
  change and relay it to Kafka — to avoid the dual-write problem. This is a per-flow decision.

## Implemented flows

| Event | Topic | Producer | Consumer | Effect | Floor |
|---|---|---|---|---|---|
| `tenant.created` | `aegis.tenant.lifecycle` | tenant-service | authorization-server (`TenantLifecycleConsumer`) | eager per-tenant signing-key provisioning | lazy on-first-use |

## Roadmap flows (designed, not built)

| Event | Topic | Consumer(s) | Effect |
|---|---|---|---|
| `identity.user.created\|updated\|deactivated\|deleted` | `aegis.identity.user` | scim-outbound; cache invalidation; welcome flow | SCIM push to downstream apps (needs the outbox — no floor) |
| `tenant.suspended` | `aegis.tenant.lifecycle` | authorization-server; admin-api | revoke tokens, disable sign-in, freeze policies |
| `auth.token.issued\|revoked` | `aegis.auth.token` | revocation cache; anomaly detection | short-lived token/consent revocation lists |

## Schemas

- [`tenant.lifecycle.v1.json`](tenant.lifecycle.v1.json)
