# Aegis Threat Model (STRIDE summary)

A security platform is itself the highest-value target. This is a living STRIDE-based summary of the
principal threats and the controls that address them. It is a *starting* threat model to be deepened
per service and re-reviewed each release — not a one-time checkbox. It does **not** claim to
enumerate every possible attack; residual risk is tracked, not denied.

## Trust boundaries
1. **Internet ↔ edge-gateway** — untrusted clients. TLS 1.3, WAF, rate limit, request validation.
2. **edge-gateway ↔ services** — semi-trusted mesh. mTLS peer auth + token scopes.
3. **service ↔ its database** — trusted, network-isolated (NetworkPolicy: only owner reaches DB).
4. **service ↔ KMS/secret store** — trusted, IAM/workload-identity gated.
5. **tenant ↔ tenant** — a logical boundary *inside* shared services; a cross-tenant leak is Sev-1.

## STRIDE

### Spoofing (identity)
- *Threat:* forged tokens, replayed assertions, stolen credentials, tenant-header spoofing.
- *Controls:* asymmetric-signed JWTs with per-tenant `kid`; SAML assertion signature verification +
  audience/recipient/`NotOnOrAfter` checks; WebAuthn origin/rpId binding + sign-counter; Argon2id
  password hashing + lockout; `X-Aegis-Tenant` only honoured behind verified mTLS peer identity;
  PKCE mandatory; refresh-token rotation with reuse-detection.

### Tampering (data/messages)
- *Threat:* modified tokens/assertions, SAML signature-wrapping, request smuggling, poisoned events.
- *Controls:* signature verification on all tokens/assertions; **XXE disabled + signature-wrapping
  hardened OpenSAML config**; strict content-type/size validation at edge; immutable append-only
  audit log; Kafka message schemas validated on consume.

### Repudiation
- *Threat:* "I never logged in / never authorized that app / never changed that policy."
- *Controls:* every auth decision emits a signed audit event (`auth.*`, `authz.*`, admin `*.changed`)
  to an append-only store streamed to customer SIEM (Okta System Log analogue); correlation ids
  thread the whole request.

### Information disclosure
- *Threat:* cross-tenant data leak, secret/key exposure, token/PII in logs, verbose errors, JWKS
  private-key leak.
- *Controls:* tenant predicate enforced in the repository layer (app code cannot query without it) +
  optional Postgres RLS; secrets only from KMS/Key Vault, never in git/env-in-image; **PII/secret
  redaction in structured logging** (no tokens, passwords, or full assertions logged); generic error
  bodies (no stack traces to clients); private keys wrapped by KMS, never serialized; Actuator locked
  to `health` publicly, everything else role-gated on an internal port.

### Denial of service
- *Threat:* credential-stuffing/brute force, token-endpoint flooding, SAML/XML decompression bombs,
  algorithmic complexity on crypto.
- *Controls:* Redis distributed rate limiting at edge and on password/OTP endpoints; account lockout;
  DEFLATE-bomb size caps in SAML; HPA autoscaling + pod resource limits; bounded Argon2 cost;
  connection/request timeouts; circuit breakers on inter-service calls.

### Elevation of privilege
- *Threat:* scope escalation, tenant escape, admin-API abuse, method-security bypass, insecure
  deserialization.
- *Controls:* default-deny filter chains (`anyRequest().authenticated()`); least-privilege scopes +
  audience-restricted tokens; method security (`@PreAuthorize`) with **negative tests**; per-tenant
  signing keys make cross-tenant token forgery cryptographically infeasible; admin RBAC separate from
  end-user roles; no Java deserialization of untrusted input; dependency-CVE gate in CI.

## OWASP / known-CVE watch-list (verify current patch level each release)
- OAuth/OIDC: open-redirect via `request_uri`/redirect handling, mix-up attacks, PKCE downgrade.
- SAML: DEFLATE decompression bombs, XXE, XML signature wrapping, comment-truncation of NameID.
- Spring Security: pinned to the **latest patch of its minor line**; `spring.io/blog` "Spring
  Security releases" checked before each release cut.
- Cookie/session: open-redirect in request-cache, session fixation (session rotated on login).

## Continuous assurance (in CI, gating merge)
SAST (SpotBugs/PMD), dependency-CVE scan (OWASP Dependency-Check), secret scanning (gitleaks),
container image scan (Trivy), plus periodic DAST (ZAP baseline) against a running compose stack, and
scheduled external pen tests before GA. A red gate blocks merge.
