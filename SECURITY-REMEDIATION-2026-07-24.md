# Aegis Platform — Security Remediation Record

**Date:** 2026-07-24
**Companion to:** `SECURITY-REVIEW-2026-07-24.md` (the original findings)
**Scope:** Every finding (High, Medium, Low) was remediated, each repo re-validated by build/test, and the fixes were then re-audited by an independent verification pass that read the changed code (not the fix claims) and hunted for regressions.

---

## Outcome

- **12 High → all FIXED and verified**, including the two release-blocker fail-open seeders.
- **23 Medium → FIXED**, except three that are implemented-but-off-by-default (documented as prod-config gates, below) and one refined (MSK IRSA).
- **~20 Low → FIXED**, except a handful accepted-as-designed (documented).
- **5 issues introduced by the fixes were caught by the verification pass and closed** in a cleanup round (dev-key fail-open, compose dev profile, onboarding timing oracle, Docker digest pins, EKS NetworkPolicy enforcement).

Validation totals (all green): authorization-server 55, identity-service 31, gateway 13, tenant 15, saml 2, mfa 47, scim 15, social 13, admin 15, commons 55; admin-console `npm run build`; terraform `fmt`+`validate`; `docker compose config`; helm `template`/`lint`; every pinned GitHub Action SHA confirmed real via `git ls-remote`.

---

## High — all fixed & verified

| ID | Fix | Verified evidence |
|---|---|---|
| H1 | `devClientSeeder` now `@Profile("dev")`; `{noop}dev-only-change-me` removed; M2M/SCIM secrets injected with no default | grep confirms literal gone from source; seeder dev-gated |
| H2 | `DevDataSeeder` `@Profile("dev")` + `matchIfMissing=false` (opt-in) | fail-closed; stage/prod seed nothing |
| H3 | `getBySlug`/`resolve` derive caller tenant from JWT, 404 cross-tenant unless `tenant:platform-admin` | negative tests: intruder → 404, owner → 200 |
| H4 | `POST /tenants` gated by distinct `tenant:platform-admin` scope | test: `tenant:admin` → 403, `platform-admin` → 201 |
| H5 | TOTP `secretBase32` AES-256-GCM encrypted (random IV, `v1:` prefix) | real GCM; key fail-fast outside dev (see cleanup #1) |
| H6 | Per-(tenant,subject) TOTP lockout, 5 failures → exponential backoff | wired into validate path |
| H7 | `@Scheduled` challenge sweep + `@EnableScheduling` | scheduling confirmed enabled |
| H8 | All 8 Terraform state backends enabled (real `s3`/`azurerm` blocks) | both prod roots `init`+`validate` clean |
| H9 | `admin_group_object_ids` required + hardened-profile validation | plan fails when unset for hardened |
| H10 | `trivy-action` pinned `@915b19bb…` (v0.28.0) | `git ls-remote` confirms SHA==tag |
| H11 | Console tokens → `InMemoryWebStorage` (not localStorage) | no `WebStorageStateStore(localStorage)` remains |
| H12 | nginx security headers moved to `include` in every location block | headers no longer dropped on SPA shell |

## Medium — fixed, with three explicit prod-config gates

FIXED and verified: M-core-1/3/4/5/6, M-edge-2/5, M-svc-1/2/3/4/5, M-infra-2/4/5/6/7, M-console-1/2, M-commons-1. Highlights: WebAuthn user-verification now tenant-driven and counter-regression **rejected**; `tenant:admin`→SUPER_ADMIN now **default-off + audited**; SCIM tokens gain expiry + rotation-with-grace + `MessageDigest.isEqual`; compose data stores bound to `127.0.0.1`; audit modules (CloudTrail/GuardDuty/Config; Azure Defender/diagnostics) real and hardened-wired; unprivileged nginx with `runAsNonRoot`+`readOnlyRootFilesystem`.

**Implemented but OFF by default — activate in prod (not code gaps, deployment gates):**
- **M-edge-1 (JWT `aud` validation)** — validator present; no-op until `AEGIS_JWT_AUDIENCE` is set. (Also L-core-3.) Deferred intentionally: the AS does not yet stamp a per-service `aud`, so enabling it now would reject the live login-path token. Enable once the AS mints per-service audiences.
- **M-edge-3 (edge rate limiting)** — Redis `RequestRateLimiter` on credential routes; active only when `aegis.ratelimit.enabled=true`. KeyResolver verified non-spoofable.
- **M-edge-4 (Host allowlist)** — rejects unknown hosts with 404 when `AEGIS_ALLOWED_HOSTS` is set; **allow-all when empty**. Set the allowlist in prod or the forged-Host/issuer-spoofing threat stays unmitigated.

**Refined:**
- **M-infra-2 (MSK IRSA)** — wildcard `"*"` service-account trust removed; now an explicit 7-service allowlist (excludes admin-console/gateway/saml, closing the nginx-assumes-role attack). Residual: the 7 still share one role with `/*` topic/group scope — full per-service least-privilege remains a follow-up.
- **M-infra-3 (NetworkPolicy egress)** — chart now emits `[Ingress, Egress]` with DNS-only default. Was enforced only on Azure (Calico); **cleanup #5 enabled VPC CNI NetworkPolicy on the EKS module** so it is now enforced on AWS too. Operational note: `networkPolicy.egressTo` defaults to DNS-only — populate per-service data-tier/sibling egress or connectivity is denied at deploy.

## Low — fixed, with accepted-as-designed exceptions

FIXED: L-core-1/2/6, L-edge-2, L-svc-4/5, L-commons-1/2/3/4, L-console-1, L-infra-1/4(partial)/6, BOM gate (CVSS 7→4 + active `security-scan` profile). All 9 service Docker base images digest-pinned to `eclipse-temurin:21-jre@sha256:273396ed…ffd3`.

Accepted-as-designed (documented, not silently shipped): L-core-4 (broad-scope SPA client now dev-only + TODO to role-gate), L-core-5 / L-edge-4 (wildcard CORS safe while `allowCredentials=false`), L-edge-1 / L-infra-3 (dev-default DB/SCIM secrets, env-overridable + profile-gated), L-infra-2 (npm audit non-blocking — Trivy is the blocking backstop; ratchet TODO), L-infra-5 (cluster-creator-admin acceptable for bootstrap; break-glass documented).

---

## Issues introduced by the fixes, caught in verification and closed

1. **Encryption dev-key fail-open (MFA + social)** — the AES key fell back to a jar-baked dev key unless a prod flag was set. Re-gated so the dev key is used **only** under an explicit `dev` profile; every other case fails fast. New unit tests assert no-profile startup throws instead of using the public key. (MFA 47, social 13 tests green.)
2. **Compose dev-ergonomics break** — gating seeders/secrets/`ddl-auto` behind the `dev` profile would have made the local stack fail-fast. Added `SPRING_PROFILES_ACTIVE=dev` to all 8 Spring services + `ALLOW_INSECURE_HTTP` to the console build; `docker compose config` validates.
3. **M-core-2 residual timing oracle** — onboarding closed the status/body oracle but the existing-org path skipped Argon2, leaking existence by timing. Equalized with a dummy-hash on the duplicate path (mirrors M-core-1). Identity-service 7+24 tests green.
4. **Docker digest pins** — 7 Dockerfiles still floated after the first pass; resolved the live multi-arch digest and pinned all.
5. **EKS NetworkPolicy inert on AWS** — enabled VPC CNI `enableNetworkPolicy` in the EKS module so the egress policy is enforced on AWS, not just Azure. `terraform validate` Success.

## Residual (accepted / defense-in-depth, not blockers)

- Console CSP `connect-src` ships placeholder origins (fail-**closed**; console won't call APIs until real origins set — consider a build-time guard).
- Auth-failure audit hashes the actor unsalted+truncated (keeps cleartext passwords out of logs; a keyed HMAC would resist offline cracking).
- MFA lockout is per-instance (move to Redis for multi-replica global lockout).
- Existing plaintext TOTP/IdP-secret rows stay plaintext until re-saved — needs a one-time backfill.

## Operator action items (require live cloud resources / cross-repo)

1. **H8** — bootstrap the S3 bucket + DynamoDB lock table (AWS) and storage account + container (Azure); `init -backend-config`; make backend-enabled a hard CI gate.
2. **H9** — set real Entra ID group object IDs for stage/prod (`TF_VAR_admin_group_object_ids`).
3. **M-infra-1** — replace `203.0.113.0/24` placeholder with real office/VPN CIDRs before EKS apply.
4. **M-edge-1/3/4** — set `AEGIS_JWT_AUDIENCE`, `aegis.ratelimit.enabled=true` (+ Redis), and `AEGIS_ALLOWED_HOSTS` in prod to activate those controls.
5. **M-infra-3** — populate `networkPolicy.egressTo` per service, or all non-DNS egress is denied.
6. **M-infra-7** — deploy Kyverno / sigstore policy-controller so cosign signatures are actually verified at admission.
7. **Data migration** — re-save existing `TotpCredential` / `IdentityProvider` rows to encrypt legacy plaintext.
8. **tenant-service / others** — add Flyway/Liquibase; `ddl-auto: validate` now fails against an empty prod schema (intended fail-safe).
9. **CVE scan** — run `mvn -Psecurity-scan verify` / OWASP Dependency-Check in CI against the resolved build (parent POM is `aegis-platform-bom`).
