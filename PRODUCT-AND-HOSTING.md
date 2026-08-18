# Aegis — market differentiation & hosting-as-a-service plan

Two questions the user asked: **what would make this unique in the market**, and **how to host it as
a service**. This document answers both. It is a plan and an operator action list — the actual
hosting requires live cloud accounts and credentials that are not available in this environment, so
nothing here has been deployed. Where a step needs a human with cloud access, it says so.

---

## Part 1 — Where Aegis sits, and how it could be different

### The incumbents, honestly

| Product | Shape | Aegis's realistic relationship to it |
|---|---|---|
| **Okta / Auth0** | The market leader; enormous breadth, closed SaaS, per-MAU pricing that punishes growth. | Aegis is architecturally the same class (the ARCHITECTURE doc explicitly benchmarks Okta), far less broad. Not a feature-parity play. |
| **Microsoft Entra ID** | Default for M365 shops; deep MS integration, opaque, hard to leave. | Different buyer. Aegis competes where "not locked to Microsoft" is a feature. |
| **Keycloak** | Open-source, self-host, huge install base; operationally heavy, single-realm scaling pain, Java monolith. | **This is the real competitive frame.** Aegis's polyrepo, database-per-service, per-tenant-key design is a direct answer to Keycloak's operational weak points. |
| **AWS Cognito / GCP Identity Platform** | Cloud-native, cheap, but thin on enterprise IAM (weak admin, weak federation UX). | Aegis competes on being cloud-agnostic and enterprise-featured. |

**Honest positioning:** Aegis is not going to out-feature Okta. Its credible wedge is **"Keycloak's
openness with a SaaS operational model, genuinely multi-cloud, with tenant isolation as a hard
security boundary rather than a realm convention."**

### Differentiators that are defensible (and already partly built)

These lean on choices the codebase *already made*, which is what makes them credible rather than
marketing:

1. **Per-tenant cryptographic isolation as the default, not a tier.** Every tenant gets its own
   signing key (`kid`), so a token minted for tenant A is cryptographically un-forgeable for B —
   verified under active attack in the pen test. Keycloak realms share a lot more. Aegis can also
   pin a premium tenant to a dedicated schema/instance *with no application change* (the datasource
   is resolved per tenant). **Moat:** "a cross-tenant leak is a Sev-1, and here's the crypto that
   makes it infeasible" is a security-buyer message competitors can't easily match without
   re-architecting.

2. **Bring-your-own-cloud / data residency by construction.** Database-per-service + Terraform
   modules for both AWS and Azure means a tenant's data can be pinned to a region or even a
   customer-owned account. For regulated buyers (EU data residency, healthcare, gov) this is a
   line-item competitors charge a fortune for or can't do at all.

3. **Standards-first, no proprietary lock-in.** OIDC/OAuth 2.1 (no implicit, no ROPC), SAML, SCIM,
   WebAuthn. Migration *in* from Okta/Auth0 is a supported story, not a fight. **Moat:** low switching
   cost is itself the pitch to anyone currently feeling Okta's renewal.

4. **Transparent, event-sourced audit as a product.** The `AuditEventPublisher` seam → Kafka → SIEM
   design (once built) is the Okta System Log analogue, but streamed to the customer's own SIEM by
   default rather than trapped behind a UI. Security teams pay for this.

5. **Passkey-first / passwordless as the default flow, not an add-on.** WebAuthn is already a
   first-class primary factor here. Positioning the whole platform as "passwordless by default,
   passwords as legacy" is a forward-looking wedge as the market moves that way.

### New capabilities that would sharpen the wedge (ranked by leverage)

- **Migration tooling from Okta/Auth0/Cognito** — a one-command importer for users (bcrypt hashes
  with upgrade-on-login — already designed in §6.1), clients, and IdP configs. Nothing sells an
  identity platform like "you can leave your current one in an afternoon."
- **Adaptive / risk-based auth** (ARCHITECTURE §1.2 lists it out-of-scope-for-now) — impossible-travel,
  new-device, IP reputation feeding the MFA step-up decision. The step-up orchestration hook already
  exists; this is a risk-signal input to it.
- **Fine-grained authorization (ReBAC / policy-as-data)** — a Zanzibar-style relationship model as a
  service, competing with Auth0 FGA / SpiceDB. The `admin-api` RBAC is the seed; this is the biggest
  net-new product surface.
- **Self-service tenant onboarding with instant custom domains** — the DNS-verified custom-domain
  flow and the gateway host→tenant resolution built this session are the foundation. "Sign up, verify
  your domain, live in minutes" is a PLG motion the enterprise incumbents don't offer.
- **Developer experience as a differentiator** — the in-console docs hub with per-language code
  samples already exists. Lean into it: local-first (`docker compose up` gives a working OIDC
  provider — once the F1/F6 fixes ship it actually does), great SDKs, honest docs.

---

## Part 2 — Hosting Aegis as a SaaS

### What "hosting" requires that this session cannot do

Actually hosting the platform needs: a cloud account, Terraform state backends bootstrapped, real
secrets in a secret manager, DNS, TLS certificates, and a container registry. None of those exist
here. The infra code is present and (per its own notes) `terraform validate`-clean, but `plan`/`apply`
needs credentials. So this section is the **runbook + action list** for the humans who have them.

### Deployment architecture (already coded, needs credentials)

`aegis-platform-infra` ships: cloud-agnostic Terraform modules with thin `aws/` (EKS, RDS/Aurora,
ElastiCache, MSK, Secrets Manager+KMS, S3, ALB/ACM, IRSA) and `azure/` (AKS, PG Flexible Server,
Azure Cache, Event Hubs, Key Vault, App Gateway, Workload Identity) roots; per-service Helm chart;
CI with build → test → SAST → CVE scan → Trivy image scan.

### Hard prerequisites before any stage/prod apply (from the security review + this session)

These are release blockers — the platform is designed to fail closed on each, so skipping them means
"won't start" rather than "insecure and running":

1. **Terraform remote state** — bootstrap the S3 bucket + DynamoDB lock table (AWS) and storage
   account + container (Azure); `init -backend-config`. Make backend-enabled a hard CI gate. *(H8)*
2. **Secrets in the secret manager, none in git** — for the authorization-server specifically:
   `POSTGRES_PASSWORD`, `SPRING_DATA_REDIS_PASSWORD`, and **`AEGIS_FIELD_ENC_KEY`** (the AES key that
   protects tenant signing keys at rest — the service will not start without it outside dev, by
   design). Back up and rotation-plan the field key: losing it makes every tenant key undecryptable.
3. **Authorization-server runs multi-replica correctly now** — deploy with
   `values-authorization-server.yaml` (created this session): `replicaCount: 2` is safe because
   signing keys are in Postgres and session + interaction codes are in Redis. **But it REQUIRES a
   reachable Redis** (`SPRING_DATA_REDIS_HOST/_PORT/_PASSWORD`) — there is no in-memory fallback, on
   purpose. Without Redis it fails to start rather than silently running non-scalably.
4. **Turn on the controls that ship disabled** (pen test F2/F3/F8):
   - `AEGIS_ALLOWED_HOSTS` = real gateway hostnames + verified tenant domains (else issuer spoofing).
   - `AEGIS_RATELIMIT_ENABLED=true` + Redis (else credential brute force is unthrottled).
   - `AEGIS_JWT_AUDIENCE` **after** the AS is changed to stamp a per-service `aud` (roadmap item).
5. **Flyway is now the schema owner** for the six data services (this session) — `ddl-auto: validate`
   validates against the migration-built schema. Existing pre-Flyway databases are handled by
   `baseline-on-migrate=true`. The AS keeps its `spring.sql.init` scripts (Spring-shipped schemas).
6. **NetworkPolicy egress** — the chart default is DNS-only; populate `networkPolicy.egressTo` per
   service (data tier + siblings) or traffic is denied at deploy. *(M-infra-3)*
7. **Prod AKS Entra RBAC / EKS API CIDR** — set `admin_group_object_ids` (hardened profile requires
   it) and narrow the EKS public API CIDR from the placeholder. *(H9, M-infra-1)*
8. **Image signing / admission** — deploy Kyverno / sigstore policy-controller so the cosign
   signatures CI produces are actually verified at admission. *(M-infra-7)*

### The multi-tenant SaaS control plane (what to build beyond the deploy)

Deploying the services is not the same as running a SaaS. The product-level operational surface:

- **Tenant onboarding & lifecycle** — the pieces exist (`tenant-service` CRUD, DNS-verified custom
  domains, per-tenant key provisioning on `tenant.created`). Wire them into a signup → verify-domain →
  provision-key → seed-admin flow. Gate tenant *creation* behind the `tenant:platform-admin` scope
  (the H4 fix keeps regular tenant admins from minting top-level tenants).
- **Metering & billing** — meter on MAU / token-issuance / API calls from the audit event stream
  (another reason to build the Kafka backbone early). Aegis's differentiation opportunity: *not*
  Okta's punitive per-MAU model — consider per-tenant flat tiers + usage overage, which the
  event-sourced meter makes measurable.
- **SLOs / SLAs** — the token endpoint (`authorization-server`) and the gateway are the
  availability-critical path; the admin API is not. This is exactly why they are separate services
  (ARCHITECTURE §3.1) — set a high SLO on the token path, a relaxed one on admin. HPA is already
  configured (2→8).
- **DR** — database-per-service means per-service backup/restore. The one irreplaceable secret is the
  field-encryption key / KMS CMK; everything else can be rebuilt. Cross-region CMK replication is the
  DR keystone.
- **Compliance posture** — the threat model, default-deny authz, tenant isolation, and (once built)
  the streamed audit trail are the evidence base for SOC 2 / ISO 27001. The gaps a real auditor will
  hit first: no account-level detection (CloudTrail/GuardDuty/Config — M-infra-4, partially in the
  Terraform audit module), and the deferred mTLS. Sequence those into the compliance runway.

### Operator action list (the human-with-credentials checklist)

1. Bootstrap TF state backends (AWS + Azure); enable the backend blocks; make it a CI gate.
2. Put the real secrets in Secrets Manager / Key Vault, above all `AEGIS_FIELD_ENC_KEY` (backed up).
3. Provision managed Postgres + Redis (+ MSK/Event Hubs when the event backbone lands).
4. `terraform apply` per env root; set `admin_group_object_ids`, narrow the EKS API CIDR.
5. `helm install` per service; use `values-authorization-server.yaml` for the AS and set its Redis.
6. Populate `AEGIS_ALLOWED_HOSTS`, `AEGIS_RATELIMIT_ENABLED=true`, `networkPolicy.egressTo`.
7. Deploy Kyverno/policy-controller; verify cosign signatures at admission.
8. Point DNS + TLS (ALB/ACM or App Gateway/Key Vault certs) at the gateway; set the console's real
   CSP `connect-src` origins at build time.
9. Run the CVE scan (`mvn -Psecurity-scan verify` / OWASP Dependency-Check) against the resolved build
   in CI.
