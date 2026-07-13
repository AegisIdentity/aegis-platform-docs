# aegis-platform-docs

Authoritative architecture & specification repository for the **Aegis Identity Platform** — a
multi-tenant, SaaS, Okta-class identity provider built on Spring Boot 4.1 / Spring Security 7,
Java 21, PostgreSQL, Redis, Kafka, and Kubernetes.

## Contents
| Path | What |
|---|---|
| [`architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md) | Main architecture spec — scope, service decomposition, data, multi-tenancy, auth mechanisms, deployment. **Start here.** |
| [`architecture/SERVICE-CATALOG.md`](architecture/SERVICE-CATALOG.md) | Per-service contract: responsibility, endpoints, datastore, maturity. |
| [`architecture/THREAT-MODEL.md`](architecture/THREAT-MODEL.md) | STRIDE threat model + OWASP/CVE watch-list + CI assurance. |
| [`architecture/adr/`](architecture/adr/) | Architecture Decision Records (ADR-0001…). |
| [`architecture/diagrams/`](architecture/diagrams/) | draw.io diagrams — editable `.drawio` source + exported **PNG** and **PDF** (system context, auth flow, deployment). |
| [`api/`](api/) | OpenAPI specs + event schemas per service (contract-first). |

## The repositories (polyrepo)
| Repo | Role | Maturity |
|---|---|---|
| `aegis-platform-docs` | this repo — specs, ADRs, contracts | — |
| `aegis-platform-bom` | Maven parent POM + dependency BOM | built |
| `aegis-platform-commons` | shared libraries (security, tenant, web, audit, testing) | built |
| `aegis-authorization-server` | OIDC/OAuth2/M2M core + login | core |
| `aegis-tenant-service` | orgs/tenants/domains/config | core |
| `aegis-identity-service` | users/credentials/groups | core |
| `aegis-edge-gateway` | routing, tenant resolution, rate limit | functional |
| `aegis-mfa-webauthn-service` | passkeys / TOTP / step-up MFA | scaffold |
| `aegis-saml-idp-service` | custom SAML 2.0 IdP (OpenSAML 5) | scaffold |
| `aegis-social-broker-service` | social + inbound SAML/OIDC federation | scaffold |
| `aegis-scim-provisioning-service` | SCIM 2.0 in/outbound | scaffold |
| `aegis-admin-api-service` | admin/console API, policy, RBAC | scaffold |
| `aegis-platform-infra` | docker-compose, Terraform (AWS/Azure), Helm, CI | infra |

## Diagrams
Authored as native, editable **draw.io** files and exported to PNG + PDF (the exports embed the
editable XML, so they reopen in draw.io). Regenerate after editing a `.drawio`:
`/Applications/draw.io.app/Contents/MacOS/draw.io -x -f png -e -b 10 --scale 2 -o <name>.drawio.png <name>.drawio`

| Diagram | View |
|---|---|
| System context & service decomposition | [PNG](architecture/diagrams/system-context.drawio.png) · [PDF](architecture/diagrams/system-context.drawio.pdf) · [source](architecture/diagrams/system-context.drawio) |
| authorization_code + PKCE flow | [PNG](architecture/diagrams/authcode-pkce-flow.drawio.png) · [PDF](architecture/diagrams/authcode-pkce-flow.drawio.pdf) · [source](architecture/diagrams/authcode-pkce-flow.drawio) |
| Deployment topology (AWS/Azure) | [PNG](architecture/diagrams/deployment-topology.drawio.png) · [PDF](architecture/diagrams/deployment-topology.drawio.pdf) · [source](architecture/diagrams/deployment-topology.drawio) |

## Conventions
- **Group id:** `io.aegis` · **Java root package:** `io.aegis.<service>` · **Artifact prefix:**
  `aegis-`. Brand is a placeholder — renameable via these three anchors.
- **Ports:** gateway 8080; authorization-server 9000; services 9101–9107 (see catalog).
- **Every non-gateway service** is an OAuth2 resource server for its management API and applies the
  shared hardening baseline from `aegis-platform-commons:security-commons`.
