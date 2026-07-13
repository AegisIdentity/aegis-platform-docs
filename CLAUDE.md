# aegis-platform-docs — working notes

Authoritative architecture + specs for the Aegis Identity Platform. No code.

- Source of truth: `architecture/ARCHITECTURE.md` (+ SERVICE-CATALOG, THREAT-MODEL, adr/).
- Diagrams are **draw.io** (`architecture/diagrams/*.drawio`) exported to PNG+PDF. Regenerate the
  exports after editing (command in README). Keep the `.drawio` source committed.
- When a service's contract changes, update SERVICE-CATALOG.md and add/supersede an ADR — do not
  edit an accepted ADR in place.
