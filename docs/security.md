# Security

**Version:** 0.1 draft
**Repo location:** `docs/security.md`
**Audience:** internal engineering; design partners' security reviewers. **Written to be shared** — this document is sales collateral as much as an internal spec.
**Depends on:** `threat-model.md`, `evidence-spec.md`, `architecture.md`

---

## 0. Framing

The security posture of this system is unusual in one respect: **a substantial part of it exists to protect relying parties from our own customers, and a further part to protect customers from us.** Conventional confidentiality and availability controls matter, but they are not what makes this product trustworthy. Requirements below are ordered accordingly.

Requirements carry IDs `SE-nnn`. Each maps to a threat in `threat-model.md`.

---

## 1. Record origin and signatures

**SE-001** — A record is authenticated by the party whose observation or conclusion it states. Customer observations and declarations are signed by the customer's `evidence` key. Hosted observations are signed by the service's `issuer` key. We do not hold the customer key in the default configuration; that is what permits the claim *we cannot modify your evidence*. The inverse matters just as much: a customer key cannot authenticate a denominator or confirmation that the hosted service claims to have retrieved independently.

**SE-002** — Issuer conclusions are issuer-authenticated. An `AttestationWindow` retains the two-signature form: the customer proof authenticates the evidence-shaped record and the issuer counter-signature authenticates the conclusion and methodology. A `RevocationRecord`, which has no customer-authored conclusion to preserve, carries an issuer primary signature.

**SE-003** — The roles are structurally distinct: different key namespaces, different custody, and different rotation lifecycles. Namespace is dispatched from the record type under ES-033, never selected by the caller. A design in which one key can satisfy both roles, or in which a caller can choose the role after seeing the signature, is non-conformant.

An ingestion receipt, a `PopulationRecord`, and an `ExternalConfirmation` are all instances of the same security category: an observation made by hosted infrastructure. A receipt proves that the service received a particular customer artifact. A population or confirmation signature proves that the service performed the corresponding connector observation. Substituting the first for the second would prove only that the customer supplied its chosen denominator — the customer marking its own homework.

Deployment location does not change record origin. Under P2 and P3 a connector may execute in customer-controlled infrastructure, but a `PopulationRecord` or `ExternalConfirmation` remains an issuer claim. Those profiles therefore require a narrowly usable issuer signing capability reachable by the connector-side observation producer. If that capability is unavailable, the observation is unavailable; it MUST NOT be relabelled as customer evidence or signed with an `evidence` key.

### 1.1 The honest limit

**SE-004** — This model prevents forgery. It does not prevent **withholding**. We could decline to issue, or fail to surface an inconvenient bundle. Mitigations: customers retain their own copy of every record they sign; the verifier runs fully offline; population records reference destination queries the customer can independently re-execute. Under deployment profile P2/P3 the residual disappears because we never hold the ledger.

This limit is stated in `evidence-spec.md` §7, `threat-model.md` §4.12, and here. It is stated three times deliberately — a reviewer who finds it disclosed in the security document trusts the rest of the document more, not less.

---

## 2. Key management

**SE-005** — Ed25519 throughout. One signing key per (tenant, deployment, collector instance). Keys are never shared across tenants or across deployments within a tenant.

**SE-006** — Custody options, recorded in the boundary and visible to relying parties:

| Option | Custody | Assurance label | Profiles |
|---|---|---|---|
| **Client-held** | Customer generates and holds; we never see the private key | Highest | All |
| **Hosted KMS** | We hold in a KMS the customer can audit; we can sign on their behalf | Reduced — disclosed on the attestation | P1 only |

**SE-007** — Hosted KMS custody MUST be disclosed on every attestation produced under it, because it materially weakens SE-001. A relying party is entitled to know that the party computing the coverage also controls the signing key.

**SE-008** — Rotation requires an in-stream `KeyContinuity` assertion: the new public key signed by the old (ES-024). Rotation without continuity is a chain break, terminating the window rather than silently continuing.

**SE-009** — Key compromise procedure: revoke from the point of suspected compromise; all attestations covering windows after that point are revoked; a superseding attestation may be issued for the pre-compromise portion only. Compromise never retroactively validates.

**SE-010** — Public keys are published in a tenant keyring retrievable by relying parties independently of the attestation bundle, so an offline verifier can be pre-seeded.

---

## 3. Tenant isolation

**SE-011** — Isolation is cryptographic and structural, not filtered. Distinct key namespaces per tenant; partitioning such that a cross-tenant read is not expressible in the query layer rather than being excluded by a `WHERE` clause.

**SE-012** — The ledger role holds `INSERT` and `SELECT` only. `UPDATE` and `DELETE` are not granted to any application role. Schema migrations that would require them go through a separately credentialed, logged path (§6).

**SE-013** — Every cross-tenant administrative operation is logged with operator identity, justification, and affected tenant, and is surfaced to the affected tenant.

---

## 4. Content minimisation

The system sees action parameters, which may contain personal data, financial detail, or business logic.

**SE-014** — Digest-by-default. Cleartext capture is per-action-family configuration, recorded in the boundary, and visible to relying parties.

**SE-015** — Fields that MUST NEVER be captured in cleartext regardless of configuration: authentication credentials, payment instrument numbers, government identifiers, and any field the customer marks `never_capture`.

**SE-016** — Selective disclosure: a relying party can verify a claim from digests without receiving cleartext, with content disclosed separately if and when the customer chooses.

**SE-017** — Retention is configurable per tenant with a floor of the attestation validity period plus the dispute window. Evidence supporting a live attestation cannot be deleted while that attestation is valid — deletion requires revocation first.

---

## 5. Authentication and authorisation

**SE-018** — Collector authentication uses per-instance credentials bound to a declared collector identity. A collector's records carry its identity and version; records from an unregistered collector are rejected rather than quarantined.

**SE-019** — Admin API access is role-separated: boundary management, qualification management, attestation issuance, and revocation are distinct permissions. **SE-020** — Issuance and revocation MUST be separable from engineering roles, so that an engineer with production access cannot unilaterally issue an attestation.

**SE-021** — Buyer verification links are scoped, time-bound, and grant access only to the attestation and the evidence explicitly included in its bundle — never to the tenant's wider ledger.

---

## 6. Operational security

**SE-022** — Production access is logged, justified, and reviewable by the affected tenant on request. We should assume a design partner's security team will ask for this and design for the answer being "yes, here it is."

**SE-023** — Secrets in the deployment pipeline follow the DamDam pattern: environment-scoped, never in the repository, with graceful failure on missing secrets rather than silent degradation.

**SE-024** — Any schema migration touching the evidence table is a two-person operation with a recorded rationale, and the pre- and post-migration chain state is verified by the independent verifier as part of the migration.

---

## 7. Per-profile differences

Key custody and network topology genuinely differ; this table is the honest version rather than a claim of uniformity.

| Control | P1 Hosted | P2 VPC | P3 Sidecar |
|---|---|---|---|
| Private key visibility to us | None (client-held) or full (hosted KMS) | None | None |
| Ledger readable by us | Yes | No | No |
| Withholding residual (TM-015) | Present | Eliminated | Eliminated |
| Destination credentials held by | Us | Customer | Customer |
| Blast radius of our compromise | Multi-tenant | Single tenant metadata | Single tenant metadata |
| Customer's operational burden | Minimal | Moderate | High |

**SE-025** — The deployment profile is recorded on the attestation, because it changes the threat analysis a relying party should apply.

---

## 8. Acceptance criteria

### SE-S-001 — Issuer cannot sign evidence records *(SE-003)*

```gherkin
Given the issuer counter-signing key
When an attempt is made to sign an evidence record with it
Then the record is rejected at ingestion
And the rejection reason is "key namespace mismatch"
```

### SE-S-002 — Hosted custody disclosed *(SE-007)*

```gherkin
Given a tenant using hosted KMS custody
When an attestation is issued
Then the attestation states that signing keys are held by the issuer
And the assurance label reflects the reduced custody
```

### SE-S-003 — Cross-tenant read not expressible *(SE-011)*

```gherkin
Given a query attempting to read records across two tenants
When it is executed under any application role
Then it fails at the database layer
And the failure does not depend on an application-layer filter
```

### SE-S-004 — Evidence deletion blocked while attestation valid *(SE-017)*

```gherkin
Given a valid attestation covering window W
When deletion of evidence within W is requested
Then deletion is refused
And the refusal states that the covering attestation must be revoked first
```

### SE-S-005 — Never-capture fields excluded regardless of config *(SE-015)*

```gherkin
Given an action family configured for full cleartext parameter capture
And a parameter matching a never-capture classification
When the record is emitted
Then that parameter appears only as a digest
And the record notes a never-capture exclusion was applied
```

### SE-S-006 — Unregistered collector rejected *(SE-018)*

```gherkin
Given records signed by a collector identity not in the boundary
When they are submitted to ingestion
Then they are rejected
And they do not enter the ledger in any state
```

### SE-S-007 — Compromise does not retroactively validate *(SE-009)*

```gherkin
Given a key compromise suspected from time T
When revocation is processed
Then all attestations covering windows after T are revoked
And any superseding attestation covers only the period before T
```

### SE-S-008 — Deployment location cannot change observation origin *(SE-001, SE-003)*

```gherkin
Given a P2 connector that can reach a customer evidence key but not an issuer key
When it attempts to produce a PopulationRecord or ExternalConfirmation
Then no issuer observation is emitted
And the evidence key is not accepted as a fallback signer
```

---

## 9. Input needed

| Question | Recommendation |
|---|---|
| Default key custody at MVP | **Client-held.** Hosted KMS as an explicit downgrade, disclosed. Costs onboarding friction, buys the central claim |
| Promote P2 (VPC) from V1 to MVP? | Depends on whether the first design partner is European. P2 eliminates the withholding residual entirely, which is the strongest available answer to the hardest question a reviewer will ask |
| Penetration test timing | Before the first production deployment, not before the first design partner. Budget ~$8-15K |
| Bug bounty | Not at MVP. Reconsider once the spec is public |

## Verification classifications

> **Verification for SE-001 — scenario-bearing; ES-S-019, SE-S-008.** The complete-record verifiers dispatch issuer observations by origin, and deployment without issuer custody is proved to have no evidence-key fallback.

> **Verification for SE-002 — scenario-bearing; ES-S-019.** The same complete-record entry points accept the two-proof `AttestationWindow` and refuse it when the issuer proof is removed.

> **Verification for SE-003 — scenario-bearing; SE-S-001, ES-S-019, SE-S-008.** Namespace substitution is refused for customer evidence, issuer observations, and deployment-profile fallback.

> **Verification for SE-004 — scenario-bearing; deferred EV-37.** This is externally observable runtime behaviour; EV-37 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for SE-005 — scenario-bearing; deferred EV-37.** This is externally observable runtime behaviour; EV-37 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for SE-006 — scenario-bearing; deferred EV-37.** This is externally observable runtime behaviour; EV-37 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for SE-008 — scenario-bearing; deferred EV-37.** This is externally observable runtime behaviour; EV-37 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for SE-010 — scenario-bearing; deferred EV-37.** This is externally observable runtime behaviour; EV-37 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for SE-012 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_structural_requirements.py::test_se_012_application_roles_cannot_update_or_delete_evidence` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for SE-013 — scenario-bearing; deferred EV-37.** This is externally observable runtime behaviour; EV-37 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for SE-014 — scenario-bearing; deferred EV-37.** This is externally observable runtime behaviour; EV-37 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for SE-016 — scenario-bearing; deferred EV-37.** This is externally observable runtime behaviour; EV-37 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for SE-019 — otherwise-verified.** `pytest:tests/traceability/test_admin_rbac_controls.py::test_se_019_admin_permissions_are_four_distinct_capabilities` — This requirement is verified by a structural API-routing check rather than a Gherkin product scenario.

> **Verification for SE-020 — otherwise-verified.** `pytest:tests/traceability/test_admin_rbac_controls.py::test_se_020_engineering_role_cannot_issue_or_revoke` — This requirement is verified by an adversarial API authorization check rather than a Gherkin product scenario.

> **Verification for SE-021 — scenario-bearing; deferred EV-37.** This is externally observable runtime behaviour; EV-37 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for SE-022 — scenario-bearing; deferred EV-37.** This is externally observable runtime behaviour; EV-37 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for SE-023 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_ci_controls.py::test_se_023_secrets_are_environment_scoped_absent_from_repo_and_fail_closed` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for SE-024 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_ci_controls.py::test_se_024_evidence_migrations_require_two_approvals_rationale_and_chain_checks` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for SE-025 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.
