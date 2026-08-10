# Release notes

## 0.2.0

EV-30 closes two Python composition-path verification bypasses.

This is a breaking SDK release. The namespace-free
`sdk_python.evidence.chain.verify_stream` and `verify_streams` functions were
removed. Callers must use `verify_evidence_stream` or
`verify_evidence_streams` and supply `verification_keys` whose values expose
both `namespace` and `public_key`. There is intentionally no compatibility
alias: retaining one would retain the SE-003 bypass.

`services.ingestion.receipts.verify_canonical_evidence_record` now dispatches
on `record_type`. An `AttestationWindow` therefore requires a valid issuer
counter-signature under an issuer-namespace key; a customer signature alone is
no longer reported as a valid complete attestation record.
