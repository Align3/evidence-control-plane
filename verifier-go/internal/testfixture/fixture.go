// Package testfixture builds signed evidence records for tests.
//
// It is test scaffolding, not verifier code. It deliberately re-derives the
// signing input from evidence-spec.md §7 rather than calling anything in
// internal/evidence, so a fixture cannot agree with the verifier by sharing the
// bug: if the verifier's notion of the signing bytes drifts, these fixtures
// stop verifying instead of drifting with it.
//
// The seeds and key ids match tests/vectors/vectors-v0.1.json so a fixture and
// a normative vector can be compared directly.
package testfixture

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
)

// Key ids used throughout the fixtures, matching the published vectors.
const (
	EvidenceKeyID = "K1"
	IssuerKeyID   = "ISSUER1"

	// Seeds from tests/vectors/vectors-v0.1.json. Test material only.
	evidenceSeedB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	issuerSeedB64   = "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8"
)

// Keys carries the signing material and the keyring a verifier is given.
type Keys struct {
	Evidence ed25519.PrivateKey
	Issuer   ed25519.PrivateKey
	Keyring  map[string]evidence.RegisteredKey
}

// NewKeys builds the fixture keyring. The namespaces are stamped from the
// vector corpus rather than defaulted, because testing-qa §10 records that a
// harness supplying its own namespace is exactly how EV-30's divergence stayed
// invisible.
func NewKeys() (Keys, error) {
	evSeed, err := base64.RawURLEncoding.DecodeString(evidenceSeedB64)
	if err != nil {
		return Keys{}, err
	}
	isSeed, err := base64.RawURLEncoding.DecodeString(issuerSeedB64)
	if err != nil {
		return Keys{}, err
	}
	ev := ed25519.NewKeyFromSeed(evSeed)
	is := ed25519.NewKeyFromSeed(isSeed)
	return Keys{
		Evidence: ev,
		Issuer:   is,
		Keyring: map[string]evidence.RegisteredKey{
			EvidenceKeyID: {
				Namespace: evidence.NamespaceEvidence,
				PublicKey: ev.Public().(ed25519.PublicKey),
			},
			IssuerKeyID: {
				Namespace: evidence.NamespaceIssuer,
				PublicKey: is.Public().(ed25519.PublicKey),
			},
		},
	}, nil
}

// Envelope is an unsigned record as a plain map, so a test can mutate any
// member — including into shapes the writer would refuse to produce, which is
// the whole point of an adversarial fixture.
type Envelope map[string]any

// NewEnvelope builds a §3 envelope with the mandatory members present.
func NewEnvelope(recordType, recordID, tenant, stream string, body map[string]any) Envelope {
	return Envelope{
		"record_id":      recordID,
		"record_type":    recordType,
		"schema_version": "1.0.0",
		"tenant_id":      tenant,
		"boundary_ref":   "boundary-1",
		"stream_id":      stream,
		"sequence":       int64(1),
		"prev_digest":    nil,
		"source":         map[string]any{"collector": "testfixture", "version": "0.1.0"},
		"clocks":         map[string]any{"source_time": "2026-08-01T12:00:00.000+01:00"},
		"body":           body,
	}
}

// canonical renders a value to RFC 8785 canonical bytes.
//
// Deliberately not internal/jcs: these fixtures must not inherit the
// canonicaliser under test. encoding/json with sorted keys is JCS-equivalent
// for the ASCII-keyed, integer-valued fixtures here, and the fixtures assert
// their own canonicality through the verifier's wire check, which fails loudly
// if that ever stops being true.
func canonical(v any) ([]byte, error) {
	// json.Marshal sorts map keys by Go string comparison, which equals JCS's
	// UTF-16 code-unit order for the ASCII member names used here.
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + fmt.Sprintf("%x", sum)
}

// Sign attaches the ES-021 primary signature and returns the complete wire
// bytes. sig is the Ed25519 signature over the bare 32-byte digest of the
// signature-excluded canonical form.
func (e Envelope) Sign(keyID string, priv ed25519.PrivateKey) ([]byte, error) {
	unsigned := make(map[string]any, len(e))
	for k, v := range e {
		if k == "signature" {
			continue
		}
		unsigned[k] = v
	}
	signing, err := canonical(unsigned)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(signing)
	sig := ed25519.Sign(priv, sum[:])
	complete := make(map[string]any, len(unsigned)+1)
	for k, v := range unsigned {
		complete[k] = v
	}
	complete["signature"] = map[string]any{
		"alg":           "ed25519",
		"key_id":        keyID,
		"sig":           base64.RawURLEncoding.EncodeToString(sig),
		"signed_digest": digest(signing),
	}
	return canonical(complete)
}

// SignAttestation produces the two structurally distinct signatures ES-023
// requires: the customer's primary proof, then the issuer counter-signature
// over the record carrying it with signature.issuer excluded.
func (e Envelope) SignAttestation(keys Keys) ([]byte, error) {
	customerWire, err := e.Sign(EvidenceKeyID, keys.Evidence)
	if err != nil {
		return nil, err
	}
	var withCustomer map[string]any
	if err := json.Unmarshal(customerWire, &withCustomer); err != nil {
		return nil, err
	}
	// The counter-signature cannot commit to its own bytes, so it covers
	// everything else — customer signature included (ES-023).
	counterInput, err := canonical(withCustomer)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(counterInput)
	issuerSig := ed25519.Sign(keys.Issuer, sum[:])
	sigObj, _ := withCustomer["signature"].(map[string]any)
	sigObj["issuer"] = map[string]any{
		"alg":           "ed25519",
		"key_id":        IssuerKeyID,
		"sig":           base64.RawURLEncoding.EncodeToString(issuerSig),
		"signed_digest": digest(counterInput),
	}
	return canonical(withCustomer)
}

// Bundle assembles an ES-034 container: a JSON array of complete signed
// records, in the order given. The records keep the exact bytes they were
// signed as, so the array is canonical whenever its elements are.
func Bundle(records ...[]byte) ([]byte, error) {
	raws := make([]json.RawMessage, 0, len(records))
	for _, r := range records {
		if r == nil {
			continue
		}
		raws = append(raws, json.RawMessage(r))
	}
	return canonical(raws)
}

// AttestationBody returns a §5.13 AttestationWindow body with every mandatory
// member present, which callers then mutate.
func AttestationBody() map[string]any {
	return map[string]any{
		"boundary_ref":           "boundary-1",
		"window_start":           "2026-08-01T00:00:00.000+00:00",
		"window_end":             "2026-08-31T00:00:00.000+00:00",
		"methodology_version":    "1.0.0",
		"denominator_class":      "C1",
		"population_record_refs": []any{},
		"coverage_level":         "observed",
		"verification_status":    "self_computed",
		"coverage_ratio":         nil,
		"counts":                 map[string]any{},
		"gaps":                   []any{},
		"assertions":             []any{},
		"exclusions":             []any{},
		"relying_parties":        []any{},
		"validity_from":          "2026-09-01T00:00:00.000+00:00",
		"validity_until":         "2026-12-01T00:00:00.000+00:00",
		"liability_ref":          "terms-1",
		"issued_at":              "2026-09-01T00:00:00.000+00:00",
		"issuer":                 "issuer-1",
		"verifier_version":       "0.1.0",
	}
}

// BoundaryBody returns a §5.1 AssuranceBoundary body with every mandatory
// member present. qualificationRefs are the record ids of the
// QualificationRecords this boundary declares (ES-009).
func BoundaryBody(qualificationRefs ...string) map[string]any {
	refs := make([]any, 0, len(qualificationRefs))
	for _, ref := range qualificationRefs {
		refs = append(refs, ref)
	}
	return map[string]any{
		"boundary_version":    "1",
		"tenant":              "tenant-1",
		"deployment":          "prod",
		"agent_identities":    []any{},
		"action_families":     []any{"refund.issue"},
		"destination_systems": []any{"billing"},
		"enforcement_points":  []any{},
		"policy_refs":         []any{},
		"window_start":        "2026-01-01T00:00:00Z",
		"window_end":          "2027-01-01T00:00:00Z",
		"collection_modes":    []any{"inline"},
		"fail_behaviour":      map[string]any{"refund.issue": "fail_closed"},
		"qualification_refs":  refs,
	}
}

// QualificationBody returns a §5.2 QualificationRecord body with every
// mandatory member present.
func QualificationBody(class, qualifiedAt string) map[string]any {
	return map[string]any{
		"action_family":        "refund.issue",
		"destination_system":   "billing",
		"enumeration":          map[string]any{"api": "list_refunds"},
		"identity_isolation":   map[string]any{"attribute": "service_account"},
		"confirmation":         map[string]any{"api": "get_refund"},
		"temporal":             map[string]any{"authoritative_timestamp_source": "billing"},
		"retention_period":     "P90D",
		"mutability":           map[string]any{"deletion_possible": false},
		"assigned_class":       class,
		"class_evidence":       "trial-1",
		"trial":                map[string]any{"match_rate": 1},
		"qualified_at":         qualifiedAt,
		"revalidation_cadence": "P90D",
	}
}

// RevocationBody returns a §5.14 RevocationRecord body. supersedingRef is
// written as an explicit null when empty, because §5.14 makes it a nullable
// member rather than an optional one.
func RevocationBody(attestationRef, reason, effectiveAt, supersedingRef string) map[string]any {
	var superseding any
	if supersedingRef != "" {
		superseding = supersedingRef
	}
	return map[string]any{
		"attestation_ref":                   attestationRef,
		"reason":                            reason,
		"issuer":                            "issuer-1",
		"effective_at":                      effectiveAt,
		"superseding_ref":                   superseding,
		"relying_party_notification_status": "sent",
	}
}
