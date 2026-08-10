// Package evidence verifies signed evidence records, chains, and ingestion
// receipts against evidence-spec.md, independently of the Python writer
// (AC-011). Every rule here is traced to a requirement in the comment above it.
package evidence

import (
	"fmt"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// Stable dotted error codes, shared with tests/vectors/ (vectors README).
const (
	CodeUnknownEnvelopeMember  = "schema.unknown_envelope_member"
	CodeMissingEnvelopeMember  = "schema.missing_envelope_member"
	CodeUnknownRecordType      = "schema.unknown_record_type"
	CodeMissingBodyMember      = "schema.missing_body_member"
	CodeBodyShapeInvalid       = "schema.body_shape_invalid"
	CodeHostedClockFieldForbid = "schema.hosted_clock_field_forbidden"
	CodeWireNonCanonical       = "wire.non_canonical"
	CodeKeyNamespaceMismatch   = "key.namespace_mismatch"
	CodeAlgorithmUnsupported   = "signature.algorithm_unsupported"
	CodeEncodingInvalid        = "signature.encoding_invalid"
	CodeUnknownCustomerMember  = "signature.unknown_customer_member"
	CodeMissingCustomerMember  = "signature.missing_customer_member"
	CodeUnknownIssuerMember    = "signature.unknown_issuer_member"
	CodeMissingIssuerMember    = "signature.missing_issuer_member"
	CodeSignatureInvalid       = "signature.invalid"
	CodeSignedDigestMismatch   = "signature.signed_digest_mismatch"
	CodeUnknownSigningKey      = "signature.unknown_key"
)

// Error carries a stable code. Wording is ours; the code is normative.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Code extracts the dotted code from any error this package or jcs produces.
func Code(err error) string {
	switch e := err.(type) {
	case *Error:
		return e.Code
	case *jcs.Error:
		return e.Code
	case *StreamError:
		return e.Code
	}
	return ""
}

// envelopeMembers is the closed envelope of evidence-spec.md §3. ES-005 makes
// an unknown member here fatal — deliberately the opposite of body, which
// tolerates unknown members and still digests them.
var envelopeMembers = map[string]bool{
	"record_id":      true,
	"record_type":    true,
	"schema_version": true,
	"tenant_id":      true,
	"boundary_ref":   true,
	"stream_id":      true,
	"sequence":       true,
	"prev_digest":    true,
	"source":         true,
	"clocks":         true,
	"body":           true,
	"signature":      true,
}

// hostedClockFields are observations only the hosted ingestion service can
// make. ES-019: a customer-signed record supplying either is rejected, because
// a collector asserting our receipt time is asserting something it cannot know.
var hostedClockFields = []string{"ingest_time", "clock_skew_ms"}

// requiredBodyMembers is the §3 envelope rule "record_type: one of §5" made
// checkable, together with the members each §5 body declares.
//
// Two distinct refusals come out of one table. Without the *enumeration* a
// record typed "FutureRecord" verifies as a valid record of no known type,
// which is not a conclusion a verifier is entitled to reach. Without the
// *member sets* the type is a label with nothing behind it: an AttestationWindow
// body relabelled "AgentIdentity" with the ES-023 issuer proof removed and the
// record re-signed by the customer key is then accepted as a valid
// AgentIdentity, and every coverage claim it carries has escaped the
// counter-signature that ES-023 requires of the type that may make them.
//
// Only presence is checked here, and only of members §5 makes mandatory. ES-005
// keeps body open, so unknown members are preserved and never refused; members
// optional by presence under ES-002b (ActionProposal.parameters, and the
// PopulationRecord pair below) are absent from these sets. Member *values* —
// timestamp shape, digest shape, the closed enumerations of ES-015 and ES-014 —
// are validated by the Python writer's typed models and are deliberately not
// claimed by this verifier; what is claimed is that a record cannot present one
// type's payload under another type's name.
var requiredBodyMembers = map[string][]string{
	"AssuranceBoundary": {
		"boundary_version", "tenant", "deployment", "agent_identities",
		"action_families", "destination_systems", "enforcement_points",
		"policy_refs", "window_start", "window_end", "collection_modes",
		"fail_behaviour", "qualification_refs",
	},
	"QualificationRecord": {
		"action_family", "destination_system", "enumeration", "identity_isolation",
		"confirmation", "temporal", "retention_period", "mutability",
		"assigned_class", "class_evidence", "trial", "qualified_at",
		"revalidation_cadence",
	},
	"PopulationRecord": {
		"action_family", "destination_system", "window_start", "window_end",
		"enumeration_query", "count", "pagination_complete", "result_cap_hit",
		"retrieved_at", "authoritative_timestamps",
	},
	"AgentIdentity": {
		"agent_id", "deployment", "runtime", "tenant_scope", "service_identity",
		"model_versions", "tool_versions", "credential_ref",
	},
	"ActionProposal": {
		"action_family", "action_id", "tool", "parameters_digest", "purpose",
		"target_ref", "risk_class", "proposed_at",
	},
	"AuthorityDecision": {
		"action_id", "decision", "policy_ref", "policy_version", "constraints",
		"decided_by", "decided_at",
	},
	"HumanReview": {
		"action_id", "reviewer_identity", "reviewer_authority", "surface",
		"evidence_shown", "evidence_shown_refs", "options_offered",
		"time_available_ms", "time_taken_ms", "decision", "modifications",
		"action_state_at_review", "decided_at",
	},
	"ExecutionReceipt": {
		"action_id", "dispatch_attempt", "connector_identity", "connector_version",
		"destination_response_digest", "destination_record_ref", "status",
		"dispatched_at", "responded_at",
	},
	"ExternalConfirmation": {
		"action_id", "destination_system", "destination_record_id",
		"destination_record_digest", "authoritative_timestamp",
		"reconciliation_status", "retrieved_at",
	},
	// ES-002b: reversible_until, compensation_ref, reversal_ref,
	// superseding_ref, actions_during_gap and coverage_ratio are required and
	// nullable. The explicit null is a claim about the world, so absence is a
	// missing member rather than an omitted option.
	"FinalityRecord": {
		"action_id", "state", "reversible_until", "compensation_ref", "settled_at",
	},
	"OutcomeRecord": {
		"action_id", "outcome_contract_ref", "authoritative_source", "result",
		"finalised_at", "disputed", "reversal_ref",
	},
	"CoverageGap": {
		"gap_start", "gap_end", "affected_scope", "cause", "detection_source",
		"exposure", "actions_during_gap",
	},
	"AttestationWindow": {
		"boundary_ref", "window_start", "window_end", "methodology_version",
		"denominator_class", "population_record_refs", "coverage_level",
		"verification_status", "coverage_ratio", "counts", "gaps", "assertions",
		"exclusions", "relying_parties", "validity_from", "validity_until",
		"liability_ref", "issued_at", "issuer", "verifier_version",
	},
	"RevocationRecord": {
		"attestation_ref", "reason", "issuer", "effective_at", "superseding_ref",
		"relying_party_notification_status",
	},
}

// Record is a parsed evidence record.
type Record struct {
	Obj *jcs.Object
}

// ParseRecord parses and structurally validates one record.
func ParseRecord(data []byte) (*Record, error) {
	v, err := jcs.Parse(data)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(*jcs.Object)
	if !ok {
		return nil, errf(jcs.CodeMalformed, "record envelope must be a JSON object")
	}
	r := &Record{Obj: obj}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate applies ES-005 (closed envelope, open body), the §3 requirement that
// record_type name a §5 type and carry that type's body, and ES-019 (no hosted
// clock fields in a customer-signed record).
func (r *Record) Validate() error {
	for _, k := range r.Obj.Keys() {
		if !envelopeMembers[k] {
			return errf(CodeUnknownEnvelopeMember,
				"unknown envelope member %q (ES-005)", k)
		}
	}
	for k := range envelopeMembers {
		if !r.Obj.Has(k) {
			return errf(CodeMissingEnvelopeMember, "missing envelope member %q", k)
		}
	}
	if err := r.validateType(); err != nil {
		return err
	}
	clocksV, _ := r.Obj.Get("clocks")
	clocks, ok := clocksV.(*jcs.Object)
	if !ok {
		return errf(jcs.CodeMalformed, "clocks must be an object")
	}
	for _, forbidden := range hostedClockFields {
		if clocks.Has(forbidden) {
			return errf(CodeHostedClockFieldForbid,
				"clocks.%s is a hosted observation and MUST NOT appear in a "+
					"customer-signed record (ES-019)", forbidden)
		}
	}
	if !clocks.Has("source_time") {
		return errf(CodeMissingEnvelopeMember, "clocks.source_time is required (ES-019)")
	}
	return nil
}

// validateType dispatches on record_type: the value must name a §5 type, and
// body must carry that type's mandatory members.
func (r *Record) validateType() error {
	typeV, _ := r.Obj.Get("record_type")
	recordType, ok := typeV.(string)
	if !ok {
		return errf(CodeUnknownRecordType, "record_type must be a string naming a §5 record type")
	}
	required, known := requiredBodyMembers[recordType]
	if !known {
		return errf(CodeUnknownRecordType,
			"record_type %q is not one of the types defined in evidence-spec.md §5; "+
				"an unrecognised type is refused rather than verified as a record of "+
				"no known kind", recordType)
	}
	bodyV, _ := r.Obj.Get("body")
	body, ok := bodyV.(*jcs.Object)
	if !ok {
		return errf(jcs.CodeMalformed, "body must be an object")
	}
	for _, member := range required {
		if !body.Has(member) {
			return errf(CodeMissingBodyMember,
				"%s body is missing %q (evidence-spec.md §5)", recordType, member)
		}
	}
	if recordType == "PopulationRecord" {
		// CM-002: the denominator is either enumerated or committed to by
		// digest. Neither leaves the population unstated; both leave two
		// descriptions of one population free to disagree.
		hasList := body.Has("record_identifiers")
		hasDigest := body.Has("identifier_digest")
		if hasList && hasDigest {
			return errf(CodeBodyShapeInvalid,
				"PopulationRecord body carries both record_identifiers and "+
					"identifier_digest; §5.3 admits exactly one")
		}
		if !hasList && !hasDigest {
			return errf(CodeBodyShapeInvalid,
				"PopulationRecord body carries neither record_identifiers nor "+
					"identifier_digest; §5.3 requires exactly one")
		}
	}
	return nil
}

func (r *Record) str(key string) string {
	v, _ := r.Obj.Get(key)
	s, _ := v.(string)
	return s
}

func (r *Record) RecordID() string   { return r.str("record_id") }
func (r *Record) RecordType() string { return r.str("record_type") }
func (r *Record) TenantID() string   { return r.str("tenant_id") }
func (r *Record) StreamID() string   { return r.str("stream_id") }

func (r *Record) Sequence() int64 {
	v, _ := r.Obj.Get("sequence")
	n, _ := v.(int64)
	return n
}

// PrevDigest returns the link and whether it is present (non-null).
func (r *Record) PrevDigest() (string, bool) {
	v, ok := r.Obj.Get("prev_digest")
	if !ok || v == nil {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

func (r *Record) SourceTime() string {
	clocksV, _ := r.Obj.Get("clocks")
	clocks, ok := clocksV.(*jcs.Object)
	if !ok {
		return ""
	}
	v, _ := clocks.Get("source_time")
	s, _ := v.(string)
	return s
}

func (r *Record) Signature() (*jcs.Object, error) {
	v, _ := r.Obj.Get("signature")
	sig, ok := v.(*jcs.Object)
	if !ok {
		return nil, errf(jcs.CodeMalformed, "signature must be an object")
	}
	return sig, nil
}

// SigningBytes is the ES-021 signing input: the canonical record with the
// signature member excluded.
func (r *Record) SigningBytes() ([]byte, error) {
	return jcs.Serialize(r.Obj.Without("signature"))
}

// SignedDigest is the ES-021 digest over SigningBytes.
func (r *Record) SignedDigest() (string, error) {
	b, err := r.SigningBytes()
	if err != nil {
		return "", err
	}
	return jcs.Digest(b), nil
}

// CompleteBytes is the whole record including its signature member. ES-006a
// makes this — not SigningBytes — the input to prev_digest, so that replacing
// a signature breaks the chain at the following record. ES-030 uses the same
// form for the receipt's record_digest.
func (r *Record) CompleteBytes() ([]byte, error) {
	return jcs.Serialize(r.Obj)
}

// CompleteDigest is the ES-006a / ES-030 digest over CompleteBytes.
func (r *Record) CompleteDigest() (string, error) {
	b, err := r.CompleteBytes()
	if err != nil {
		return "", err
	}
	return jcs.Digest(b), nil
}
