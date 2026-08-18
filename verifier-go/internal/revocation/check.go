package revocation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/versions"
)

// SPEC GAP (recorded, not guessed).
//
// AR-013 and TM-014 require the verifier to "check revocation online where
// possible" against "the issuer endpoint", and evidence-spec.md §5.14 defines
// the RevocationRecord body. Nothing in the corpus states the wire protocol
// between them: no path, no request shape, no response shape, and no way to
// spell "no revocation exists" as distinct from "I have no idea". There are no
// revocation vectors either, so ES-029 cannot decide it.
//
// The protocol below is therefore this implementation's, chosen so that the
// ambiguity cannot become an overclaim, and reported as a finding rather than
// resolved silently:
//
//	GET {endpoint}/revocations/{attestation record_id}
//	  404                     -> no revocation published        -> Valid
//	  200 + RevocationRecord  -> authenticated, then classified  -> Revoked/Superseded
//	  anything else           -> Unchecked
//
// A relying party pointed at a different issuer implementation will get
// Unchecked, which is wrong-but-safe. The reverse default — treating an
// unrecognised answer as "no revocation" — is wrong-and-fatal, which is why
// the asymmetry is deliberate.

// Fetcher retrieves the issuer's answer for one attestation. It exists so the
// failure paths are directly testable: every error a real network can produce
// has to be injectable, because "none may collapse into valid" is a claim
// about the error paths specifically.
type Fetcher interface {
	Fetch(ctx context.Context, attestationRef string) (status int, body []byte, err error)
}

// HTTPFetcher is the real transport.
type HTTPFetcher struct {
	Endpoint string
	Client   *http.Client
}

// NewHTTPFetcher builds a fetcher with an explicit timeout. A verifier that
// hangs is a verifier that never reports unchecked, so the timeout is not
// optional and there is no zero-means-infinite path.
func NewHTTPFetcher(endpoint string, timeout time.Duration) *HTTPFetcher {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPFetcher{Endpoint: endpoint, Client: &http.Client{Timeout: timeout}}
}

// Fetch performs the GET described in the SPEC GAP note above.
func (f *HTTPFetcher) Fetch(ctx context.Context, attestationRef string) (int, []byte, error) {
	base, err := url.Parse(f.Endpoint)
	if err != nil {
		return 0, nil, fmt.Errorf("revocation endpoint is not a URL: %w", err)
	}
	target := base.JoinPath("revocations", attestationRef)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Bound the read: an endpoint that streams forever must produce unchecked,
	// not a verifier that never terminates.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// Checker holds everything the four-state machine needs.
type Checker struct {
	// Fetcher is nil when no endpoint was configured, which is one of the two
	// honest ways to be offline.
	Fetcher Fetcher
	// Offline suppresses the network entirely. TM-S-004 runs the verifier with
	// no network access; this is that switch, and it short-circuits before any
	// transport is touched so the scenario cannot pass by accident of a
	// connection failure.
	Offline bool
	// IssuerKeys authenticates the RevocationRecord. ES-033 requires a
	// RevocationRecord to carry a primary issuer-namespace signature, so an
	// unauthenticated answer establishes nothing in either direction.
	IssuerKeys map[string]evidence.RegisteredKey
	// Now is injectable so effective_at handling is testable without sleeping.
	Now func() time.Time
}

func (c Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Check answers the four-state question for one attestation.
//
// It returns no error. That is the API carrying the requirement: a caller
// cannot drop an error and be left holding something that looks affirmative,
// because every failure is already spelled as an Unchecked Result with a
// reason. There is exactly one return path that yields Valid, and it is
// reached only after an authenticated 404 or an authenticated,
// not-yet-effective record.
func (c Checker) Check(ctx context.Context, attestationRef string) Result {
	if c.Offline {
		return unchecked(ReasonOffline,
			"verifier is running offline; revocation state is unknown, not fine")
	}
	if c.Fetcher == nil {
		return unchecked(ReasonNoEndpoint,
			"no revocation endpoint configured; revocation state is unknown")
	}
	if attestationRef == "" {
		return unchecked(ReasonWrongSubject,
			"no attestation reference to ask about")
	}

	status, body, err := c.Fetcher.Fetch(ctx, attestationRef)
	if err != nil {
		if isTimeout(err) {
			return unchecked(ReasonTimeout,
				fmt.Sprintf("revocation endpoint did not answer in time: %v", err))
		}
		return unchecked(ReasonTransport,
			fmt.Sprintf("revocation endpoint unreachable: %v", err))
	}

	switch status {
	case http.StatusNotFound:
		// The issuer answered, and the answer was "nothing published". This is
		// the only 'no record' path that may become Valid, and it is Valid
		// because the issuer said so, not because we failed to hear otherwise.
		return checkedValid(ReasonNonePublished,
			"issuer published no RevocationRecord for this attestation")
	case http.StatusOK:
		// fall through
	default:
		return unchecked(ReasonHTTPStatus,
			fmt.Sprintf("revocation endpoint returned HTTP %d", status))
	}

	return c.classify(body, attestationRef)
}

// classify authenticates the returned RevocationRecord and reads its state.
func (c Checker) classify(body []byte, attestationRef string) Result {
	if len(body) == 0 {
		return unchecked(ReasonMalformed, "revocation endpoint returned an empty 200")
	}
	// The full canonical-wire path, not a primitive: a revocation answer is a
	// composition entry point, and testing-qa §10 is explicit that these are
	// where a stricter primitive gets bypassed. ES-033 dispatch inside
	// VerifyCanonicalEvidenceRecord is what refuses an evidence-key-signed
	// RevocationRecord, which is otherwise exactly how a customer would
	// un-revoke themselves.
	verified, err := evidence.VerifyCanonicalEvidenceRecord(body, c.IssuerKeys)
	if err != nil {
		return unchecked(ReasonUnauthenticated,
			fmt.Sprintf("revocation response did not authenticate: %v", err))
	}
	if verified.RecordType != "RevocationRecord" {
		return unchecked(ReasonMalformed,
			fmt.Sprintf("revocation endpoint returned a %s, not a RevocationRecord",
				verified.RecordType))
	}

	rec, err := evidence.ParseRecord(body)
	if err != nil {
		return unchecked(ReasonMalformed, err.Error())
	}
	bodyObj, err := recordBody(rec)
	if err != nil {
		return unchecked(ReasonBodyShape, err.Error())
	}

	schemaRaw, _ := rec.Obj.Get("schema_version")
	schema, schemaOK := schemaRaw.(string)
	if !schemaOK || versions.Schema(schema) != versions.Published {
		return unchecked(ReasonMalformed,
			fmt.Sprintf("RevocationRecord schema_version %q is not published", schema))
	}

	ref, refOK := stringMember(bodyObj, "attestation_ref")
	if !refOK {
		return unchecked(ReasonBodyShape,
			"RevocationRecord attestation_ref must be a string")
	}
	if ref != attestationRef {
		// An authenticated record about a different attestation tells us
		// nothing about this one. Reporting it as revoked would let one
		// revocation take down an unrelated attestation; reporting it as valid
		// would let a stale record vouch for one.
		return unchecked(ReasonWrongSubject,
			fmt.Sprintf("RevocationRecord names attestation %q, not %q", ref, attestationRef))
	}

	effectiveAt, ok := stringMember(bodyObj, "effective_at")
	if !ok {
		return unchecked(ReasonBodyShape, "RevocationRecord has no effective_at")
	}
	effective, err := time.Parse(time.RFC3339, effectiveAt)
	if err != nil {
		return unchecked(ReasonBodyShape,
			fmt.Sprintf("RevocationRecord effective_at %q is not RFC 3339", effectiveAt))
	}

	supersedingRaw, hasSuperseding := bodyObj.Get("superseding_ref")
	if !hasSuperseding {
		return unchecked(ReasonBodyShape,
			"RevocationRecord has no superseding_ref")
	}
	var supersededBy string
	if supersedingRaw != nil {
		var ok bool
		supersededBy, ok = supersedingRaw.(string)
		if !ok || supersededBy == "" {
			return unchecked(ReasonBodyShape,
				"RevocationRecord superseding_ref must be null or a non-empty string")
		}
	}
	reason, reasonOK := stringMember(bodyObj, "reason")
	if !reasonOK || reason == "" {
		return unchecked(ReasonBodyShape,
			"RevocationRecord reason must be a non-empty string")
	}
	if _, ok := stringMember(bodyObj, "relying_party_notification_status"); !ok {
		return unchecked(ReasonBodyShape,
			"RevocationRecord relying_party_notification_status must be a string")
	}

	if effective.After(c.now()) {
		// Checked, and the answer is that the revocation has not taken effect
		// yet. The pending state is carried on the Result rather than folded
		// away, because a relying party deciding today needs to see it.
		return checkedPendingValid(effectiveAt, supersededBy,
			fmt.Sprintf("a revocation is published but takes effect at %s", effectiveAt))
	}

	if supersededBy != "" {
		return checkedSuperseded(effectiveAt, supersededBy,
			fmt.Sprintf("superseded by %s", supersededBy))
	}
	return checkedRevoked(effectiveAt, fmt.Sprintf("revoked by issuer: %s", reason))
}

func recordBody(rec *evidence.Record) (*jcs.Object, error) {
	v, ok := rec.Obj.Get("body")
	if !ok {
		return nil, errors.New("record has no body")
	}
	obj, ok := v.(*jcs.Object)
	if !ok {
		return nil, errors.New("record body is not an object")
	}
	return obj, nil
}

func stringMember(obj *jcs.Object, key string) (string, bool) {
	v, ok := obj.Get(key)
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// isTimeout separates "did not answer in time" from other transport failures.
// Both are unchecked; they are distinguished because an operator debugging a
// verifier needs to know which one happened, and because a timeout is the
// failure most likely to be mistaken for success by a naive implementation
// that returns a zero-valued result on error.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
