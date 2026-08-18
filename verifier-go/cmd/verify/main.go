// Command verify independently validates evidence records, streams, and
// ingestion receipts.
//
// It MUST NOT share code with the Python writer (AC-011). The cross-
// implementation agreement asserted by ES-S-007 is only meaningful if the
// implementations are genuinely independent, so everything below is built from
// evidence-spec.md and the published vectors rather than ported.
//
// EV-05 built the primitives: canonicalisation, digests, signatures, chains,
// key continuity, and receipts. EV-19 adds -mode bundle, which validates a
// complete attestation bundle: both ES-023 signatures, schema and methodology
// versions, the AR-009 validity period, TM-013 qualification dates, and the
// four-state revocation check of TM-014.
//
// Whatever this command does not check, it says so in its own output rather
// than leaving the omission to be inferred from a green exit code.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/bundle"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/revocation"
)

const version = "0.1.0"

// Exit codes. A verifier that cannot reach a conclusion exits distinctly from
// one that reached a negative conclusion: "I could not check" and "this is
// invalid" are different claims, and collapsing them is how an outage becomes
// an apparent verification failure.
const (
	exitOK        = 0
	exitInvalid   = 1
	exitUsage     = 2
	exitUncertain = 3
)

type keyEntry struct {
	Namespace string `json:"namespace"`
	PublicKey string `json:"public_key"`
}

func main() {
	var (
		keyringPath = flag.String("keyring", "", "JSON file of {key_id: {namespace, public_key}}")
		mode        = flag.String("mode", "record", "record | bundle | stream | receipt | canonicalize")
		showVersion = flag.Bool("version", false, "print verifier version and exit")
		endpoint    = flag.String("revocation-endpoint", "",
			"issuer revocation endpoint; without one, revocation reports unchecked")
		offline = flag.Bool("offline", false,
			"make no network request at all; revocation reports unchecked")
		revTimeout = flag.Duration("revocation-timeout", 5*time.Second,
			"how long to wait for the revocation endpoint before reporting unchecked")
		asOf = flag.String("as-of", "",
			"RFC 3339 instant to evaluate the validity period at (default: now)")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"usage: verify [-mode record|bundle|stream|receipt|canonicalize] "+
				"[-keyring FILE] <input.json>\n\n"+
				"-mode record verifies one record's signatures and nothing else. An\n"+
				"AttestationWindow presented there has its two ES-023 signatures\n"+
				"checked; its coverage claim is not examined.\n\n"+
				"-mode bundle verifies a complete attestation bundle. Without\n"+
				"-revocation-endpoint, or with -offline, revocation_status is reported\n"+
				"as unchecked and the verdict is never \"valid\" (TM-014).\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("verify %s\n", version)
		return
	}
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(exitUsage)
	}

	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read input: %v\n", err)
		os.Exit(exitUncertain)
	}

	switch *mode {
	case "canonicalize":
		runCanonicalize(data)
	case "record":
		runRecord(data, loadKeyring(*keyringPath))
	case "bundle":
		runBundle(data, loadKeyring(*keyringPath), *endpoint, *offline, *revTimeout, *asOf)
	case "stream":
		runStream(data, loadKeyring(*keyringPath))
	case "receipt":
		runReceipt(data, loadKeyring(*keyringPath))
	default:
		flag.Usage()
		os.Exit(exitUsage)
	}
}

func loadKeyring(path string) map[string]evidence.RegisteredKey {
	if path == "" {
		fmt.Fprintln(os.Stderr, "a -keyring is required for signature verification")
		os.Exit(exitUsage)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read keyring: %v\n", err)
		os.Exit(exitUncertain)
	}
	var entries map[string]keyEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		fmt.Fprintf(os.Stderr, "malformed keyring: %v\n", err)
		os.Exit(exitUsage)
	}
	out := make(map[string]evidence.RegisteredKey, len(entries))
	for id, e := range entries {
		pk, err := base64.RawURLEncoding.DecodeString(e.PublicKey)
		if err != nil || len(pk) != ed25519.PublicKeySize {
			fmt.Fprintf(os.Stderr, "keyring entry %q: public_key must be 32 unpadded base64url bytes\n", id)
			os.Exit(exitUsage)
		}
		out[id] = evidence.RegisteredKey{Namespace: e.Namespace, PublicKey: pk}
	}
	return out
}

func runCanonicalize(data []byte) {
	canonical, err := jcs.Canonicalize(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REJECTED %s\n", err)
		os.Exit(exitInvalid)
	}
	fmt.Printf("%s\n", canonical)
	fmt.Fprintf(os.Stderr, "digest %s\n", jcs.Digest(canonical))
}

// runRecord verifies the received bytes as received (ES-001) before
// authenticating, so a non-canonical wire form is reported as such rather than
// as a signature failure.
func runRecord(data []byte, keys map[string]evidence.RegisteredKey) {
	// ES-023 dispatch on record_type lives in the library, so this command and
	// every other caller of the record path check the same things.
	verified, err := evidence.VerifyCanonicalEvidenceRecord(data, keys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID %s\n", err)
		os.Exit(exitInvalid)
	}
	rec, err := evidence.ParseRecord(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID %s\n", err)
		os.Exit(exitInvalid)
	}
	digest, err := rec.CompleteDigest()
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID %s\n", err)
		os.Exit(exitInvalid)
	}
	if verified.IssuerKeyID != "" {
		fmt.Printf("VALID %s %s\n  customer key   %s\n"+
			"  issuer key     %s\n  record digest  %s\n"+
			"  NOT CHECKED    bundle contents, coverage, lattice, revocation (EV-19)\n",
			verified.RecordType, rec.RecordID(), verified.KeyID, verified.IssuerKeyID, digest)
		return
	}
	fmt.Printf("VALID %s %s\n  signed by      %s (%s namespace)\n  record digest  %s\n",
		verified.RecordType, rec.RecordID(), verified.KeyID,
		keys[verified.KeyID].Namespace, digest)
}

// runBundle is the EV-19 entry point.
//
// The output is written so that the *absence* of a check is as visible as its
// result. TM-S-004 requires that an offline run not state the attestation is
// valid, and the way that requirement gets quietly broken is not by printing
// the word — it is by printing a confident summary that a reader takes as one.
// So every line here names what was established and by what, the verdict word
// is never "valid" unless the issuer affirmatively answered, and the checks
// that did not run are listed by name.
func runBundle(data []byte, keys map[string]evidence.RegisteredKey,
	endpoint string, offline bool, timeout time.Duration, asOf string) {
	// -as-of exists because "is this attestation valid" is a question about an
	// instant, and a relying party reconstructing a past decision needs to ask
	// it about that instant rather than about today. It is not a test hook:
	// QA-004 requires the artifact under test to be the shipped one, so the
	// instant used is printed on every run and the default is the real clock.
	now := time.Now
	if asOf != "" {
		at, err := time.Parse(time.RFC3339, asOf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "-as-of %q is not RFC 3339: %v\n", asOf, err)
			os.Exit(exitUsage)
		}
		now = func() time.Time { return at }
	}

	parsed, err := bundle.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID %s\n", err)
		os.Exit(exitInvalid)
	}

	checker := revocation.Checker{Offline: offline, IssuerKeys: keys, Now: now}
	switch {
	case offline:
		// No fetcher is constructed at all, so an -offline run cannot reach the
		// network even if an endpoint was also supplied.
	case endpoint != "":
		checker.Fetcher = revocation.NewHTTPFetcher(endpoint, timeout)
	}

	res := bundle.Verify(context.Background(), parsed, bundle.Options{
		Keys:       keys,
		Revocation: checker,
		// EV-19's coverage recomputation, lattice re-checking and assertion
		// catalogue register here. Until they do, the "NOT CHECKED" line below
		// says so on every run.
		Checks: registeredChecks(),
		Now:    now,
	})

	out := os.Stdout
	if res.Verdict != bundle.Valid {
		out = os.Stderr
	}
	fmt.Fprintf(out, "VERDICT %s\n", res.Verdict)
	fmt.Fprintf(out, "  attestation      %s\n", res.AttestationID)
	fmt.Fprintf(out, "  evaluated at     %s\n", now().UTC().Format(time.RFC3339))
	if res.EvidenceKeyID != "" {
		fmt.Fprintf(out, "  customer key     %s\n", res.EvidenceKeyID)
	}
	if res.IssuerKeyID != "" {
		fmt.Fprintf(out, "  issuer key       %s\n", res.IssuerKeyID)
	}
	fmt.Fprintf(out, "  revocation       %s (%s)\n",
		res.Revocation.Status(), res.Revocation.Reason())
	if d := res.Revocation.Detail(); d != "" {
		fmt.Fprintf(out, "                   %s\n", d)
	}
	if res.Revocation.SupersededBy != "" {
		fmt.Fprintf(out, "  superseded by    %s\n", res.Revocation.SupersededBy)
	}
	if len(res.ChecksRun) > 0 {
		fmt.Fprintf(out, "  checks run       %v\n", res.ChecksRun)
	}
	for _, note := range res.Notes {
		fmt.Fprintf(out, "  NOT CHECKED      %s\n", note)
	}
	// Unresolved items are printed unconditionally, whatever the verdict word
	// turned out to be. Without this an offline run hides them completely: the
	// unchecked-revocation verdict is reported first, and a coverage claim that
	// could not be recomputed would leave no trace in the output at all.
	for _, u := range res.Unresolved {
		fmt.Fprintf(out, "  NOT CHECKED      %s\n", u)
	}
	for _, f := range res.Findings {
		fmt.Fprintf(out, "  REFUSED          %s\n", f)
	}

	switch res.Verdict {
	case bundle.Valid:
		os.Exit(exitOK)
	case bundle.UncheckedRevocation, bundle.Indeterminate:
		// "I could not check" is not "this is invalid" (see the exit codes).
		os.Exit(exitUncertain)
	default:
		os.Exit(exitInvalid)
	}
}

func runStream(data []byte, keys map[string]evidence.RegisteredKey) {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		fmt.Fprintf(os.Stderr, "stream input must be a JSON array of records: %v\n", err)
		os.Exit(exitUsage)
	}
	records := make([]*evidence.Record, 0, len(raw))
	for i, item := range raw {
		rec, err := evidence.ParseRecord(item)
		if err != nil {
			fmt.Fprintf(os.Stderr, "INVALID record %d: %s\n", i, err)
			os.Exit(exitInvalid)
		}
		records = append(records, rec)
	}
	res, err := evidence.VerifyEvidenceStream(records, keys)
	if err != nil {
		// CM-017: a break terminates the window at the break rather than
		// invalidating what preceded it, so the verified prefix is reported.
		if se, ok := err.(*evidence.StreamError); ok {
			fmt.Fprintf(os.Stderr,
				"BROKEN %s\n  break at sequence   %d\n  verified through    %d\n  %s\n",
				se.Code, se.BreakSequence, se.ValidThrough, se.Msg)
		} else {
			fmt.Fprintf(os.Stderr, "BROKEN %s\n", err)
		}
		os.Exit(exitInvalid)
	}
	fmt.Printf("VALID stream sequences %d..%d\n  last key      %s\n  last digest   %s\n",
		res.StartSequence, res.EndSequence, res.LastKeyID, res.LastDigest)
}

// receiptInput pairs a customer record with its detached issuer receipt.
type receiptInput struct {
	Record  json.RawMessage `json:"record"`
	Receipt struct {
		CanonicalHex string `json:"canonical_utf8_hex"`
		KeyID        string `json:"key_id"`
		Signature    string `json:"signature"`
	} `json:"receipt"`
}

// runReceipt verifies an ES-030 ingestion receipt against its record. Without
// this mode the receipt verifier was reachable only from Go tests, which means
// a relying party could not check the hosted clock observation at all.
func runReceipt(data []byte, keys map[string]evidence.RegisteredKey) {
	var input receiptInput
	if err := json.Unmarshal(data, &input); err != nil {
		fmt.Fprintf(os.Stderr,
			"receipt input must be {\"record\": {...}, \"receipt\": "+
				"{canonical_utf8_hex, key_id, signature}}: %v\n", err)
		os.Exit(exitUsage)
	}
	rec, err := evidence.ParseRecord(input.Record)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID %s\n", err)
		os.Exit(exitInvalid)
	}
	canonical, err := hex.DecodeString(input.Receipt.CanonicalHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "receipt canonical_utf8_hex is not hex: %v\n", err)
		os.Exit(exitUsage)
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(input.Receipt.Signature)
	if err != nil {
		fmt.Fprintf(os.Stderr, "receipt signature is not unpadded base64url: %v\n", err)
		os.Exit(exitUsage)
	}
	payload, err := evidence.VerifyIngestionReceipt(evidence.SignedReceipt{
		CanonicalBytes: canonical,
		KeyID:          input.Receipt.KeyID,
		Signature:      sig,
	}, rec, keys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID %s\n", err)
		os.Exit(exitInvalid)
	}
	fmt.Printf("VALID receipt for record %s\n  issuer key     %s (issuer namespace)\n"+
		"  ingest_time    %s\n  clock_skew_ms  %d (recomputed, not taken from the receipt)\n",
		rec.RecordID(), input.Receipt.KeyID, payload.IngestTime, payload.ClockSkewMS)
}
