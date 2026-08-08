// Command verify independently validates evidence records, streams, and
// ingestion receipts.
//
// It MUST NOT share code with the Python writer (AC-011). The cross-
// implementation agreement asserted by ES-S-007 is only meaningful if the
// implementations are genuinely independent, so everything below is built from
// evidence-spec.md and the published vectors rather than ported.
//
// Scope is EV-05: canonicalisation, digests, signatures, chains, key
// continuity, and receipts. Attestation bundle validation, coverage
// recomputation and revocation checking are EV-19 and are deliberately absent —
// the exit codes below never claim anything about them.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
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
		mode        = flag.String("mode", "record", "record | stream | receipt | canonicalize")
		showVersion = flag.Bool("version", false, "print verifier version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"usage: verify [-mode record|stream|receipt|canonicalize] [-keyring FILE] <input.json>\n\n"+
				"Scope: EV-05 primitives only. Attestation *bundle* validation,\n"+
				"coverage recomputation, lattice re-checking and revocation are EV-19\n"+
				"and are not performed. An AttestationWindow presented to -mode record\n"+
				"has its two signatures checked (ES-023) and nothing else.\n\n")
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
	keyID, err := evidence.VerifyCanonicalEvidenceRecord(data, keys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID %s\n", err)
		os.Exit(exitInvalid)
	}
	rec, err := evidence.ParseRecord(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID %s\n", err)
		os.Exit(exitInvalid)
	}
	// ES-023: an AttestationWindow carries two signatures, and checking only
	// the customer's would report one with its counter-signature stripped as
	// valid. The record path dispatches on record_type rather than leaving the
	// second signature to whoever remembers to ask for it.
	if rec.RecordType() == "AttestationWindow" {
		issuerKeyID, err := verifyAttestation(rec, keys)
		if err != nil {
			fmt.Fprintf(os.Stderr, "INVALID %s\n", err)
			os.Exit(exitInvalid)
		}
		digest, derr := rec.CompleteDigest()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "INVALID %s\n", derr)
			os.Exit(exitInvalid)
		}
		fmt.Printf("VALID attestation window %s\n  customer key   %s\n"+
			"  issuer key     %s\n  record digest  %s\n"+
			"  NOT CHECKED    bundle contents, coverage, lattice, revocation (EV-19)\n",
			rec.RecordID(), keyID, issuerKeyID, digest)
		return
	}
	digest, err := rec.CompleteDigest()
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID %s\n", err)
		os.Exit(exitInvalid)
	}
	fmt.Printf("VALID record %s\n  signed by      %s (evidence namespace)\n  record digest  %s\n",
		rec.RecordID(), keyID, digest)
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
	// The namespace-enforcing entry point, not the bare primitive: an issuer
	// key must not authenticate a customer stream (SE-003).
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

// verifyAttestation checks both ES-023 signatures, splitting the keyring by
// namespace so the issuer proof cannot be satisfied by an evidence key.
func verifyAttestation(rec *evidence.Record,
	keys map[string]evidence.RegisteredKey) (string, error) {
	evidenceKeys := map[string]ed25519.PublicKey{}
	issuerKeys := map[string]ed25519.PublicKey{}
	for id, k := range keys {
		switch k.Namespace {
		case evidence.NamespaceEvidence:
			evidenceKeys[id] = k.PublicKey
		case evidence.NamespaceIssuer:
			issuerKeys[id] = k.PublicKey
		}
	}
	_, issuerKeyID, err := evidence.VerifyAttestationSignatures(rec, evidenceKeys, issuerKeys)
	return issuerKeyID, err
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
