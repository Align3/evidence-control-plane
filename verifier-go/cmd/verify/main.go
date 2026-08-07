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
		mode        = flag.String("mode", "record", "record | stream | canonicalize")
		showVersion = flag.Bool("version", false, "print verifier version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"usage: verify [-mode record|stream|canonicalize] [-keyring FILE] <input.json>\n\n"+
				"Scope: EV-05 primitives only. Attestation bundle validation,\n"+
				"coverage recomputation and revocation are EV-19 and are not performed.\n\n")
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
	res, err := evidence.VerifyStream(records, evidence.PublicKeyMap(keys))
	if err != nil {
		// CM-017: a break terminates the window at the break rather than
		// invalidating what preceded it, so the verified prefix is reported.
		if se, ok := err.(*evidence.StreamError); ok {
			fmt.Fprintf(os.Stderr,
				"BROKEN %s\n  break at sequence   %d\n  verified through    %d\n  %s\n",
				se.Code, se.BreakSequence, se.ValidThrough, se.Msg)
			// Every determinable failure is printed, not just the leading one:
			// suppressing the rest would hide a second integrity failure behind
			// the first (ES-006a refusal precedence).
			for _, c := range se.Codes[1:] {
				fmt.Fprintf(os.Stderr, "  also reported       %s\n", c)
			}
		} else {
			fmt.Fprintf(os.Stderr, "BROKEN %s\n", err)
		}
		os.Exit(exitInvalid)
	}
	fmt.Printf("VALID stream sequences %d..%d\n  last key      %s\n  last digest   %s\n",
		res.StartSequence, res.EndSequence, res.LastKeyID, res.LastDigest)
}
