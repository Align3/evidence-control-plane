// Command verify independently validates an evidence bundle or attestation.
//
// It MUST NOT share code with the Python writer (AC-011). The cross-
// implementation agreement asserted by ES-S-007 is only meaningful if the
// implementations are genuinely independent.
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: verify <bundle.json>")
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "verifier %s: not implemented (EV-05)\n", version)
	os.Exit(1)
}
