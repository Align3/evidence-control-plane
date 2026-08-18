package bundle

import (
	"sort"
)

// checkChainLinks verifies ES-006a links between bundle records that sit at
// consecutive sequences in one stream.
//
// TM-S-004 says "signature and chain verification succeed", and until now this
// package checked only signatures. The gap mattered: a record's signature
// proves who wrote it, and prev_digest is what proves nothing was removed from
// in front of it.
//
// The check is deliberately narrow, and the narrowness is a requirement rather
// than a shortcut. ES-026 makes selective disclosure mandatory — a relying
// party may be given a bundle proving one claim without the rest of the
// ledger — so a bundle is expected to carry slices of streams, not whole ones.
// Running the full stream verifier here would refuse every selectively
// disclosed bundle for not being anchored at sequence 1, which would make
// ES-026 unimplementable through the entry point relying parties actually use.
//
// So: where two records in one stream sit at consecutive sequences, the link
// between them is determinate and is checked. Where the slice is
// non-contiguous, the chain across the hole is not verifiable from what the
// bundle carries, and that is reported as unresolved rather than either
// refused (which would break ES-026) or passed over (which would let a removed
// record travel invisibly).
//
// SPEC GAP (recorded): no document states what chain verification means for a
// bundle as opposed to a stream. The reading above is chosen because it is the
// only one that leaves ES-026 satisfiable, not because the corpus states it.
func checkChainLinks(b *Bundle) ([]Finding, []string) {
	var (
		out        []Finding
		unresolved []string
	)

	// Group by (tenant, stream). Records from different streams have no link
	// to check between them, and ES-024a forbids inferring continuity across a
	// stream boundary.
	type streamKey struct{ tenant, stream string }
	groups := map[streamKey][]*Record{}
	for _, rec := range allRecords(b) {
		key := streamKey{rec.Parsed.TenantID(), rec.Parsed.StreamID()}
		groups[key] = append(groups[key], rec)
	}

	keys := make([]streamKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	// Sorted so the findings a bundle produces do not depend on map iteration
	// order: a verifier whose output varies run to run is one nobody can
	// diff against a golden (QA-008).
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].tenant != keys[j].tenant {
			return keys[i].tenant < keys[j].tenant
		}
		return keys[i].stream < keys[j].stream
	})

	for _, key := range keys {
		records := groups[key]
		if len(records) < 2 {
			continue
		}
		sort.Slice(records, func(i, j int) bool {
			return records[i].Parsed.Sequence() < records[j].Parsed.Sequence()
		})

		for i := 1; i < len(records); i++ {
			prev, cur := records[i-1], records[i]
			prevSeq, curSeq := prev.Parsed.Sequence(), cur.Parsed.Sequence()

			if curSeq == prevSeq {
				// Two records claiming one position in one stream is a fork,
				// and it is a refusal regardless of disclosure: both cannot be
				// the record at that sequence.
				out = append(out, finding(CodeChainFork,
					"stream %q carries two records at sequence %d (%s and %s); "+
						"a bundle cannot present two records for one position",
					key.stream, curSeq, prev.Parsed.RecordID(), cur.Parsed.RecordID()))
				continue
			}
			if curSeq != prevSeq+1 {
				unresolved = append(unresolved, chainHole(key.stream, prevSeq, curSeq))
				continue
			}

			want, err := prev.Parsed.CompleteDigest()
			if err != nil {
				out = append(out, finding(CodeChainBroken,
					"stream %q sequence %d: cannot compute the ES-006a digest of "+
						"its predecessor: %v", key.stream, curSeq, err))
				continue
			}
			got, present := cur.Parsed.PrevDigest()
			if !present {
				out = append(out, finding(CodeChainBroken,
					"stream %q sequence %d has a null prev_digest but follows "+
						"sequence %d in this bundle; only the first record of a "+
						"stream has no predecessor (ES-006a)",
					key.stream, curSeq, prevSeq))
				continue
			}
			if got != want {
				// ES-006a digests the complete record including its signature,
				// so this also catches a validly re-signed predecessor: the
				// signature changed, therefore the link changed.
				out = append(out, finding(CodeChainBroken,
					"stream %q sequence %d does not link to sequence %d: "+
						"prev_digest is %s, the predecessor in this bundle digests "+
						"to %s (ES-006a)", key.stream, curSeq, prevSeq, got, want))
			}
		}
	}

	return out, unresolved
}

func chainHole(stream string, prevSeq, curSeq int64) string {
	return "chain: stream " + stream + " jumps from sequence " +
		itoa(prevSeq) + " to " + itoa(curSeq) +
		"; the records between them are not in the bundle, so the chain across " +
		"that hole was not verified (ES-026 permits the omission; it does not " +
		"make the link checkable)"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// allRecords is every record the bundle carries, attestation included.
func allRecords(b *Bundle) []*Record {
	out := make([]*Record, 0,
		1+len(b.Qualifications)+len(b.Populations)+len(b.Gaps)+len(b.Other))
	out = append(out, b.Attestation)
	out = append(out, b.Qualifications...)
	out = append(out, b.Populations...)
	out = append(out, b.Gaps...)
	out = append(out, b.Other...)
	if b.Boundary != nil {
		out = append(out, b.Boundary)
	}
	return out
}
