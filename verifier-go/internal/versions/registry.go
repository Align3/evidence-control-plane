// Package versions is the single Go transcription of the ES-035 and CM-025
// published-version registries. Verification entry points consult this package
// instead of carrying private copies that can drift.
package versions

// Status is a version's publication state.
type Status uint8

const (
	Unknown Status = iota
	Published
	Reserved
)

var schema = map[string]Status{
	"1.0.0": Published,
	"2.0.0": Reserved,
}

var methodology = map[string]Status{
	"1.0.0": Published,
}

// Schema returns the ES-035 status of a schema version.
func Schema(value string) Status { return schema[value] }

// Methodology returns the CM-025 status of a methodology version.
func Methodology(value string) Status { return methodology[value] }
