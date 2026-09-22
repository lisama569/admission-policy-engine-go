// Package loader dispatches policy documents to the right parser based on
// their declared version ("v1" historical, "v2" current).
package loader

import (
	"encoding/json"

	"github.com/lisama569/admission-policy-engine-go/pkg/legacy"
	"github.com/lisama569/admission-policy-engine-go/pkg/policy"
)

// versionProbe peeks at the top-level "version" field without accepting or
// rejecting the rest of the document.
type versionProbe struct {
	Version string `json:"version"`
}

// Load parses raw JSON, auto-detecting the document version:
//
//   - "v1": parsed and normalized through the legacy converter;
//   - "v2": parsed natively;
//   - missing/anything else: rejected with a typed *policy.LoadError.
//
// The returned PolicySet is fully validated and safe to install into an
// Engine. Invalid input never returns a partially usable set.
func Load(raw []byte) (*policy.PolicySet, error) {
	if !json.Valid(raw) {
		return nil, &policy.LoadError{Code: policy.ErrInvalidJSON,
			Message: "policy document is not valid JSON"}
	}
	var probe versionProbe
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, &policy.LoadError{Code: policy.ErrInvalidJSON, Message: err.Error()}
	}
	switch probe.Version {
	case policy.CurrentVersion:
		return policy.ParsePolicySet(raw)
	case legacy.LegacyVersion:
		return legacy.ConvertDocument(raw)
	case "":
		return nil, &policy.LoadError{Code: policy.ErrMissingVersion,
			Message: "policy document has no version field; expected \"v1\" or \"v2\""}
	default:
		return nil, &policy.LoadError{Code: policy.ErrUnsupportedVersion,
			Message: "unsupported policy document version \"" + probe.Version + "\"; expected \"v1\" or \"v2\""}
	}
}
