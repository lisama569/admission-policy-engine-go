package policy

import (
	"bytes"
	"encoding/json"
	"strings"
)

// CurrentVersion is the native policy format accepted by ParsePolicySet.
const CurrentVersion = "v2"

// ParsePolicySet parses a v2 ("version": "v2") policy document and
// validates it as a whole. A returned error is *LoadError and the caller
// can keep using any previously loaded set unchanged.
func ParsePolicySet(raw []byte) (*PolicySet, error) {
	if !json.Valid(raw) {
		return nil, &LoadError{Code: ErrInvalidJSON, Message: "document is not valid JSON"}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Reject unknown fields up front: a silently ignored field would hide
	// a policy that does not say what its author thought it said.
	dec.DisallowUnknownFields()

	var set PolicySet
	if err := dec.Decode(&set); err != nil {
		return nil, &LoadError{Code: ErrInvalidJSON, Message: err.Error()}
	}

	for i := range set.Rules {
		r := &set.Rules[i]
		for j := range r.Match.All {
			normalizeCondition(&r.Match.All[j])
		}
		for j := range r.Match.Any {
			normalizeCondition(&r.Match.Any[j])
		}
		for j := range r.Match.Not {
			normalizeCondition(&r.Match.Not[j])
		}
	}

	if err := set.Validate(); err != nil {
		return nil, err
	}
	return &set, nil
}

// Validate checks a PolicySet for self-consistency. It is also applied to
// sets produced by legacy conversion, so invalid rules can never reach the
// engine regardless of entry point.
func (s *PolicySet) Validate() error {
	if s.Version != CurrentVersion {
		return &LoadError{Code: ErrUnsupportedVersion,
			Message: "native parser expects version \"" + CurrentVersion + "\", got \"" + s.Version + "\""}
	}
	// An empty defaultEffect fails closed (deny); an explicitly invalid
	// value is rejected rather than guessed.
	switch s.DefaultEffect {
	case "":
		s.DefaultEffect = EFFECT_DENY
	case EFFECT_ALLOW, EFFECT_WARN, EFFECT_DENY:
	default:
		return &LoadError{Code: ErrDefaultEffectInvalid,
			Message: "defaultEffect must be allow, warn or deny; got \"" + string(s.DefaultEffect) + "\""}
	}

	seen := make(map[string]struct{}, len(s.Rules))
	for i := range s.Rules {
		r := &s.Rules[i]
		path := "rules[" + itoa(i) + "]"
		id := strings.TrimSpace(r.ID)
		if id == "" {
			return &LoadError{Code: ErrMissingRuleID, Path: path,
				Message: "every rule requires a non-empty id"}
		}
		if _, dup := seen[id]; dup {
			return &LoadError{Code: ErrDuplicateRuleID, Path: path,
				Message: "duplicate rule id: " + id}
		}
		seen[id] = struct{}{}

		switch r.Effect {
		case EFFECT_ALLOW, EFFECT_WARN, EFFECT_DENY:
		default:
			return &LoadError{Code: ErrInvalidEffect, Path: "rules[" + id + "]",
				Message: "effect must be allow, warn or deny; got \"" + string(r.Effect) + "\""}
		}

		if err := validateMatch(&r.Match, "rules["+id+"].match"); err != nil {
			return err
		}
	}
	return nil
}

func validateMatch(m *Match, basePath string) error {
	groups := []struct {
		name string
		cond []Condition
	}{
		{"all", m.All}, {"any", m.Any}, {"not", m.Not},
	}
	for _, g := range groups {
		for i, c := range g.cond {
			path := basePath + "." + g.name + "[" + itoa(i) + "]"
			if err := validateCondition(c, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCondition(c Condition, path string) error {
	if strings.TrimSpace(c.Field) == "" {
		return &LoadError{Code: ErrInvalidFieldPath, Path: path, Message: "condition field is empty"}
	}
	if err := ValidateFieldPath(c.Field); err != nil {
		return &LoadError{Code: ErrInvalidFieldPath, Path: path, Message: err.Error()}
	}
	switch c.Operator {
	case OP_EQ, OP_NE, OP_GT, OP_GTE, OP_LT, OP_LTE, OP_STARTS_WITH:
		if c.Value == nil {
			return &LoadError{Code: ErrMissingValue, Path: path,
				Message: string(c.Operator) + " requires a value"}
		}
	case OP_CONTAINS:
		if c.Value == nil {
			return &LoadError{Code: ErrMissingValue, Path: path,
				Message: "contains requires a value"}
		}
	case OP_IN, OP_NOT_IN:
		if len(c.Values) == 0 {
			return &LoadError{Code: ErrMissingValue, Path: path,
				Message: string(c.Operator) + " requires a non-empty values list"}
		}
	case OP_EXISTS:
		// no operands allowed
	default:
		return &LoadError{Code: ErrInvalidOperator, Path: path,
			Message: "unknown operator: " + string(c.Operator)}
	}
	if (c.Operator == OP_GT || c.Operator == OP_GTE || c.Operator == OP_LT || c.Operator == OP_LTE) && c.Value != nil {
		if _, ok := toFloat64(c.Value); !ok {
			if _, ok := c.Value.(string); !ok {
				return &LoadError{Code: ErrInvalidValue, Path: path,
					Message: string(c.Operator) + " value must be number or string"}
			}
		}
	}
	if c.Operator == OP_STARTS_WITH {
		if _, ok := c.Value.(string); !ok {
			return &LoadError{Code: ErrInvalidValue, Path: path,
				Message: "startsWith value must be a string"}
		}
	}
	return nil
}

// ValidateFieldPath checks the syntax of a dotted field path. Unknown
// bare paths are legal: they resolve into Resource.Extra. Empty segments
// and trailing dots are rejected to avoid alias spellings of one field.
func ValidateFieldPath(path string) error {
	if path == "" {
		return &LoadError{Code: ErrInvalidFieldPath, Message: "empty field path"}
	}
	if strings.HasPrefix(path, ".") || strings.HasSuffix(path, ".") {
		return &LoadError{Code: ErrInvalidFieldPath, Message: "field path has leading or trailing dot: " + path}
	}
	segs := strings.Split(path, ".")
	for _, seg := range segs {
		if seg == "" {
			return &LoadError{Code: ErrInvalidFieldPath, Message: "field path has empty segment: " + path}
		}
	}
	return nil
}

func normalizeCondition(c *Condition) {
	c.Value = normalizeNumbers(c.Value)
	for i := range c.Values {
		c.Values[i] = normalizeNumbers(c.Values[i])
	}
}

// normalizeNumbers converts encoding/json float64 payloads that hold exact
// integers into int64, so rule values authored as 3 never behave
// differently from 3.0. Non-integral and non-numeric values are untouched.
func normalizeNumbers(v interface{}) interface{} {
	switch t := v.(type) {
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
		return t
	case map[string]interface{}:
		for k, val := range t {
			t[k] = normalizeNumbers(val)
		}
		return t
	case []interface{}:
		for i, val := range t {
			t[i] = normalizeNumbers(val)
		}
		return t
	default:
		return v
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
