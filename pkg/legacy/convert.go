// Package legacy converts historical (v1) policy documents into the
// normalized v2 PolicySet. Rules whose semantics are ambiguous or cannot
// be converted safely are rejected with a typed policy.LoadError instead
// of being silently dropped or downgraded to allow.
package legacy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lisama569/admission-policy-engine-go/pkg/policy"
)

// LegacyVersion is the only accepted historical document version.
const LegacyVersion = "v1"

// V1Document is the on-disk shape of a historical policy document.
type V1Document struct {
	Version string   `json:"version"`
	Name    string   `json:"name,omitempty"`
	Rules   []V1Rule `json:"rules"`
}

// V1Rule is a single legacy rule.
type V1Rule struct {
	Name       string                 `json:"name"`
	Action     string                 `json:"action"`
	Severity   string                 `json:"severity,omitempty"`
	TargetKind string                 `json:"targetKind,omitempty"`
	Selector   map[string]string      `json:"selector,omitempty"`
	Constraint *V1Constraint          `json:"constraint,omitempty"`
	Extra      map[string]interface{} `json:"extra,omitempty"`
}

// V1Constraint is the legacy constraint expression.
type V1Constraint struct {
	Field string      `json:"field"`
	Op    string      `json:"op"`
	Value interface{} `json:"value"`
}

// supportedExtraKeys enumerates v1 "extra" keys whose meaning is known.
// An unknown extra key could silently change a rule's intent, so any
// document carrying one is rejected as ambiguous.
var supportedExtraKeys = map[string]struct{}{
	"message":     {},
	"description": {},
}

// ConvertDocument parses and converts a v1 document into a validated v2
// PolicySet. Conversion is all-or-nothing: the first rule that cannot be
// converted safely fails the whole document with a *policy.LoadError whose
// Code distinguishes the reason.
func ConvertDocument(raw []byte) (*policy.PolicySet, error) {
	if !json.Valid(raw) {
		return nil, &policy.LoadError{Code: policy.ErrInvalidJSON,
			Message: "legacy document is not valid JSON"}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var doc V1Document
	if err := dec.Decode(&doc); err != nil {
		return nil, &policy.LoadError{Code: policy.ErrInvalidJSON,
			Message: err.Error()}
	}
	if strings.TrimSpace(doc.Version) == "" {
		return nil, &policy.LoadError{Code: policy.ErrMissingVersion,
			Message: "legacy document has no version field"}
	}
	if doc.Version != LegacyVersion {
		return nil, &policy.LoadError{Code: policy.ErrUnsupportedVersion,
			Message: fmt.Sprintf("legacy converter expects %q, got %q", LegacyVersion, doc.Version)}
	}
	if len(doc.Rules) == 0 {
		return nil, &policy.LoadError{Code: policy.ErrInvalidValue,
			Message: "legacy document contains no rules"}
	}

	set := &policy.PolicySet{
		Version:       policy.CurrentVersion,
		Name:          doc.Name,
		DefaultEffect: policy.EFFECT_DENY, // v1 had no explicit default; fail closed
		Rules:         make([]policy.Rule, 0, len(doc.Rules)),
	}
	for i, vr := range doc.Rules {
		converted, err := convertRule(vr, i)
		if err != nil {
			return nil, err
		}
		set.Rules = append(set.Rules, converted)
	}
	if err := set.Validate(); err != nil {
		return nil, err
	}
	return set, nil
}

// convertRule normalizes one v1 rule. Error Path pins the failure to
// rules[index] so callers can report exactly which legacy rule was unsafe.
func convertRule(rule V1Rule, index int) (policy.Rule, error) {
	path := fmt.Sprintf("rules[%d]", index)
	if strings.TrimSpace(rule.Name) == "" {
		return policy.Rule{}, &policy.LoadError{Code: policy.ErrMissingRuleID, Path: path,
			Message: "legacy rule requires a name"}
	}

	prio, err := severityPriority(rule.Severity)
	if err != nil {
		return policy.Rule{}, &policy.LoadError{Code: policy.ErrAmbiguousLegacyRule, Path: path, Message: err.Error()}
	}

	out := policy.Rule{
		ID:          "legacy-" + rule.Name,
		Priority:    prio,
		Description: legacyDescription(rule),
	}
	if msg, ok := rule.Extra["message"].(string); ok {
		out.Message = msg
	}
	if desc, ok := rule.Extra["description"].(string); ok {
		if out.Description == "" {
			out.Description = desc
		}
	}
	for key := range rule.Extra {
		if _, known := supportedExtraKeys[key]; !known {
			return policy.Rule{}, &policy.LoadError{
				Code: policy.ErrAmbiguousLegacyRule, Path: path,
				Message: fmt.Sprintf("legacy rule %q carries unsupported extra key %q with undefined semantics", rule.Name, key)}
		}
	}

	effect, err := convertAction(rule.Action)
	if err != nil {
		return policy.Rule{}, &policy.LoadError{Code: policy.ErrInvalidLegacyAction, Path: path, Message: err.Error()}
	}
	out.Effect = effect

	if rule.TargetKind != "" {
		out.Match.All = append(out.Match.All, policy.Condition{
			Field: "kind", Operator: policy.OP_EQ, Value: rule.TargetKind,
		})
	}
	// Selector keys are sorted for reproducible (though order-independent)
	// output; each label selector is an AND condition.
	keys := make([]string, 0, len(rule.Selector))
	for k := range rule.Selector {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		out.Match.All = append(out.Match.All, policy.Condition{
			Field: "labels." + k, Operator: policy.OP_EQ, Value: rule.Selector[k],
		})
	}

	if rule.Constraint != nil {
		cond, negate, err := convertConstraint(rule.Constraint, path)
		if err != nil {
			return policy.Rule{}, err
		}
		if negate {
			out.Match.Not = append(out.Match.Not, cond)
		} else {
			out.Match.All = append(out.Match.All, cond)
		}
	}

	// A rule with no target kind, selector or constraint matched
	// everything in v1. That is a dangerous silent footgun in admission,
	// so it is rejected rather than converted into a universal effect.
	if len(out.Match.All) == 0 && len(out.Match.Not) == 0 {
		return policy.Rule{}, &policy.LoadError{Code: policy.ErrAmbiguousLegacyRule, Path: path,
			Message: fmt.Sprintf("legacy rule %q has no targetKind, selector or constraint; an unconditional rule is rejected", rule.Name)}
	}
	return out, nil
}

// convertAction maps v1 actions to v2 effects.
func convertAction(action string) (policy.Effect, error) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "permit", "allow":
		return policy.EFFECT_ALLOW, nil
	case "reject", "deny":
		return policy.EFFECT_DENY, nil
	case "warn", "warning":
		return policy.EFFECT_WARN, nil
	case "":
		return "", fmt.Errorf("legacy rule has no action")
	default:
		return "", fmt.Errorf("unknown legacy action %q (supported: permit/allow, reject/deny, warn)", action)
	}
}

// severityPriority maps the v1 qualitative severity scale to numeric
// priorities. An unrecognized non-empty severity is ambiguous and rejected.
func severityPriority(severity string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 30, nil
	case "high":
		return 20, nil
	case "medium", "":
		return 10, nil
	case "low":
		return 5, nil
	case "info":
		return 1, nil
	default:
		return 0, fmt.Errorf("unknown legacy severity %q (supported: critical/high/medium/low/info)", severity)
	}
}

// convertConstraint maps a v1 constraint to a v2 condition. negate=true
// means the condition must be placed into Match.Not (the v1
// "missing"/"absent" operator means "field does not exist").
func convertConstraint(c *V1Constraint, path string) (cond policy.Condition, negate bool, err error) {
	if strings.TrimSpace(c.Field) == "" {
		return policy.Condition{}, false, &policy.LoadError{Code: policy.ErrInvalidFieldPath, Path: path,
			Message: "legacy constraint has no field"}
	}
	switch strings.ToLower(strings.TrimSpace(c.Op)) {
	case "eq", "=", "==":
		cond, err := valueCondition(c, policy.OP_EQ, path)
		return cond, false, err
	case "ne", "!=":
		cond, err := valueCondition(c, policy.OP_NE, path)
		return cond, false, err
	case "gt", ">":
		cond, err := valueCondition(c, policy.OP_GT, path)
		return cond, false, err
	case "gte", ">=":
		cond, err := valueCondition(c, policy.OP_GTE, path)
		return cond, false, err
	case "lt", "<":
		cond, err := valueCondition(c, policy.OP_LT, path)
		return cond, false, err
	case "lte", "<=":
		cond, err := valueCondition(c, policy.OP_LTE, path)
		return cond, false, err
	case "in":
		values, err := asList(c.Value)
		if err != nil {
			return policy.Condition{}, false, &policy.LoadError{Code: policy.ErrInvalidValue, Path: path, Message: err.Error()}
		}
		return policy.Condition{Field: c.Field, Operator: policy.OP_IN, Values: values}, false, nil
	case "notin":
		values, err := asList(c.Value)
		if err != nil {
			return policy.Condition{}, false, &policy.LoadError{Code: policy.ErrInvalidValue, Path: path, Message: err.Error()}
		}
		return policy.Condition{Field: c.Field, Operator: policy.OP_NOT_IN, Values: values}, false, nil
	case "exists", "present":
		return policy.Condition{Field: c.Field, Operator: policy.OP_EXISTS}, false, nil
	case "missing", "absent":
		if c.Value != nil {
			return policy.Condition{}, false, &policy.LoadError{Code: policy.ErrInvalidValue, Path: path,
				Message: "legacy op missing/absent must not carry a value"}
		}
		return policy.Condition{Field: c.Field, Operator: policy.OP_EXISTS}, true, nil
	case "like", "glob":
		cond, err := convertLike(c, path)
		return cond, false, err
	case "regex", "regexp", "match":
		return policy.Condition{}, false, &policy.LoadError{Code: policy.ErrUnsupportedLegacyOp, Path: path,
			Message: fmt.Sprintf("legacy op %q has no safe structural equivalent in v2", c.Op)}
	default:
		return policy.Condition{}, false, &policy.LoadError{Code: policy.ErrUnsupportedLegacyOp, Path: path,
			Message: fmt.Sprintf("unknown legacy constraint op %q", c.Op)}
	}
}

// valueCondition builds a single-value condition, rejecting an absent
// constraint value (a v1 document that left value null is ambiguous).
func valueCondition(c *V1Constraint, op policy.Operator, path string) (policy.Condition, error) {
	if c.Value == nil {
		return policy.Condition{}, &policy.LoadError{Code: policy.ErrMissingValue, Path: path,
			Message: fmt.Sprintf("legacy constraint on %q with op %q has no value", c.Field, c.Op)}
	}
	return policy.Condition{Field: c.Field, Operator: op, Value: normalizeLegacyValue(c.Value)}, nil
}

// convertLike accepts only the safely translatable wildcard forms:
//   - "abc*" -> startsWith "abc"
//   - "*abc" -> contains "abc"
//
// Internal wildcards ("a*b"), middle-only patterns ("*a*") and regex-like
// escapes are rejected because v1 wildcard semantics are not formally
// specified and converting them would guess.
func convertLike(c *V1Constraint, path string) (policy.Condition, error) {
	pattern, ok := c.Value.(string)
	if !ok {
		return policy.Condition{}, &policy.LoadError{Code: policy.ErrInvalidValue, Path: path,
			Message: fmt.Sprintf("legacy op %q requires a string value", c.Op)}
	}
	star := strings.Count(pattern, "*")
	switch {
	case star == 0:
		return policy.Condition{Field: c.Field, Operator: policy.OP_EQ, Value: pattern}, nil
	case star == 1 && strings.HasSuffix(pattern, "*"):
		return policy.Condition{Field: c.Field, Operator: policy.OP_STARTS_WITH,
			Value: strings.TrimSuffix(pattern, "*")}, nil
	case star == 1 && strings.HasPrefix(pattern, "*"):
		return policy.Condition{Field: c.Field, Operator: policy.OP_CONTAINS,
			Value: strings.TrimPrefix(pattern, "*")}, nil
	default:
		return policy.Condition{}, &policy.LoadError{Code: policy.ErrAmbiguousLegacyRule, Path: path,
			Message: fmt.Sprintf("legacy wildcard pattern %q is not a safe prefix/suffix pattern", pattern)}
	}
}

func asList(v interface{}) ([]interface{}, error) {
	if v == nil {
		return nil, fmt.Errorf("list constraint has no value")
	}
	list, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected a JSON array, got %T", v)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("list constraint value is empty")
	}
	out := make([]interface{}, len(list))
	for i, item := range list {
		out[i] = normalizeLegacyValue(item)
	}
	return out, nil
}

func normalizeLegacyValue(v interface{}) interface{} {
	if n, ok := v.(float64); ok && n == float64(int64(n)) {
		return int64(n)
	}
	return v
}

func legacyDescription(rule V1Rule) string {
	if rule.Severity == "" {
		return ""
	}
	return "converted from v1 rule, severity=" + rule.Severity
}

// sortStrings is a tiny local sort to avoid pulling in sort for one call.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
