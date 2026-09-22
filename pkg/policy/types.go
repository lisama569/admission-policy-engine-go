// Package policy defines the core domain model of the admission policy
// engine: resources, rules, policy sets, evaluation results and errors.
package policy

import "strings"

// Effect is the decision a single rule produces when it matches.
//
// Effects are ordered by strength: EFFECT_DENY > EFFECT_WARN > EFFECT_ALLOW.
// When several rules match the same resource the strongest effect wins.
type Effect string

const (
	// EFFECT_ALLOW permits the resource.
	EFFECT_ALLOW Effect = "allow"
	// EFFECT_WARN admits the resource but attaches a warning.
	EFFECT_WARN Effect = "warn"
	// EFFECT_DENY rejects the resource.
	EFFECT_DENY Effect = "deny"
)

// effectStrength implements the total order deny > warn > allow.
func effectStrength(e Effect) int {
	switch e {
	case EFFECT_DENY:
		return 3
	case EFFECT_WARN:
		return 2
	case EFFECT_ALLOW:
		return 1
	default:
		return 0
	}
}

// Operator is the comparison operator used by a single match condition.
type Operator string

const (
	OP_EQ          Operator = "eq"
	OP_NE          Operator = "ne"
	OP_IN          Operator = "in"
	OP_NOT_IN      Operator = "notIn"
	OP_EXISTS      Operator = "exists"
	OP_GT          Operator = "gt"
	OP_GTE         Operator = "gte"
	OP_LT          Operator = "lt"
	OP_LTE         Operator = "lte"
	OP_CONTAINS    Operator = "contains"
	OP_STARTS_WITH Operator = "startsWith"
)

// Resource is the object submitted for admission.
//
// APIVersion/Kind/Namespace/Name are the core identity fields. Labels and
// Annotations are string maps. Spec (and any other data) lives in Extra,
// keyed by dotted field path (for example "spec.replicas").
type Resource struct {
	APIVersion  string                 `json:"apiVersion"`
	Kind        string                 `json:"kind"`
	Namespace   string                 `json:"namespace"`
	Name        string                 `json:"name"`
	Labels      map[string]string      `json:"labels,omitempty"`
	Annotations map[string]string      `json:"annotations,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

// Field resolves a dotted field path against the resource.
//
// Core fields ("apiVersion", "kind", "namespace", "name") are read
// directly; "labels.<k>" and "annotations.<k>" read the corresponding
// maps; bare "labels"/"annotations" return the whole map. Any other path
// is looked up in Extra, walking nested maps segment by segment and
// falling back to the full path as a flat key. ok reports whether the
// field exists (an explicit nil value counts as existing).
func (r *Resource) Field(path string) (value interface{}, ok bool) {
	switch path {
	case "apiVersion":
		return r.APIVersion, true
	case "kind":
		return r.Kind, true
	case "namespace":
		return r.Namespace, true
	case "name":
		return r.Name, true
	case "labels":
		return labelsAsInterface(r.Labels), r.Labels != nil
	case "annotations":
		return annotationsAsInterface(r.Annotations), r.Annotations != nil
	}
	if strings.HasPrefix(path, "labels.") {
		key := strings.TrimPrefix(path, "labels.")
		if key == "" {
			return nil, false
		}
		v, found := r.Labels[key]
		if !found {
			return nil, false
		}
		return v, true
	}
	if strings.HasPrefix(path, "annotations.") {
		key := strings.TrimPrefix(path, "annotations.")
		if key == "" {
			return nil, false
		}
		v, found := r.Annotations[key]
		if !found {
			return nil, false
		}
		return v, true
	}
	if r.Extra != nil {
		if v, found := r.Extra[path]; found {
			return v, true
		}
		segments := strings.Split(path, ".")
		var cur interface{} = r.Extra
		for _, seg := range segments {
			m, isMap := cur.(map[string]interface{})
			if !isMap {
				return nil, false
			}
			v, found := m[seg]
			if !found {
				return nil, false
			}
			cur = v
		}
		return cur, true
	}
	return nil, false
}

func labelsAsInterface(m map[string]string) interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func annotationsAsInterface(m map[string]string) interface{} {
	return labelsAsInterface(m)
}

// Condition is a single field-level predicate.
type Condition struct {
	Field    string        `json:"field"`
	Operator Operator      `json:"operator"`
	Value    interface{}   `json:"value,omitempty"`
	Values   []interface{} `json:"values,omitempty"`
}

// Match groups conditions with AND (All), OR (Any) and NOT (Not) semantics.
// A zero Match matches every resource.
type Match struct {
	All []Condition `json:"all,omitempty"`
	Any []Condition `json:"any,omitempty"`
	Not []Condition `json:"not,omitempty"`
}

// Rule is a single admission rule in the normalized (v2) format.
type Rule struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	Priority    int    `json:"priority"`
	Effect      Effect `json:"effect"`
	Match       Match  `json:"match"`
	Message     string `json:"message,omitempty"`
}

// PolicySet is an immutable, validated collection of rules. Once returned
// by ParsePolicySet/Validate/loader.Load it must not be mutated while in
// use; Engine.Update performs its work on a fresh validated copy.
type PolicySet struct {
	Version       string `json:"version"`
	Name          string `json:"name,omitempty"`
	DefaultEffect Effect `json:"defaultEffect"`
	Rules         []Rule `json:"rules"`
}

// Decision is the final admission decision for a resource.
type Decision string

const (
	DECISION_ALLOW Decision = "allow"
	DECISION_WARN  Decision = "warn"
	DECISION_DENY  Decision = "deny"
)

// HitRule records one rule that matched a resource, in the deterministic
// order used to resolve the decision, so reports are reproducible.
type HitRule struct {
	RuleID      string `json:"ruleId"`
	Effect      Effect `json:"effect"`
	Priority    int    `json:"priority"`
	Message     string `json:"message,omitempty"`
	Description string `json:"description,omitempty"`
}

// Result is the fully explained outcome of evaluating one resource.
type Result struct {
	Decision      Decision  `json:"decision"`
	Matched       []HitRule `json:"matched"`
	Reason        string    `json:"reason"`
	PolicyName    string    `json:"policyName,omitempty"`
	PolicyVersion string    `json:"policyVersion,omitempty"`
}

// LoadErrorCode enumerates the distinguishable reasons for which a policy
// document or a legacy rule can be rejected.
type LoadErrorCode string

const (
	ErrInvalidJSON          LoadErrorCode = "INVALID_JSON"
	ErrUnsupportedVersion   LoadErrorCode = "UNSUPPORTED_VERSION"
	ErrMissingVersion       LoadErrorCode = "MISSING_VERSION"
	ErrDuplicateRuleID      LoadErrorCode = "DUPLICATE_RULE_ID"
	ErrInvalidEffect        LoadErrorCode = "INVALID_EFFECT"
	ErrInvalidOperator      LoadErrorCode = "INVALID_OPERATOR"
	ErrInvalidFieldPath     LoadErrorCode = "INVALID_FIELD_PATH"
	ErrMissingRuleID        LoadErrorCode = "MISSING_RULE_ID"
	ErrInvalidValue         LoadErrorCode = "INVALID_VALUE"
	ErrMissingValue         LoadErrorCode = "MISSING_VALUE"
	ErrInvalidLegacyAction  LoadErrorCode = "INVALID_LEGACY_ACTION"
	ErrAmbiguousLegacyRule  LoadErrorCode = "AMBIGUOUS_LEGACY_RULE"
	ErrUnsupportedLegacyOp  LoadErrorCode = "UNSUPPORTED_LEGACY_OPERATOR"
	ErrDefaultEffectInvalid LoadErrorCode = "DEFAULT_EFFECT_INVALID"
)

// LoadError is a typed validation error. Code is machine-distinguishable;
// Path identifies the offending rule/field when known.
type LoadError struct {
	Code    LoadErrorCode
	Path    string
	Message string
}

func (e *LoadError) Error() string {
	if e.Path != "" {
		return string(e.Code) + " at " + e.Path + ": " + e.Message
	}
	return string(e.Code) + ": " + e.Message
}

// Ensure LoadError satisfies error at compile time.
var _ error = (*LoadError)(nil)
