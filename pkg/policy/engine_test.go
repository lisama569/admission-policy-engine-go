package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func mustParseSet(t *testing.T, raw string) *PolicySet {
	t.Helper()
	set, err := ParsePolicySet([]byte(raw))
	if err != nil {
		t.Fatalf("ParsePolicySet failed: %v", err)
	}
	return set
}

func TestEvaluate_DenyOverridesAllow(t *testing.T) {
	raw := `{
	  "version": "v2",
	  "name": "p",
	  "defaultEffect": "allow",
	  "rules": [
	    {"id":"allow-all","effect":"allow","priority":100,"match":{"all":[{"field":"kind","operator":"eq","value":"Deployment"}]}},
	    {"id":"deny-prod","effect":"deny","priority":1,"match":{"all":[{"field":"namespace","operator":"eq","value":"prod"}]}}
	  ]
	}`
	engine, err := NewEngine(mustParseSet(t, raw))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	r := &Resource{Kind: "Deployment", Namespace: "prod", Name: "web"}
	res := engine.Evaluate(r)
	t.Logf("input: kind=%s ns=%s; matched=%v; decision=%s; reason=%s",
		r.Kind, r.Namespace, res.Matched, res.Decision, res.Reason)
	if res.Decision != DECISION_DENY {
		t.Fatalf("want deny (deny outranks allow at any priority), got %s", res.Decision)
	}
	if len(res.Matched) != 2 || res.Matched[0].RuleID != "deny-prod" {
		t.Fatalf("deny-prod must be ranked first regardless of priority, got %+v", res.Matched)
	}
}

func TestEvaluate_PriorityWithinSameEffect(t *testing.T) {
	raw := `{
	  "version":"v2",
	  "defaultEffect":"deny",
	  "rules":[
	    {"id":"warn-low","effect":"warn","priority":1,"match":{"all":[{"field":"kind","operator":"eq","value":"ConfigMap"}]}},
	    {"id":"warn-high","effect":"warn","priority":99,"match":{"all":[{"field":"kind","operator":"eq","value":"ConfigMap"}]}}
	  ]
	}`
	engine, _ := NewEngine(mustParseSet(t, raw))
	res := engine.Evaluate(&Resource{Kind: "ConfigMap", Name: "cm"})
	t.Logf("matched order: %+v; decision=%s; reason=%s", res.Matched, res.Decision, res.Reason)
	if res.Decision != DECISION_WARN || res.Matched[0].RuleID != "warn-high" {
		t.Fatalf("higher-priority warn must win, got %+v", res.Matched)
	}
}

func TestEvaluate_TieBreaksByRuleID(t *testing.T) {
	// Same effect and priority, rules supplied in deliberately scrambled
	// order. The decision must be explainable via the rule ID tie-break.
	raw := `{
	  "version":"v2",
	  "defaultEffect":"deny",
	  "rules":[
	    {"id":"zzz-rule","effect":"deny","priority":5,"message":"later id",
	     "match":{"all":[{"field":"kind","operator":"eq","value":"Pod"}]}},
	    {"id":"aaa-rule","effect":"deny","priority":5,"message":"earlier id",
	     "match":{"all":[{"field":"kind","operator":"eq","value":"Pod"}]}}
	  ]
	}`
	engine, _ := NewEngine(mustParseSet(t, raw))
	res := engine.Evaluate(&Resource{Kind: "Pod", Name: "p"})
	t.Logf("tie-break matched: %+v; reason=%s", res.Matched, res.Reason)
	if res.Matched[0].RuleID != "aaa-rule" {
		t.Fatalf("lexicographically smallest rule id must win ties, got %s", res.Matched[0].RuleID)
	}
}

func TestEvaluate_LoadOrderIndependent(t *testing.T) {
	ruleA := `{"id":"a","effect":"deny","priority":10,"match":{"all":[{"field":"name","operator":"eq","value":"x"}]}}`
	ruleB := `{"id":"b","effect":"warn","priority":5,"match":{"all":[{"field":"name","operator":"eq","value":"x"}]}}`
	order1 := `{"version":"v2","defaultEffect":"allow","rules":[` + ruleA + "," + ruleB + `]}`
	order2 := `{"version":"v2","defaultEffect":"allow","rules":[` + ruleB + "," + ruleA + `]}`
	e1, _ := NewEngine(mustParseSet(t, order1))
	e2, _ := NewEngine(mustParseSet(t, order2))
	r := &Resource{Name: "x"}
	r1, r2 := e1.Evaluate(r), e2.Evaluate(r)
	if r1.Decision != r2.Decision || r1.Matched[0].RuleID != r2.Matched[0].RuleID {
		t.Fatalf("results depend on load order: %+v vs %+v", r1.Matched, r2.Matched)
	}
	t.Logf("both orders -> %s via %s; reason=%s", r1.Decision, r1.Matched[0].RuleID, r1.Reason)
}

func TestEvaluate_DefaultDenyWhenNothingMatches(t *testing.T) {
	raw := `{"version":"v2","rules":[{"id":"r1","effect":"allow","match":{"all":[{"field":"kind","operator":"eq","value":"Pod"}]}}]}`
	engine, _ := NewEngine(mustParseSet(t, raw))
	res := engine.Evaluate(&Resource{Kind: "Service", Name: "svc"})
	t.Logf("no-match decision=%s reason=%s", res.Decision, res.Reason)
	if res.Decision != DECISION_DENY {
		t.Fatalf("missing defaultEffect must fail closed with deny, got %s", res.Decision)
	}
}

func TestParse_RejectsInvalidDocuments(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		code LoadErrorCode
	}{
		{"bad json", `{not json`, ErrInvalidJSON},
		{"missing version", `{"rules":[]}`, ErrUnsupportedVersion},
		{"duplicate id", `{"version":"v2","rules":[
		   {"id":"x","effect":"deny","match":{}},
		   {"id":"x","effect":"allow","match":{}}]}`, ErrDuplicateRuleID},
		{"missing id", `{"version":"v2","rules":[{"effect":"deny","match":{}}]}`, ErrMissingRuleID},
		{"bad effect", `{"version":"v2","rules":[{"id":"r","effect":"maybe","match":{}}]}`, ErrInvalidEffect},
		{"bad operator", `{"version":"v2","rules":[{"id":"r","effect":"deny","match":{"all":[{"field":"kind","operator":"??","value":"Pod"}]}}]}`, ErrInvalidOperator},
		{"in without values", `{"version":"v2","rules":[{"id":"r","effect":"deny","match":{"all":[{"field":"kind","operator":"in"}]}}]}`, ErrMissingValue},
		{"unknown field", `{"version":"v2","sneaky":1,"rules":[]}`, ErrInvalidJSON},
		{"bad default", `{"version":"v2","defaultEffect":"banana","rules":[]}`, ErrDefaultEffectInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePolicySet([]byte(tc.raw))
			var le *LoadError
			if !errors.As(err, &le) {
				t.Fatalf("want *LoadError, got %v", err)
			}
			t.Logf("document rejected as expected: code=%s path=%s msg=%s", le.Code, le.Path, le.Message)
			if le.Code != tc.code {
				t.Fatalf("want code %s, got %s", tc.code, le.Code)
			}
		})
	}
}

func TestConditionOperators(t *testing.T) {
	r := &Resource{
		Kind:      "Pod",
		Namespace: "prod",
		Labels:    map[string]string{"app": "web", "tier": "fe"},
		Extra: map[string]interface{}{
			"spec.replicas": int64(3),
			"tags":          []interface{}{"a", "b"},
		},
	}
	cases := []struct {
		cond Condition
		want bool
	}{
		{Condition{Field: "kind", Operator: OP_IN, Values: []interface{}{"Pod", "Job"}}, true},
		{Condition{Field: "namespace", Operator: OP_NOT_IN, Values: []interface{}{"dev"}}, true},
		{Condition{Field: "spec.replicas", Operator: OP_GTE, Value: int64(3)}, true},
		{Condition{Field: "spec.replicas", Operator: OP_LT, Value: 5}, true},
		{Condition{Field: "labels.app", Operator: OP_EQ, Value: "web"}, true},
		{Condition{Field: "labels.missing", Operator: OP_EXISTS}, false},
		{Condition{Field: "labels.missing", Operator: OP_NOT_IN, Values: []interface{}{"x"}}, true},
		{Condition{Field: "tags", Operator: OP_CONTAINS, Value: "b"}, true},
		{Condition{Field: "kind", Operator: OP_STARTS_WITH, Value: "Po"}, true},
		{Condition{Field: "absent", Operator: OP_EQ, Value: "x"}, false},
	}
	for _, tc := range cases {
		got, err := evalCondition(r, tc.cond)
		if err != nil {
			t.Fatalf("operator %s: %v", tc.cond.Operator, err)
		}
		t.Logf("condition %s %v -> %v (want %v)", tc.cond.Field, tc.cond.Operator, got, tc.want)
		if got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.cond.Operator, got, tc.want)
		}
	}
}

func TestResultJSONShape(t *testing.T) {
	engine, _ := NewEngine(mustParseSet(t, `{"version":"v2","name":"n","rules":[
	  {"id":"r","effect":"warn","message":"m","match":{"all":[{"field":"kind","operator":"eq","value":"Pod"}]}}]}`))
	res := engine.Evaluate(&Resource{Kind: "Pod", Name: "p"})
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"decision":"warn"`) || !strings.Contains(string(data), `"ruleId":"r"`) {
		t.Fatalf("unexpected result json: %s", data)
	}
	t.Logf("result json: %s", data)
}
