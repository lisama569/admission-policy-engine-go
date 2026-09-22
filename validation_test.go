package policy

import (
	"errors"
	"testing"
)

func validRule(id string) Rule {
	return Rule{ID: id, Priority: 1, Effect: EffectDeny,
		Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}}
}

func TestValidatePolicySet_Reasons(t *testing.T) {
	cases := []struct {
		name   string
		ps     PolicySet
		reason string
	}{
		{"empty-version", PolicySet{Rules: []Rule{validRule("r")}}, ErrReasonEmptyPolicyVersion},
		{"empty-rule-id", PolicySet{Version: "v", Rules: []Rule{{ID: "", Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"x"}}}}}}, ErrReasonEmptyRuleID},
		{"duplicate-id", PolicySet{Version: "v", Rules: []Rule{validRule("r"), validRule("r")}}, ErrReasonDuplicateRuleID},
		{"bad-effect", PolicySet{Version: "v", Rules: []Rule{{ID: "r", Effect: "maybe",
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"x"}}}}}}, ErrReasonInvalidEffect},
		{"bad-operator", PolicySet{Version: "v", Rules: []Rule{{ID: "r", Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: "regex", Values: []string{"x"}}}}}}, ErrReasonInvalidOperator},
		{"empty-field", PolicySet{Version: "v", Rules: []Rule{{ID: "r", Effect: EffectDeny,
			Conditions: []Condition{{Field: "", Op: OpEq, Values: []string{"x"}}}}}}, ErrReasonEmptyField},
		{"missing-value", PolicySet{Version: "v", Rules: []Rule{{ID: "r", Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq}}}}}, ErrReasonMissingValue},
		{"bad-glob", PolicySet{Version: "v", Rules: []Rule{{ID: "r", Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpMatches, Values: []string{"["}}}}}}, ErrReasonInvalidGlob},
		{"empty-conditions", PolicySet{Version: "v", Rules: []Rule{{ID: "r", Effect: EffectDeny}}}, ErrReasonEmptyConditions},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePolicySet(tc.ps)
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("want *ValidationError, got %v", err)
			}
			t.Logf("input=%+v => reason=%s detail=%q", tc.ps, ve.Reason, ve.Detail)
			if ve.Reason != tc.reason {
				t.Fatalf("want reason %s, got %s", tc.reason, ve.Reason)
			}
		})
	}
}

func TestUpdate_InvalidPolicyKeepsOldVersion(t *testing.T) {
	old := PolicySet{Version: "v1", Rules: []Rule{validRule("old-deny")}}
	e := mustEngine(t, old)

	// 多种非法更新：空版本、坏 effect、重复 ID、非法 glob。
	bad := []PolicySet{
		{Rules: []Rule{validRule("x")}},
		{Version: "v2", Rules: []Rule{{ID: "x", Effect: "nope",
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}}}},
		{Version: "v2", Rules: []Rule{validRule("dup"), validRule("dup")}},
		{Version: "v2", Rules: []Rule{{ID: "x", Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpMatches, Values: []string{"["}}}}}},
	}
	for i, ps := range bad {
		if err := e.Update(ps); err == nil {
			t.Fatalf("case %d: update must fail", i)
		} else {
			t.Logf("case %d rejected as expected: %v", i, err)
		}
		cur := e.Current()
		if cur.Version != "v1" || len(cur.Rules) != 1 || cur.Rules[0].ID != "old-deny" {
			t.Fatalf("case %d: old policy polluted: %+v", i, cur)
		}
	}

	// 合法更新整体生效。
	newPS := PolicySet{Version: "v2", Rules: []Rule{
		{ID: "new-allow", Priority: 1, Effect: EffectAllow,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	if err := e.Update(newPS); err != nil {
		t.Fatalf("valid update failed: %v", err)
	}
	cur := e.Current()
	t.Logf("after valid update: version=%s rules=%v", cur.Version, []string{cur.Rules[0].ID})
	if cur.Version != "v2" || cur.Rules[0].ID != "new-allow" {
		t.Fatalf("effective policy not switched")
	}
}

func TestCurrent_ReturnsDeepCopy(t *testing.T) {
	e := mustEngine(t, PolicySet{Version: "v1", Rules: []Rule{validRule("r")}})
	c := e.Current()
	c.Version = "tampered"
	c.Rules[0].ID = "tampered"
	c.Rules[0].Conditions[0].Values[0] = "Tampered"
	again := e.Current()
	if again.Version != "v1" || again.Rules[0].ID != "r" || again.Rules[0].Conditions[0].Values[0] != "Pod" {
		t.Fatalf("internal policy mutated through Current(): %+v", again)
	}
}
