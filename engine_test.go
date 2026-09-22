package policy

import (
	"encoding/json"
	"testing"
)

// logResult 打印评估输入、命中规则与判定依据，满足可解释性要求。
func logResult(t *testing.T, name string, r Resource, res Result) {
	t.Helper()
	input, _ := json.Marshal(r)
	t.Logf("[%s] input=%s", name, input)
	t.Logf("[%s] decision=%s policyVersion=%s winningRule=%q", name, res.Decision, res.PolicyVersion, res.WinningRule)
	for _, h := range res.Hits {
		t.Logf("[%s] hit rule=%s effect=%s priority=%d desc=%q", name, h.RuleID, h.Effect, h.Priority, h.Description)
		for _, mc := range h.MatchedConditions {
			t.Logf("[%s]   matched condition field=%s op=%s want=%v got=%q present=%v",
				name, mc.Field, mc.Op, mc.WantValues, mc.GotValue, mc.Present)
		}
	}
	t.Logf("[%s] reason=%s", name, res.Reason)
}

func mustEngine(t *testing.T, ps PolicySet) *Engine {
	t.Helper()
	e, err := NewEngine(ps)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	return e
}

func TestEvaluate_DenyWarnAllowPriority(t *testing.T) {
	ps := PolicySet{
		Version: "p-v1",
		Rules: []Rule{
			{ID: "allow-low", Priority: 10, Effect: EffectAllow,
				Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Deployment"}}}},
			{ID: "warn-mid", Priority: 50, Effect: EffectWarn,
				Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Deployment"}}}},
			{ID: "deny-high", Priority: 100, Effect: EffectDeny,
				Conditions: []Condition{{Field: "metadata.name", Op: OpMatches, Values: []string{"bad-*"}}}},
		},
	}
	e := mustEngine(t, ps)

	r := Resource{"kind": "Deployment", "metadata": map[string]any{"name": "bad-app"}}
	res := e.Evaluate(r)
	logResult(t, "deny-high-wins", r, res)
	if res.Decision != DecisionDeny || res.WinningRule != "deny-high" {
		t.Fatalf("want deny via deny-high, got %s via %q", res.Decision, res.WinningRule)
	}

	r2 := Resource{"kind": "Deployment", "metadata": map[string]any{"name": "good-app"}}
	res2 := e.Evaluate(r2)
	logResult(t, "warn-mid-wins", r2, res2)
	if res2.Decision != DecisionWarn || res2.WinningRule != "warn-mid" {
		t.Fatalf("want warn via warn-mid, got %s via %q", res2.Decision, res2.WinningRule)
	}
}

func TestEvaluate_SamePriorityEffectTieBreakIsDeterministic(t *testing.T) {
	// 三条规则同优先级且都命中，deny 必须压过 warn/allow，与加载顺序无关。
	mk := func(id string, effect Effect) Rule {
		return Rule{ID: id, Priority: 10, Effect: effect,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"ConfigMap"}}}}
	}
	orders := [][]Rule{
		{mk("a-allow", EffectAllow), mk("b-warn", EffectWarn), mk("c-deny", EffectDeny)},
		{mk("c-deny", EffectDeny), mk("b-warn", EffectWarn), mk("a-allow", EffectAllow)},
		{mk("b-warn", EffectWarn), mk("a-allow", EffectAllow), mk("c-deny", EffectDeny)},
	}
	r := Resource{"kind": "ConfigMap"}
	for i, rules := range orders {
		e := mustEngine(t, PolicySet{Version: "p", Rules: rules})
		res := e.Evaluate(r)
		logResult(t, "effect-tiebreak-order", r, res)
		if res.Decision != DecisionDeny || res.WinningRule != "c-deny" {
			t.Fatalf("order %d: want deny/c-deny, got %s/%q", i, res.Decision, res.WinningRule)
		}
	}
}

func TestEvaluate_SamePrioritySameEffectIDSorted(t *testing.T) {
	// 同优先级同效果时按规则 ID 字典序决胜，结果可复现。
	mk := func(id string) Rule {
		return Rule{ID: id, Priority: 5, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpIn, Values: []string{"Secret", "ConfigMap"}}}}
	}
	for _, rules := range [][]Rule{
		{mk("z-rule"), mk("a-rule"), mk("m-rule")},
		{mk("m-rule"), mk("z-rule"), mk("a-rule")},
	} {
		e := mustEngine(t, PolicySet{Version: "p", Rules: rules})
		r := Resource{"kind": "Secret"}
		res := e.Evaluate(r)
		logResult(t, "id-tiebreak", r, res)
		if res.WinningRule != "a-rule" {
			t.Fatalf("want a-rule, got %q", res.WinningRule)
		}
		if res.Hits[0].RuleID != "a-rule" || res.Hits[2].RuleID != "z-rule" {
			t.Fatalf("hits must be sorted by id, got %s,%s,%s", res.Hits[0].RuleID, res.Hits[1].RuleID, res.Hits[2].RuleID)
		}
	}
}

func TestEvaluate_DefaultAllowWhenNoRuleMatches(t *testing.T) {
	ps := PolicySet{Version: "p", Rules: []Rule{
		{ID: "only-secret", Priority: 1, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Secret"}}}},
	}}
	e := mustEngine(t, ps)
	r := Resource{"kind": "Pod"}
	res := e.Evaluate(r)
	logResult(t, "default-allow", r, res)
	if res.Decision != DecisionAllow {
		t.Fatalf("want default allow, got %s", res.Decision)
	}
	if len(res.Hits) != 0 || res.WinningRule != "" {
		t.Fatalf("want no hits and no winning rule")
	}
}

func TestEvaluate_OperatorsAndNestedFields(t *testing.T) {
	ps := PolicySet{
		Version: "p",
		Rules: []Rule{
			{ID: "exists-label", Priority: 10, Effect: EffectWarn,
				Conditions: []Condition{{Field: "metadata.labels.tier", Op: OpExists}}},
			{ID: "not-in-ns", Priority: 20, Effect: EffectDeny,
				Conditions: []Condition{{Field: "metadata.namespace", Op: OpNotIn, Values: []string{"default", "kube-system"}}}},
			{ID: "neq-kind", Priority: 30, Effect: EffectDeny,
				Conditions: []Condition{{Field: "kind", Op: OpNotEq, Values: []string{"Pod"}}}},
			{ID: "array-index", Priority: 40, Effect: EffectDeny,
				Conditions: []Condition{{Field: "spec.containers.0.image", Op: OpMatches, Values: []string{"*:latest"}}}},
		},
	}
	e := mustEngine(t, ps)

	r := Resource{
		"kind": "Deployment",
		"metadata": map[string]any{
			"namespace": "prod",
			"labels":    map[string]any{"tier": "frontend"},
		},
		"spec": map[string]any{
			"containers": []any{map[string]any{"image": "nginx:latest"}},
		},
	}
	res := e.Evaluate(r)
	logResult(t, "operators", r, res)
	// array-index 优先级最高（40）
	if res.Decision != DecisionDeny || res.WinningRule != "array-index" {
		t.Fatalf("want deny/array-index, got %s/%q", res.Decision, res.WinningRule)
	}
	if len(res.Hits) != 4 {
		t.Fatalf("want 4 hits, got %d", len(res.Hits))
	}
}
