package policy

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestConvertLegacyV1_Success(t *testing.T) {
	raw := []byte(`{
	  "version": "v1",
	  "rules": [
	    {"id": "old-permit", "action": "permit", "weight": 100, "match": {"kind": "Pod"}},
	    {"id": "old-reject", "action": "reject", "weight": 500, "match": {"namespace": "prod"}},
	    {"id": "old-flag",   "action": "flag",   "weight": 50,  "match": {"name": "edge-gw"}},
	    {"id": "old-label",  "action": "reject", "weight": 900,
	     "match": {"label": {"key": "env", "value": "legacy"}}}
	  ]
	}`)
	ps, err := ConvertLegacyV1(raw)
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}
	out, _ := json.MarshalIndent(ps, "", "  ")
	t.Logf("converted policy set:\n%s", out)
	if ps.Version != legacyNormalizedVersion || len(ps.Rules) != 4 {
		t.Fatalf("unexpected normalized set: version=%s rules=%d", ps.Version, len(ps.Rules))
	}

	want := map[string]struct {
		effect   Effect
		priority int
		field    string
		value    string
	}{
		"old-permit": {EffectAllow, 100, "kind", "Pod"},
		"old-reject": {EffectDeny, 500, "metadata.namespace", "prod"},
		"old-flag":   {EffectWarn, 50, "metadata.name", "edge-gw"},
		"old-label":  {EffectDeny, 900, "metadata.labels.env", "legacy"},
	}
	for _, r := range ps.Rules {
		w, ok := want[r.ID]
		if !ok {
			t.Fatalf("unexpected rule %s", r.ID)
		}
		if r.Effect != w.effect || r.Priority != w.priority {
			t.Fatalf("rule %s effect/priority mismatch: %s/%d", r.ID, r.Effect, r.Priority)
		}
		if len(r.Conditions) != 1 || r.Conditions[0].Field != w.field ||
			r.Conditions[0].Op != OpEq || len(r.Conditions[0].Values) != 1 ||
			r.Conditions[0].Values[0] != w.value {
			t.Fatalf("rule %s condition mismatch: %+v", r.ID, r.Conditions)
		}
	}

	// 归一后的规则必须真正参与评估：label 规则命中历史资源。
	e := mustEngine(t, ps)
	r := Resource{"kind": "Pod", "metadata": map[string]any{
		"namespace": "prod",
		"name":      "edge-gw",
		"labels":    map[string]any{"env": "legacy"},
	}}
	res := e.Evaluate(r)
	logResult(t, "legacy-evaluated", r, res)
	if res.Decision != DecisionDeny || res.WinningRule != "old-label" {
		t.Fatalf("want deny/old-label (weight 900), got %s/%q", res.Decision, res.WinningRule)
	}
	if len(res.Hits) != 4 {
		t.Fatalf("want all 4 legacy rules to match, got %d", len(res.Hits))
	}
}

func TestConvertLegacyV1_RejectionReasons(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		reason string
	}{
		{"unsupported-version", `{"version":"v2","rules":[]}`, ConvReasonUnsupportedVersion},
		{"missing-version", `{"rules":[]}`, ConvReasonUnsupportedVersion},
		{"unknown-top-field", `{"version":"v1","rules":[],"defaults":{}}`, ConvReasonUnknownTopField},
		{"unknown-rule-field", `{"version":"v1","rules":[{"id":"r","action":"permit","weight":1,"match":{"kind":"Pod"},"note":"x"}]}`, ConvReasonUnknownTopField},
		{"empty-id", `{"version":"v1","rules":[{"action":"permit","weight":1,"match":{"kind":"Pod"}}]}`, ConvReasonEmptyRuleID},
		{"unknown-action", `{"version":"v1","rules":[{"id":"r","action":"delete","weight":1,"match":{"kind":"Pod"}}]}`, ConvReasonUnknownAction},
		{"deprecated-advise", `{"version":"v1","rules":[{"id":"r","action":"advise","weight":1,"match":{"kind":"Pod"}}]}`, ConvReasonDeprecatedAction},
		{"missing-action", `{"version":"v1","rules":[{"id":"r","weight":1,"match":{"kind":"Pod"}}]}`, ConvReasonUnknownAction},
		{"missing-weight", `{"version":"v1","rules":[{"id":"r","action":"permit","match":{"kind":"Pod"}}]}`, ConvReasonInvalidWeight},
		{"weight-too-big", `{"version":"v1","rules":[{"id":"r","action":"permit","weight":1001,"match":{"kind":"Pod"}}]}`, ConvReasonInvalidWeight},
		{"weight-negative", `{"version":"v1","rules":[{"id":"r","action":"permit","weight":-1,"match":{"kind":"Pod"}}]}`, ConvReasonInvalidWeight},
		{"weight-float", `{"version":"v1","rules":[{"id":"r","action":"permit","weight":1.5,"match":{"kind":"Pod"}}]}`, ConvReasonInvalidWeight},
		{"missing-match", `{"version":"v1","rules":[{"id":"r","action":"permit","weight":1}]}`, ConvReasonMissingMatch},
		{"empty-match", `{"version":"v1","rules":[{"id":"r","action":"permit","weight":1,"match":{}}]}`, ConvReasonMissingMatch},
		{"ambiguous-two-selectors", `{"version":"v1","rules":[{"id":"r","action":"permit","weight":1,"match":{"kind":"Pod","namespace":"prod"}}]}`, ConvReasonAmbiguousMatch},
		{"unknown-selector", `{"version":"v1","rules":[{"id":"r","action":"permit","weight":1,"match":{"annotations":"x"}}]}`, ConvReasonUnknownMatchField},
		{"label-missing-value", `{"version":"v1","rules":[{"id":"r","action":"permit","weight":1,"match":{"label":{"key":"env"}}}]}`, ConvReasonAmbiguousMatch},
		{"label-unknown-field", `{"version":"v1","rules":[{"id":"r","action":"permit","weight":1,"match":{"label":{"key":"env","value":"x","op":"eq"}}}]}`, ConvReasonAmbiguousMatch},
		{"label-empty-key", `{"version":"v1","rules":[{"id":"r","action":"permit","weight":1,"match":{"label":{"key":"","value":"x"}}}]}`, ConvReasonAmbiguousMatch},
		{"duplicate-legacy-id", `{"version":"v1","rules":[
		   {"id":"r","action":"permit","weight":1,"match":{"kind":"Pod"}},
		   {"id":"r","action":"reject","weight":2,"match":{"kind":"Pod"}}]}`, ErrReasonDuplicateRuleID},
		{"invalid-json", `{"version":"v1","rules":[`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ConvertLegacyV1([]byte(tc.raw))
			if err == nil {
				t.Fatalf("conversion must fail for %s", tc.name)
			}
			var ce *ConversionError
			var ve *ValidationError
			switch {
			case errors.As(err, &ce):
				t.Logf("input=%s => conversion error reason=%s rule=%q detail=%q", tc.raw, ce.Reason, ce.LegacyRuleID, ce.Detail)
				if tc.reason == "" {
					return
				}
				if ce.Reason != tc.reason {
					t.Fatalf("want conversion reason %s, got %s", tc.reason, ce.Reason)
				}
			case errors.As(err, &ve):
				t.Logf("input=%s => post-normalize validation error reason=%s detail=%q", tc.raw, ve.Reason, ve.Detail)
				if ve.Reason != tc.reason {
					t.Fatalf("want validation reason %s, got %s", tc.reason, ve.Reason)
				}
			default:
				t.Logf("input=%s => generic error: %v (json parse case)", tc.raw, err)
				if tc.reason != "" {
					t.Fatalf("want typed error with reason %s, got generic: %v", tc.reason, err)
				}
			}
		})
	}
}

func TestConvertLegacyV1_DoesNotSilentlyPass(t *testing.T) {
	// 任何转换失败都不允许返回“空策略集=默认全放行”。
	raw := []byte(`{"version":"v1","rules":[{"id":"r","action":"mystery","weight":1,"match":{"kind":"Pod"}}]}`)
	ps, err := ConvertLegacyV1(raw)
	if err == nil {
		t.Fatalf("unknown action must be rejected")
	}
	if len(ps.Rules) != 0 || ps.Version != "" {
		t.Fatalf("failed conversion must return zero PolicySet, got %+v", ps)
	}
	t.Logf("correctly rejected with no partial policy: %v", err)
}
