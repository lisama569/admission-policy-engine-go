package legacy

import (
	"errors"
	"testing"

	"github.com/lisama569/admission-policy-engine-go/pkg/policy"
)

func loadLegacy(t *testing.T, raw string) *policy.PolicySet {
	t.Helper()
	set, err := ConvertDocument([]byte(raw))
	if err != nil {
		t.Fatalf("ConvertDocument: %v", err)
	}
	return set
}

func TestConvert_BasicNormalization(t *testing.T) {
	doc := `{
	  "version":"v1",
	  "name":"old",
	  "rules":[
	    {"name":"block-prod","action":"reject","severity":"critical",
	     "targetKind":"Deployment","selector":{"env":"prod"},
	     "constraint":{"field":"spec.replicas","op":">","value":5},
	     "extra":{"message":"too many replicas in prod"}}
	  ]
	}`
	set := loadLegacy(t, doc)
	if set.Version != "v2" || len(set.Rules) != 1 {
		t.Fatalf("unexpected converted set: %+v", set)
	}
	r := set.Rules[0]
	if r.ID != "legacy-block-prod" || r.Effect != policy.EFFECT_DENY || r.Priority != 30 {
		t.Fatalf("normalized rule wrong: %+v", r)
	}
	if len(r.Match.All) != 3 {
		t.Fatalf("want 3 AND conditions (kind/label/constraint), got %d", len(r.Match.All))
	}

	engine, err := policy.NewEngine(set)
	if err != nil {
		t.Fatal(err)
	}
	hit := &policy.Resource{Kind: "Deployment", Namespace: "x", Name: "d",
		Labels: map[string]string{"env": "prod"},
		Extra:  map[string]interface{}{"spec.replicas": int64(6)}}
	miss := &policy.Resource{Kind: "Deployment", Name: "d",
		Labels: map[string]string{"env": "prod"},
		Extra:  map[string]interface{}{"spec.replicas": int64(3)}}
	resHit := engine.Evaluate(hit)
	resMiss := engine.Evaluate(miss)
	t.Logf("converted rule %s conditions: %+v", r.ID, r.Match.All)
	t.Logf("hit input: replicas=6 -> %s; matched=%v; reason=%s",
		resHit.Decision, resHit.Matched, resHit.Reason)
	t.Logf("miss input: replicas=3 -> %s; reason=%s", resMiss.Decision, resMiss.Reason)
	if resHit.Decision != policy.DECISION_DENY || resMiss.Decision != policy.DECISION_DENY {
		t.Fatalf("miss should fall through to default deny; got hit=%s miss=%s",
			resHit.Decision, resMiss.Decision)
	}
}

func TestConvert_AllActionsAndOps(t *testing.T) {
	doc := `{
	  "version":"v1",
	  "rules":[
	    {"name":"permit-pods","action":"permit","targetKind":"Pod","constraint":{"field":"spec.x","op":"eq","value":"1"}},
	    {"name":"warn-jobs","action":"warning","targetKind":"Job","constraint":{"field":"spec.class","op":"in","value":["a","b"]}},
	    {"name":"deny-cm","action":"deny","targetKind":"ConfigMap","constraint":{"field":"name","op":"like","value":"secret-*"}},
	    {"name":"deny-svc","action":"reject","targetKind":"Service","constraint":{"field":"labels.owner","op":"missing"}}
	  ]
	}`
	set := loadLegacy(t, doc)
	engine, _ := policy.NewEngine(set)
	for _, r := range set.Rules {
		t.Logf("normalized: id=%s effect=%s priority=%d all=%d not=%d",
			r.ID, r.Effect, r.Priority, len(r.Match.All), len(r.Match.Not))
	}
	cases := []struct {
		r    *policy.Resource
		want policy.Decision
	}{
		{&policy.Resource{Kind: "Pod", Name: "p", Extra: map[string]interface{}{"spec.x": "1"}}, policy.DECISION_ALLOW},
		{&policy.Resource{Kind: "Job", Name: "j", Extra: map[string]interface{}{"spec.class": "b"}}, policy.DECISION_WARN},
		{&policy.Resource{Kind: "ConfigMap", Name: "secret-x"}, policy.DECISION_DENY},
		{&policy.Resource{Kind: "Service", Name: "s"}, policy.DECISION_DENY},
	}
	for _, tc := range cases {
		res := engine.Evaluate(tc.r)
		t.Logf("input kind=%s name=%s -> %s; matched=%v", tc.r.Kind, tc.r.Name, res.Decision, res.Matched)
		if res.Decision != tc.want {
			t.Fatalf("kind=%s: want %s got %s (%s)", tc.r.Kind, tc.want, res.Decision, res.Reason)
		}
	}
}

func TestConvert_RejectionReasonsAreDistinguishable(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		code policy.LoadErrorCode
	}{
		{"bad json", `{`, policy.ErrInvalidJSON},
		{"missing version", `{"rules":[]}`, policy.ErrMissingVersion},
		{"wrong version", `{"version":"v9","rules":[]}`, policy.ErrUnsupportedVersion},
		{"no rules", `{"version":"v1","rules":[]}`, policy.ErrInvalidValue},
		{"missing name", `{"version":"v1","rules":[{"action":"deny","targetKind":"Pod"}]}`, policy.ErrMissingRuleID},
		{"bad action", `{"version":"v1","rules":[{"name":"r","action":"explode","targetKind":"Pod"}]}`, policy.ErrInvalidLegacyAction},
		{"bad severity", `{"version":"v1","rules":[{"name":"r","action":"deny","severity":"super","targetKind":"Pod"}]}`, policy.ErrAmbiguousLegacyRule},
		{"unconditional rule", `{"version":"v1","rules":[{"name":"r","action":"deny"}]}`, policy.ErrAmbiguousLegacyRule},
		{"unsupported op regex", `{"version":"v1","rules":[{"name":"r","action":"deny","targetKind":"Pod","constraint":{"field":"x","op":"regex","value":".*"}}]}`, policy.ErrUnsupportedLegacyOp},
		{"unknown op", `{"version":"v1","rules":[{"name":"r","action":"deny","targetKind":"Pod","constraint":{"field":"x","op":"??","value":1}}]}`, policy.ErrUnsupportedLegacyOp},
		{"missing constraint value", `{"version":"v1","rules":[{"name":"r","action":"deny","targetKind":"Pod","constraint":{"field":"x","op":"eq"}}]}`, policy.ErrMissingValue},
		{"ambiguous internal wildcard", `{"version":"v1","rules":[{"name":"r","action":"deny","targetKind":"Pod","constraint":{"field":"x","op":"like","value":"a*b"}}]}`, policy.ErrAmbiguousLegacyRule},
		{"unknown extra key", `{"version":"v1","rules":[{"name":"r","action":"deny","targetKind":"Pod","extra":{"mystery":true}}]}`, policy.ErrAmbiguousLegacyRule},
		{"duplicate converted id", `{"version":"v1","rules":[
		  {"name":"dup","action":"deny","targetKind":"Pod"},
		  {"name":"dup","action":"allow","targetKind":"Service"}]}`, policy.ErrDuplicateRuleID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ConvertDocument([]byte(tc.raw))
			var le *policy.LoadError
			if !errors.As(err, &le) {
				t.Fatalf("want *LoadError, got %v", err)
			}
			if le.Code != tc.code {
				t.Fatalf("want code %s, got %s (%s)", tc.code, le.Code, le.Message)
			}
			t.Logf("REJECTED input=%s -> code=%s path=%s reason=%s", tc.name, le.Code, le.Path, le.Message)
		})
	}
}

func TestConvert_DefaultIsDenyNotAllow(t *testing.T) {
	// A converted set must never silently downgrade to allow: a Pod that
	// matches no converted rule must be denied by the converted default.
	set := loadLegacy(t, `{"version":"v1","rules":[
	  {"name":"only-jobs","action":"permit","targetKind":"Job"}]}`)
	engine, _ := policy.NewEngine(set)
	res := engine.Evaluate(&policy.Resource{Kind: "Pod", Name: "p"})
	t.Logf("unmatched resource -> %s: %s", res.Decision, res.Reason)
	if res.Decision != policy.DECISION_DENY {
		t.Fatal("legacy conversion must fail closed with default deny")
	}
}

func TestConvert_WildcardForms(t *testing.T) {
	set := loadLegacy(t, `{"version":"v1","rules":[
	  {"name":"prefix","action":"warn","targetKind":"Pod","constraint":{"field":"name","op":"glob","value":"tmp-*"}},
	  {"name":"suffix","action":"warn","targetKind":"Pod","constraint":{"field":"name","op":"glob","value":"*-tmp"}}
	]}`)
	engine, _ := policy.NewEngine(set)
	r1 := engine.Evaluate(&policy.Resource{Kind: "Pod", Name: "tmp-123"})
	r2 := engine.Evaluate(&policy.Resource{Kind: "Pod", Name: "abc-tmp"})
	r3 := engine.Evaluate(&policy.Resource{Kind: "Pod", Name: "other"})
	t.Logf("prefix hit=%v suffix hit=%v neither hits=%d", r1.Matched, r2.Matched, len(r3.Matched))
	if r1.Decision != policy.DECISION_WARN || r2.Decision != policy.DECISION_WARN {
		t.Fatal("prefix/suffix wildcard conversions must match")
	}
	if len(r3.Matched) != 0 || r3.Decision != policy.DECISION_DENY {
		t.Fatal("non-matching name must not hit wildcard rules")
	}
}
