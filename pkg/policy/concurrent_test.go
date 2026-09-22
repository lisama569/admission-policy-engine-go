package policy

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentEvaluation_MatchesSerial(t *testing.T) {
	raw := `{
	  "version":"v2",
	  "name":"concurrent",
	  "defaultEffect":"allow",
	  "rules":[
	    {"id":"deny-prod-pods","effect":"deny","priority":50,
	     "match":{"all":[{"field":"kind","operator":"eq","value":"Pod"},
	                     {"field":"namespace","operator":"eq","value":"prod"}]}},
	    {"id":"warn-canary","effect":"warn","priority":40,
	     "match":{"all":[{"field":"labels.track","operator":"eq","value":"canary"}]}},
	    {"id":"allow-dev","effect":"allow","priority":30,
	     "match":{"all":[{"field":"namespace","operator":"eq","value":"dev"}]}}
	  ]
	}`
	engine, err := NewEngine(mustParseSet(t, raw))
	if err != nil {
		t.Fatal(err)
	}

	resources := make([]*Resource, 0, 12)
	for _, ns := range []string{"prod", "dev", "staging"} {
		for _, kind := range []string{"Pod", "Service", "ConfigMap"} {
			for i := 0; i < 2; i++ {
				resources = append(resources, &Resource{
					Kind:      kind,
					Namespace: ns,
					Name:      fmt.Sprintf("%s-%s-%d", kind, ns, i),
					Labels:    map[string]string{"track": map[bool]string{true: "canary", false: "stable"}[i == 0 && kind == "Pod"]},
				})
			}
		}
	}

	// Serial baseline.
	serial := make([]Result, len(resources))
	for i, r := range resources {
		serial[i] = engine.Evaluate(r)
		t.Logf("serial input: kind=%s ns=%s labels=%v -> %s; hits=%d; reason=%s",
			r.Kind, r.Namespace, r.Labels, serial[i].Decision, len(serial[i].Matched), serial[i].Reason)
	}

	// Concurrent evaluation against the same immutable snapshot.
	const goroutines = 32
	var wg sync.WaitGroup
	var mismatch int64
	errCh := make(chan string, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for round := 0; round < 200; round++ {
				for i, r := range resources {
					got := engine.Evaluate(r)
					want := serial[i]
					if got.Decision != want.Decision || len(got.Matched) != len(want.Matched) {
						atomic.AddInt64(&mismatch, 1)
						errCh <- fmt.Sprintf("goroutine=%d round=%d resource=%s: got %s(%d hits) want %s(%d hits)",
							seed, round, r.Name, got.Decision, len(got.Matched), want.Decision, len(want.Matched))
						return
					}
					for k := range got.Matched {
						if got.Matched[k].RuleID != want.Matched[k].RuleID {
							atomic.AddInt64(&mismatch, 1)
							errCh <- fmt.Sprintf("hit ordering differs for %s: %+v vs %+v", r.Name, got.Matched, want.Matched)
							return
						}
					}
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Error(msg)
	}
	if atomic.LoadInt64(&mismatch) != 0 {
		t.Fatalf("concurrent results diverged from serial baseline: %d mismatches", mismatch)
	}
	t.Logf("all %d goroutines x 200 rounds matched serial baseline", goroutines)
}

func TestHotUpdate_AtomicVisibility(t *testing.T) {
	v1 := `{"version":"v2","name":"p","defaultEffect":"deny","rules":[
	  {"id":"v1-deny","effect":"deny","match":{"all":[{"field":"kind","operator":"eq","value":"Pod"}]}}]}`
	v2 := `{"version":"v2","name":"p","defaultEffect":"allow","rules":[
	  {"id":"v2-allow","effect":"allow","match":{"all":[{"field":"kind","operator":"eq","value":"Pod"}]}}]}`

	engine, err := NewEngine(mustParseSet(t, v1))
	if err != nil {
		t.Fatal(err)
	}
	r := &Resource{Kind: "Pod", Name: "p"}
	if got := engine.Evaluate(r).Decision; got != DECISION_DENY {
		t.Fatalf("initial snapshot: want deny, got %s", got)
	}

	// Hammer readers while one writer installs v2. Every read must return
	// a pure v1 result or a pure v2 result — never a half-merged state
	// (which would show up as unknown rule ids or mixed matched sets).
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var violations int64
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				res := engine.Evaluate(r)
				switch len(res.Matched) {
				case 1:
					id := res.Matched[0].RuleID
					if id != "v1-deny" && id != "v2-allow" {
						atomic.AddInt64(&violations, 1)
					}
					if (id == "v1-deny" && res.Decision != DECISION_DENY) ||
						(id == "v2-allow" && res.Decision != DECISION_ALLOW) {
						atomic.AddInt64(&violations, 1)
					}
				default:
					atomic.AddInt64(&violations, 1)
				}
			}
		}()
	}

	if err := engine.Update(mustParseSet(t, v2)); err != nil {
		t.Fatalf("valid update rejected: %v", err)
	}
	close(stop)
	wg.Wait()

	if v := atomic.LoadInt64(&violations); v != 0 {
		t.Fatalf("observed %d non-atomic/half-snapshot evaluations", v)
	}
	if engine.ActiveVersion() != 2 {
		t.Fatalf("version should be 2 after one successful update, got %d", engine.ActiveVersion())
	}
	if got := engine.Evaluate(r).Decision; got != DECISION_ALLOW {
		t.Fatalf("after update: want allow, got %s", got)
	}
	t.Log("every concurrent evaluation saw complete v1 or complete v2 snapshot")
}

func TestHotUpdate_InvalidCandidateRejectedWhole(t *testing.T) {
	good := `{"version":"v2","name":"p","defaultEffect":"deny","rules":[
	  {"id":"good-deny","effect":"deny","match":{"all":[{"field":"kind","operator":"eq","value":"Pod"}]}}]}`
	engine, _ := NewEngine(mustParseSet(t, good))
	before := engine.ActivePolicySet()

	invalidCandidates := []string{
		`{"version":"v2","rules":[{"id":"dup","effect":"deny","match":{}},{"id":"dup","effect":"allow","match":{}}]}`,
		`{"version":"v2","rules":[{"id":"x","effect":"nope","match":{}}]}`,
		`{"version":"v2","rules":[{"id":"x","effect":"deny","match":{"all":[{"field":"kind","operator":"bogus","value":"Pod"}]}}]}`,
	}
	for i, raw := range invalidCandidates {
		bad := mustParseSetAllowInvalid(t, raw)
		err := engine.Update(bad)
		var le *LoadError
		if !errors.As(err, &le) {
			t.Fatalf("candidate %d: want typed LoadError, got %v", i, err)
		}
		t.Logf("candidate %d rejected: code=%s path=%s msg=%s", i, le.Code, le.Path, le.Message)
		if engine.ActiveVersion() != 1 {
			t.Fatalf("rejected update changed version to %d", engine.ActiveVersion())
		}
		if engine.ActivePolicySet() != before {
			t.Fatalf("rejected update replaced the active snapshot pointer")
		}
	}
	res := engine.Evaluate(&Resource{Kind: "Pod", Name: "p"})
	if res.Decision != DECISION_DENY || len(res.Matched) != 1 || res.Matched[0].RuleID != "good-deny" {
		t.Fatalf("active policy was polluted by rejected updates: %+v", res)
	}
	t.Logf("active policy remains intact after %d rejected updates: %s", len(invalidCandidates), res.Reason)
}

func TestHotUpdate_NilCandidateRejected(t *testing.T) {
	engine, _ := NewEngine(mustParseSet(t, `{"version":"v2","rules":[]}`))
	if err := engine.Update(nil); err == nil {
		t.Fatal("nil update must be rejected")
	} else {
		t.Logf("nil update rejected: %v", err)
	}
	if engine.ActiveVersion() != 1 {
		t.Fatal("version changed after nil update")
	}
}

func TestUpdate_CallerMutationCannotAffectEngine(t *testing.T) {
	set := mustParseSet(t, `{"version":"v2","defaultEffect":"allow","rules":[
	  {"id":"r","effect":"deny","match":{"all":[{"field":"kind","operator":"eq","value":"Pod"}]}}]}`)
	engine, _ := NewEngine(set)
	// Mutate the caller's copy after installation.
	set.Rules[0].Effect = EFFECT_ALLOW
	res := engine.Evaluate(&Resource{Kind: "Pod", Name: "p"})
	if res.Decision != DECISION_DENY {
		t.Fatalf("caller mutation leaked into frozen snapshot: %s", res.Reason)
	}
	t.Logf("frozen snapshot unaffected by caller mutation: %s", res.Reason)
}

func mustParseSetAllowInvalid(t *testing.T, raw string) *PolicySet {
	t.Helper()
	// ParsePolicySet rejects; build the invalid set straight from JSON to
	// prove Update performs its own whole-set validation.
	var set PolicySet
	if err := unmarshalLoose([]byte(raw), &set); err != nil {
		t.Fatalf("fixture decode: %v", err)
	}
	return &set
}
