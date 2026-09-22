package policy

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
)

// 串行基准：给定一组资源，逐版本评估并记录结论。
func serialEvaluate(t *testing.T, versions []PolicySet, resources []Resource) map[string][]Result {
	t.Helper()
	got := make(map[string][]Result, len(versions))
	for _, ps := range versions {
		e := mustEngine(t, ps)
		for _, r := range resources {
			got[ps.Version] = append(got[ps.Version], e.Evaluate(r))
		}
	}
	return got
}

func TestConcurrentEvaluation_MatchesSerial(t *testing.T) {
	ps := PolicySet{
		Version: "p-1",
		Rules: []Rule{
			{ID: "deny-prod", Priority: 100, Effect: EffectDeny,
				Conditions: []Condition{
					{Field: "metadata.namespace", Op: OpEq, Values: []string{"prod"}},
					{Field: "kind", Op: OpIn, Values: []string{"Deployment", "StatefulSet"}},
				}},
			{ID: "warn-latest", Priority: 50, Effect: EffectWarn,
				Conditions: []Condition{{Field: "spec.containers.0.image", Op: OpMatches, Values: []string{"*:latest"}}}},
			{ID: "allow-pods", Priority: 10, Effect: EffectAllow,
				Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
		},
	}
	e := mustEngine(t, ps)

	resources := []Resource{
		{"kind": "Deployment", "metadata": map[string]any{"namespace": "prod"},
			"spec": map[string]any{"containers": []any{map[string]any{"image": "nginx:1.25"}}}},
		{"kind": "Pod", "metadata": map[string]any{"namespace": "dev"},
			"spec": map[string]any{"containers": []any{map[string]any{"image": "busybox:latest"}}}},
		{"kind": "StatefulSet", "metadata": map[string]any{"namespace": "staging"},
			"spec": map[string]any{"containers": []any{map[string]any{"image": "redis:latest"}}}},
		{"kind": "ConfigMap", "metadata": map[string]any{"namespace": "dev"}},
	}
	baseline := serialEvaluate(t, []PolicySet{ps}, resources)["p-1"]

	const goroutines = 64
	const iterations = 200
	var wg sync.WaitGroup
	var mismatches int64
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for n := 0; n < iterations; n++ {
				for i, r := range resources {
					res := e.Evaluate(r)
					want := baseline[i]
					if res.Decision != want.Decision || res.WinningRule != want.WinningRule ||
						len(res.Hits) != len(want.Hits) || res.PolicyVersion != want.PolicyVersion {
						atomic.AddInt64(&mismatches, 1)
						in, _ := json.Marshal(r)
						t.Errorf("goroutine %d iter %d resource %d: concurrent=%+v serial=%+v input=%s",
							id, n, i, res, want, in)
					}
					if n == 0 && g == 0 {
						logResult(t, "concurrent-sample", r, res)
					}
				}
			}
		}(g)
	}
	wg.Wait()
	if atomic.LoadInt64(&mismatches) != 0 {
		t.Fatalf("concurrent results diverged from serial: %d mismatches", mismatches)
	}
	t.Logf("concurrent evaluation: %d goroutines x %d iterations x %d resources, all match serial baseline",
		goroutines, iterations, len(resources))
}

func TestHotUpdate_AtomicVisibility(t *testing.T) {
	// 两个版本规则差异明显，结论可直接区分。
	v1 := PolicySet{Version: "v1", Rules: []Rule{
		{ID: "v1-deny", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	v2 := PolicySet{Version: "v2", Rules: []Rule{
		{ID: "v2-warn", Priority: 100, Effect: EffectWarn,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	v3 := PolicySet{Version: "v3", Rules: []Rule{
		{ID: "v3-allow-high", Priority: 100, Effect: EffectAllow,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}

	e := mustEngine(t, v1)
	r := Resource{"kind": "Pod"}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var observed int64

	// 持续评估：每次结果必须是某个完整版本，版本与结论必须自洽。
	validVersions := map[string]struct {
		decision Decision
		winner   string
	}{
		"v1": {DecisionDeny, "v1-deny"},
		"v2": {DecisionWarn, "v2-warn"},
		"v3": {DecisionAllow, "v3-allow-high"},
	}
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					res := e.Evaluate(r)
					want, ok := validVersions[res.PolicyVersion]
					if !ok {
						t.Errorf("observed torn/unknown version %q", res.PolicyVersion)
						return
					}
					if res.Decision != want.decision || res.WinningRule != want.winner {
						t.Errorf("version/decision inconsistency: version=%s decision=%s winner=%s",
							res.PolicyVersion, res.Decision, res.WinningRule)
						return
					}
					atomic.AddInt64(&observed, 1)
				}
			}
		}()
	}

	// 更新方交替推送合法/非法版本；非法更新必须被整体拒绝。
	for i := 0; i < 200; i++ {
		switch i % 4 {
		case 0:
			if err := e.Update(v2); err != nil {
				t.Fatalf("v2 update: %v", err)
			}
		case 1:
			bad := PolicySet{Version: "", Rules: v2.Rules}
			if err := e.Update(bad); err == nil {
				t.Fatal("invalid empty-version update must be rejected")
			}
		case 2:
			if err := e.Update(v3); err != nil {
				t.Fatalf("v3 update: %v", err)
			}
		case 3:
			bad := PolicySet{Version: "bad", Rules: []Rule{{ID: "broken", Effect: EffectDeny,
				Conditions: []Condition{{Field: "kind", Op: OpMatches, Values: []string{"["}}}}}}
			if err := e.Update(bad); err == nil {
				t.Fatal("invalid glob update must be rejected")
			}
		}
	}
	close(stop)
	wg.Wait()
	t.Logf("hot-update race: %d evaluations observed, every result was a complete consistent version", observed)

	final := e.Evaluate(r)
	logResult(t, "hot-update-final", r, final)
	// 最后一次推送（case 3）是非法更新，生效版本必须仍是 v3。
	if final.PolicyVersion != "v3" {
		t.Fatalf("invalid final update polluted policy: effective=%s", final.PolicyVersion)
	}
}
