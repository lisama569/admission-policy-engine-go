package policy

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// 本文件覆盖“候选必须先可用、才能进入预演/切换”的拦截：
//  1. 未就绪候选（nil、直接构造的零值 &Candidate{}、准备失败后留下的对象）
//     被 Rehearse 整份拒绝：不产出任何逐条结果、不会被当成空策略评估成放行；
//  2. 同一个候选在 Rehearse 与 Promote 上的“能不能用”判断完全一致；
//  3. 被拒调用不改动线上策略；并发热更新下整批预演仍固定在同一完整版本，
//     被拒调用不残留任何中间状态。

// liveDenyPolicy 是各用例共享的线上初始策略：Pod 一律 deny，便于验证
// “被拒之后线上结论一个字节都没变”。
func liveDenyPolicy() PolicySet {
	return PolicySet{Version: "live-1", Rules: []Rule{
		{ID: "live-deny-pod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
}

func sampleResources() []Resource {
	return []Resource{
		{"kind": "Pod", "metadata": map[string]any{"name": "p1", "namespace": "prod"}},
		{"kind": "Pod", "metadata": map[string]any{"name": "p2"}},
		{"kind": "ConfigMap", "metadata": map[string]any{"name": "cfg"}},
	}
}

func rehearsalErrorReason(t *testing.T, err error) string {
	t.Helper()
	var re *RehearsalError
	if !errors.As(err, &re) {
		t.Fatalf("want *RehearsalError, got %T: %v", err, err)
	}
	return re.Reason
}

// 未就绪候选（nil 与零值 &Candidate{}）必须被 Rehearse 整份拒绝：
// 报告为空、没有任何逐条结果，更不允许把它当空策略评估成全放行。
func TestRehearse_RejectsUnreadyCandidateWithoutAnyResults(t *testing.T) {
	e := mustEngine(t, liveDenyPolicy())
	resources := sampleResources()
	for _, r := range resources {
		logResult(t, "live-before", r, e.Evaluate(r))
	}

	cases := []struct {
		name       string
		candidate  *Candidate
		wantReason string
	}{
		{"nil-candidate", nil, ErrReasonCandidateUnavailable},
		// 外部包真实可写出的“没走准备流程”的对象：字段不可见但零值可取址。
		{"zero-value-candidate", &Candidate{}, ErrReasonCandidateNotPrepared},
		// 准备到一半夭折的形态：有来源痕迹但没走完校验，同样未就绪。
		{"half-baked-candidate", &Candidate{
			source: CandidateSource{Kind: CandidateFromCurrent},
			policy: PolicySet{},
		}, ErrReasonCandidateNotPrepared},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.candidate != nil && tc.candidate.Ready() {
				t.Fatalf("%s: Ready() must be false before preparation", tc.name)
			}

			rep, err := e.Rehearse(resources, tc.candidate)
			if err == nil {
				t.Fatalf("%s: Rehearse must reject unready candidate", tc.name)
			}
			if got := rehearsalErrorReason(t, err); got != tc.wantReason {
				t.Fatalf("%s: reason=%s want %s", tc.name, got, tc.wantReason)
			}
			t.Logf("[%s] rejected as expected: reason=%s detail=%q", tc.name, tc.wantReason, err)

			// 整份拒绝：不得有任何逐条结果、计数、版本，防止调用方误用零值报告。
			if rep.Items != nil || rep.ResourceCount != 0 ||
				rep.CurrentVersion != "" || rep.CandidateVersion != "" ||
				rep.Summary != (DiffSummary{}) {
				t.Fatalf("%s: rejected call must not yield partial/empty-policy results: %+v",
					tc.name, rep)
			}
		})
	}

	// 线上策略与评估结论必须完全不变（Pod 仍按 live-1 拒绝）。
	cur := e.Current()
	if cur.Version != "live-1" || len(cur.Rules) != 1 || cur.Rules[0].ID != "live-deny-pod" {
		t.Fatalf("live policy mutated by rejected rehearsals: %+v", cur)
	}
	for i, r := range resources {
		got := e.Evaluate(r)
		logResult(t, fmt.Sprintf("live-after-%d", i), r, got)
		if got.PolicyVersion != "live-1" {
			t.Fatalf("resource %d live version changed: %s", i, got.PolicyVersion)
		}
		if r["kind"] == "Pod" && got.Decision != DecisionDeny {
			t.Fatalf("resource %d: Pod must stay deny, got %s", i, got.Decision)
		}
	}
	t.Log("unready candidates rejected wholesale; no per-resource results; live policy untouched")
}

// 同一个候选对象在 Rehearse 与 Promote 上的可用性判断必须一致：
// 未就绪两边都拒（且 reason 一致），已就绪两边都接受，绝不能一边放行一边拒。
func TestCandidate_ReadinessParityBetweenRehearseAndPromote(t *testing.T) {
	e := mustEngine(t, liveDenyPolicy())
	resources := sampleResources()

	unready := []struct {
		name string
		c    *Candidate
	}{
		{"nil", nil},
		{"zero-value", &Candidate{}},
	}
	for _, u := range unready {
		t.Run("unready/"+u.name, func(t *testing.T) {
			_, rehearseErr := e.Rehearse(resources, u.c)
			promoteErr := e.Promote(u.c)
			if rehearseErr == nil || promoteErr == nil {
				t.Fatalf("%s: both Rehearse and Promote must reject", u.name)
			}
			rr := rehearsalErrorReason(t, rehearseErr)
			pr := rehearsalErrorReason(t, promoteErr)
			t.Logf("[%s] Rehearse reason=%s, Promote reason=%s", u.name, rr, pr)
			if rr != pr {
				t.Fatalf("%s: readiness judgment diverged: rehearse=%s promote=%s", u.name, rr, pr)
			}
			if v := e.Current().Version; v != "live-1" {
				t.Fatalf("%s: live version changed to %s after rejections", u.name, v)
			}
		})
	}

	// 已就绪合法候选：两边都接受，且 Promote 后逐条结论与 Rehearse 候选列一致。
	good := mustCandidate(t, PolicySet{Version: "cand-ok", Rules: []Rule{
		{ID: "cand-warn-pod", Priority: 100, Effect: EffectWarn,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}})
	if !good.Ready() {
		t.Fatal("prepared candidate must report Ready()==true")
	}
	rep, err := e.Rehearse(resources, good)
	if err != nil {
		t.Fatalf("Rehearse prepared candidate: %v", err)
	}
	t.Logf("\n%s", rep.Text())
	if err := e.Promote(good); err != nil {
		t.Fatalf("Promote prepared candidate: %v", err)
	}
	for i, r := range resources {
		live := e.Evaluate(r)
		logResult(t, fmt.Sprintf("parity-post-promote-%d", i), r, live)
		if !resultsEqual(rep.Items[i].Candidate, live) {
			t.Fatalf("resource %d: rehearse/promote diverged for prepared candidate", i)
		}
	}
	t.Log("readiness parity verified: unready rejected by both; prepared accepted by both")
}

// 被拒的预演调用在并发热更新下也不得残留中间状态：
// 不断对未就绪候选发起 Rehearse（全部必须失败、报告必须为空），
// 同时高频热更新；穿插进行的成功批量预演必须整批固定在单一完整版本上。
func TestRehearse_RejectedCallsLeaveNoStateUnderHotUpdate(t *testing.T) {
	e := mustEngine(t, liveDenyPolicy())
	resources := makePods(200)

	v1 := liveDenyPolicy()
	v2 := PolicySet{Version: "live-2", Rules: []Rule{
		{ID: "live-allow-pod", Priority: 100, Effect: EffectAllow,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	goodCand := mustCandidate(t, PolicySet{Version: "cand-x", Rules: []Rule{
		{ID: "cand-deny-all-pods", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}})
	validVersions := map[string]PolicySet{"live-1": v1, "live-2": v2}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 更新者：在两个完整版本之间高频切换。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = e.Update(v2)
				_ = e.Update(v1)
			}
		}
	}()

	// 拒绝者：反复用未就绪候选预演，必须次次整份拒绝、零残留。
	var rejected atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				rep, err := e.Rehearse(resources[:10], &Candidate{})
				if err == nil {
					t.Errorf("unready candidate unexpectedly accepted")
					return
				}
				if rehearsalErrorReason(t, err) != ErrReasonCandidateNotPrepared {
					t.Errorf("unexpected reason: %v", err)
					return
				}
				if rep.Items != nil || rep.ResourceCount != 0 {
					t.Errorf("rejected rehearsal left results: %+v", rep)
					return
				}
				rejected.Add(1)
			}
		}
	}()

	// 成功预演者：每一批都必须固定在同一个完整版本上，不新旧混用；
	// 候选列必须全部来自 cand-x，证明被拒调用没有污染候选/快照路径。
	var tornBatches atomic.Int64
	for iter := 0; iter < 300; iter++ {
		rep, err := e.Rehearse(resources, goodCand)
		if err != nil {
			t.Fatalf("valid rehearsal failed: %v", err)
		}
		pinned, ok := validVersions[rep.CurrentVersion]
		if !ok {
			t.Fatalf("batch pinned to unknown/torn version %q", rep.CurrentVersion)
		}
		for i, d := range rep.Items {
			if d.Current.PolicyVersion != rep.CurrentVersion {
				t.Fatalf("iter %d item %d: torn batch version %s vs %s",
					iter, i, d.Current.PolicyVersion, rep.CurrentVersion)
			}
			want := evaluatePolicySet(pinned, resources[i])
			if !resultsEqual(d.Current, want) {
				t.Fatalf("iter %d item %d: current column not recomputable from pinned %s",
					iter, i, rep.CurrentVersion)
			}
			if d.Candidate.PolicyVersion != "cand-x" {
				t.Fatalf("iter %d item %d: candidate column polluted: %s",
					iter, i, d.Candidate.PolicyVersion)
			}
		}
		tornBatches.Add(1)
	}
	close(stop)
	wg.Wait()

	t.Logf("concurrency check: %d valid batches each pinned to one complete version, "+
		"%d unready rehearsals rejected with no residual state", tornBatches.Load(), rejected.Load())
	if rejected.Load() == 0 {
		t.Fatal("rejector goroutine never ran; test did not exercise the race")
	}
}
