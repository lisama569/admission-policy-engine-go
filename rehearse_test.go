package policy

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// 预演候选结论与 Promote 生效后逐条一致。
func TestRehearse_MatchesPostPromoteEvaluation(t *testing.T) {
	current := PolicySet{Version: "cur-1", Rules: []Rule{
		{ID: "cur-deny-pod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	candPS := PolicySet{Version: "cand-1", Rules: []Rule{
		{ID: "cand-warn-pod", Priority: 100, Effect: EffectWarn,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
		{ID: "cand-deny-latest", Priority: 200, Effect: EffectDeny,
			Conditions: []Condition{{Field: "spec.containers.0.image", Op: OpMatches, Values: []string{"*:latest"}}}},
	}}
	e := mustEngine(t, current)
	cand, err := PrepareCandidate(candPS)
	if err != nil {
		t.Fatalf("PrepareCandidate: %v", err)
	}

	resources := []Resource{
		{"kind": "Pod", "metadata": map[string]any{"name": "p1"},
			"spec": map[string]any{"containers": []any{map[string]any{"image": "nginx:1.25"}}}},
		{"kind": "Pod", "metadata": map[string]any{"name": "p2"},
			"spec": map[string]any{"containers": []any{map[string]any{"image": "busybox:latest"}}}},
		{"kind": "Deployment", "metadata": map[string]any{"name": "d1"},
			"spec": map[string]any{"containers": []any{map[string]any{"image": "redis:latest"}}}},
		{"kind": "ConfigMap", "metadata": map[string]any{"name": "cfg"}},
	}

	report, err := e.Rehearse(resources, cand)
	if err != nil {
		t.Fatalf("Rehearse: %v", err)
	}
	t.Logf("\n%s", report.Text())
	if report.CurrentVersion != "cur-1" || report.CandidateVersion != "cand-1" {
		t.Fatalf("unexpected versions: %+v", report)
	}

	// 预演的"当前"列必须与生效中引擎逐条评估一致。
	for i, r := range resources {
		live := e.Evaluate(r)
		got := report.Items[i].Current
		if !resultsEqual(got, live) {
			t.Fatalf("item %d current column diverged from live eval:\nrehearse=%+v\nlive=%+v", i, got, live)
		}
	}

	// 切换后逐条评估必须与预演的"候选"列完全一致（结论、决胜、命中集合、版本）。
	if err := e.Promote(cand); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	for i, r := range resources {
		live := e.Evaluate(r)
		got := report.Items[i].Candidate
		logResult(t, "post-promote", r, live)
		if !resultsEqual(got, live) {
			t.Fatalf("item %d candidate column diverged from post-promote eval:\nrehearse=%+v\nlive=%+v", i, got, live)
		}
	}
}

// resultsEqual 比较两份结论在判定上的全部关键事实。
func resultsEqual(a, b Result) bool {
	if a.Decision != b.Decision || a.WinningRule != b.WinningRule || a.PolicyVersion != b.PolicyVersion {
		return false
	}
	if len(a.Hits) != len(b.Hits) {
		return false
	}
	ah := map[string]RuleHit{}
	for _, h := range a.Hits {
		ah[h.RuleID] = h
	}
	for _, h := range b.Hits {
		oa, ok := ah[h.RuleID]
		if !ok || oa.Effect != h.Effect || oa.Priority != h.Priority {
			return false
		}
	}
	return true
}

// 差异汇总计数与逐条依据（命中规则、决胜规则、差异原因）正确。
func TestRehearse_DiffSummaryAndPerItemBasis(t *testing.T) {
	// 当前：Pod 一律 deny。候选：Pod 降为 warn；带 latest 镜像的 deny；
	// 同结论但命中集合/决胜规则变化的场景用额外规则覆盖。
	current := PolicySet{Version: "cur", Rules: []Rule{
		{ID: "deny-pod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
		{ID: "warn-secret", Priority: 50, Effect: EffectWarn,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Secret"}}}},
	}}
	cand := mustCandidate(t, PolicySet{Version: "cand", Rules: []Rule{
		{ID: "warn-pod", Priority: 100, Effect: EffectWarn,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
		{ID: "deny-latest", Priority: 200, Effect: EffectDeny,
			Conditions: []Condition{{Field: "spec.containers.0.image", Op: OpMatches, Values: []string{"*:latest"}}}},
	}})
	e := mustEngine(t, current)

	podStable := Resource{"kind": "Pod", "metadata": map[string]any{"name": "a"},
		"spec": map[string]any{"containers": []any{map[string]any{"image": "nginx:1"}}}}
	podLatest := Resource{"kind": "Pod", "metadata": map[string]any{"name": "b"},
		"spec": map[string]any{"containers": []any{map[string]any{"image": "nginx:latest"}}}}
	deployLatest := Resource{"kind": "Deployment", "metadata": map[string]any{"name": "c"},
		"spec": map[string]any{"containers": []any{map[string]any{"image": "redis:latest"}}}}
	secret := Resource{"kind": "Secret", "metadata": map[string]any{"name": "s"}}
	cm := Resource{"kind": "ConfigMap", "metadata": map[string]any{"name": "x"}}
	resources := []Resource{podStable, podLatest, deployLatest, secret, cm}

	rep, err := e.Rehearse(resources, cand)
	if err != nil {
		t.Fatalf("Rehearse: %v", err)
	}
	t.Logf("\n%s", rep.Text())

	// [0] Pod 稳定镜像：deny -> warn
	// [1] Pod latest：deny(deny-pod) -> deny(deny-latest)，结论不变、依据变
	// [2] Deployment latest：allow -> deny
	// [3] Secret：当前 warn-secret 命中；候选无任何命中 -> warn -> allow
	// [4] ConfigMap：allow -> allow，无变化
	want := []struct {
		decision, reason bool
		from, to         Decision
		winnerFrom       string
		winnerTo         string
	}{
		{true, false, DecisionDeny, DecisionWarn, "deny-pod", "warn-pod"},
		{false, true, DecisionDeny, DecisionDeny, "deny-pod", "deny-latest"},
		{true, false, DecisionAllow, DecisionDeny, "", "deny-latest"},
		{true, false, DecisionWarn, DecisionAllow, "warn-secret", ""},
		{false, false, DecisionAllow, DecisionAllow, "", ""},
	}
	for i, w := range want {
		d := rep.Items[i]
		if d.DecisionChanged != w.decision || d.ReasonChanged != w.reason {
			t.Fatalf("item %d flags: got decision=%v reason=%v want %v/%v",
				i, d.DecisionChanged, d.ReasonChanged, w.decision, w.reason)
		}
		if d.Current.Decision != w.from || d.Candidate.Decision != w.to {
			t.Fatalf("item %d decisions: %s->%s want %s->%s",
				i, d.Current.Decision, d.Candidate.Decision, w.from, w.to)
		}
		if d.Current.WinningRule != w.winnerFrom || d.Candidate.WinningRule != w.winnerTo {
			t.Fatalf("item %d winners: %q->%q want %q->%q",
				i, d.Current.WinningRule, d.Candidate.WinningRule, w.winnerFrom, w.winnerTo)
		}
		if d.Reason == "" {
			t.Fatalf("item %d must carry a human-readable diff reason", i)
		}
		t.Logf("item %d (%s/%s): %s", i, d.Resource.Kind, d.Resource.Name, d.Reason)
	}

	s := rep.Summary
	if s.Total != 5 || s.Unchanged != 1 || s.DecisionChanged != 3 || s.ReasonChangedOnly != 1 {
		t.Fatalf("unexpected primary counts: %+v", s)
	}
	if s.AddedDeny != 1 || s.AllowToDeny != 1 || s.WarnToDeny != 0 {
		t.Fatalf("added deny counts wrong: %+v", s)
	}
	// deny->warn（新增告警）与 warn->allow（移除告警）各一；没有 deny->allow。
	if s.RemovedDeny != 1 || s.DenyToWarn != 1 || s.DenyToAllow != 0 {
		t.Fatalf("removed deny counts wrong: %+v", s)
	}
	if s.AddedWarn != 1 || s.AllowToWarn != 0 || s.RemovedWarn != 1 || s.WarnToAllow != 1 {
		t.Fatalf("warn counts wrong: %+v", s)
	}

	// 逐条依据：item[2] 的候选命中必须包含完整条件匹配事实。
	hits := rep.Items[2].Candidate.Hits
	if len(hits) != 1 || hits[0].RuleID != "deny-latest" ||
		hits[0].MatchedConditions[0].GotValue != "redis:latest" {
		t.Fatalf("item 2 candidate basis missing matched condition facts: %+v", hits)
	}
}

func mustCandidate(t *testing.T, ps PolicySet) *Candidate {
	t.Helper()
	c, err := PrepareCandidate(ps)
	if err != nil {
		t.Fatalf("PrepareCandidate: %v", err)
	}
	return c
}

// 预演期间线上热更新：整批仍固定在同一个当前版本，不新旧混用。
func TestRehearse_PinnedAcrossHotUpdate(t *testing.T) {
	v1 := PolicySet{Version: "v1", Rules: []Rule{
		{ID: "v1-deny-pod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	v2 := PolicySet{Version: "v2", Rules: []Rule{
		{ID: "v2-allow-pod", Priority: 100, Effect: EffectAllow,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	cand := mustCandidate(t, PolicySet{Version: "cand", Rules: []Rule{
		{ID: "c-warn-pod", Priority: 100, Effect: EffectWarn,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}})
	e := mustEngine(t, v1)

	resources := makePods(400)
	sets := map[string]PolicySet{"v1": v1, "v2": v2}

	var rep RehearsalReport
	var repErr error
	done := make(chan struct{})
	go func() {
		rep, repErr = e.Rehearse(resources, cand)
		close(done)
	}()
	// 在预演进行期间高频交替热更新。
updater:
	for {
		select {
		case <-done:
			break updater
		default:
			if err := e.Update(v2); err != nil {
				t.Fatalf("update v2: %v", err)
			}
			if err := e.Update(v1); err != nil {
				t.Fatalf("update v1: %v", err)
			}
		}
	}
	if repErr != nil {
		t.Fatalf("Rehearse: %v", repErr)
	}

	// 整份报告必须固定在某一个完整版本上。
	pinnedVer := rep.CurrentVersion
	pinned, ok := sets[pinnedVer]
	if !ok {
		t.Fatalf("report pinned to unknown/torn version %q", pinnedVer)
	}
	for i, d := range rep.Items {
		if d.Current.PolicyVersion != pinnedVer {
			t.Fatalf("item %d used version %s while batch pinned %s (torn batch)",
				i, d.Current.PolicyVersion, pinnedVer)
		}
		// 用固定版本的策略集做纯函数复算，必须与报告"当前"列逐条一致。
		want := evaluatePolicySet(pinned, resources[i])
		if !resultsEqual(d.Current, want) {
			t.Fatalf("item %d current result does not match pinned %s evaluation", i, pinnedVer)
		}
		if d.Candidate.PolicyVersion != "cand" {
			t.Fatalf("item %d candidate version unexpected: %s", i, d.Candidate.PolicyVersion)
		}
	}
	t.Logf("rehearsal pinned to %s throughout %d resources despite concurrent hot updates",
		pinnedVer, len(resources))
}

func makePods(n int) []Resource {
	out := make([]Resource, n)
	for i := range out {
		out[i] = Resource{"kind": "Pod", "metadata": map[string]any{"name": podName(i)}}
	}
	return out
}

func podName(i int) string {
	return fmt.Sprintf("pod-%04d", i)
}

// 大批量：不丢不重、顺序稳定；相同输入重复预演结果完全一致。
func TestRehearse_LargeBatchNoLossNoDupStableOrder(t *testing.T) {
	current := PolicySet{Version: "cur", Rules: []Rule{
		{ID: "deny-prod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "metadata.namespace", Op: OpEq, Values: []string{"prod"}}}},
	}}
	cand := mustCandidate(t, PolicySet{Version: "cand", Rules: []Rule{
		{ID: "deny-prod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "metadata.namespace", Op: OpEq, Values: []string{"prod"}}}},
		{ID: "deny-latest", Priority: 200, Effect: EffectDeny,
			Conditions: []Condition{{Field: "spec.containers.0.image", Op: OpMatches, Values: []string{"*:latest"}}}},
		{ID: "warn-dev", Priority: 50, Effect: EffectWarn,
			Conditions: []Condition{{Field: "metadata.namespace", Op: OpEq, Values: []string{"dev"}}}},
	}})
	e := mustEngine(t, current)

	const n = 3000
	resources := make([]Resource, n)
	nsFor := func(i int) string {
		switch i % 3 {
		case 0:
			return "prod"
		case 1:
			return "dev"
		default:
			return "staging"
		}
	}
	imgFor := func(i int) string {
		if i%2 == 0 {
			return "app:latest"
		}
		return "app:1.0"
	}
	for i := range resources {
		resources[i] = Resource{
			"kind": "Pod",
			"metadata": map[string]any{
				"name":      fmt.Sprintf("r%04d", i),
				"namespace": nsFor(i),
			},
			"spec": map[string]any{"containers": []any{map[string]any{"image": imgFor(i)}}},
		}
	}

	rep1, err := e.Rehearse(resources, cand)
	if err != nil {
		t.Fatalf("Rehearse #1: %v", err)
	}
	// 规则加载顺序打乱后重复预演，差异清单内容与顺序必须仍然完全一致。
	candReversed := mustCandidate(t, PolicySet{Version: "cand", Rules: []Rule{
		cand.policy.Rules[2], cand.policy.Rules[1], cand.policy.Rules[0],
	}})
	rep2, err := e.Rehearse(resources, candReversed)
	if err != nil {
		t.Fatalf("Rehearse #2: %v", err)
	}

	if rep1.ResourceCount != n || len(rep1.Items) != n {
		t.Fatalf("loss detected: want %d items, got %d", n, len(rep1.Items))
	}
	seen := make(map[int]bool, n)
	for i, d := range rep1.Items {
		if d.Resource.Index != i {
			t.Fatalf("order unstable at %d: item carries index %d", i, d.Resource.Index)
		}
		if d.Resource.Name != fmt.Sprintf("r%04d", i) {
			t.Fatalf("item %d points at wrong resource %q", i, d.Resource.Name)
		}
		if seen[i] {
			t.Fatalf("duplicate item at %d", i)
		}
		seen[i] = true
		// 与逐条评估交叉核对，保证不是批量路径自身的系统性偏差。
		live := evaluatePolicySet(current, resources[i])
		if !resultsEqual(d.Current, live) {
			t.Fatalf("item %d current mismatch", i)
		}
		want := evaluatePolicySet(cand.policy, resources[i])
		if !resultsEqual(d.Candidate, want) {
			t.Fatalf("item %d candidate mismatch", i)
		}
	}

	// 两次预演：每条的判定、标记、原因文本完全一致。
	for i := 0; i < n; i++ {
		a, b := rep1.Items[i], rep2.Items[i]
		if a.DecisionChanged != b.DecisionChanged || a.ReasonChanged != b.ReasonChanged ||
			a.Reason != b.Reason || !resultsEqual(a.Current, b.Current) || !resultsEqual(a.Candidate, b.Candidate) {
			t.Fatalf("repeat rehearsal diverged at item %d:\n%+v\n%+v", i, a, b)
		}
	}
	if rep1.Summary != rep2.Summary {
		t.Fatalf("summary diverged: %+v vs %+v", rep1.Summary, rep2.Summary)
	}

	// 独立统计核对：当前仅 prod 拒绝；候选下 latest 镜像（偶数下标）拒绝
	// （deny-latest 优先级 200 最高）。新增拒绝 = 非 prod 且偶数下标。
	var wantAddedDeny int
	for i := 0; i < n; i++ {
		if i%2 == 0 && i%3 != 0 {
			wantAddedDeny++
		}
	}
	if rep1.Summary.AddedDeny != wantAddedDeny {
		t.Fatalf("AddedDeny=%d want %d", rep1.Summary.AddedDeny, wantAddedDeny)
	}
	t.Logf("large batch: %d resources, summary=%+v, order/stability verified", n, rep1.Summary)
}

// EvaluateBatch 同样固定版本，结果与逐条评估一致。
func TestEvaluateBatch_PinnedAndInOrder(t *testing.T) {
	v1 := PolicySet{Version: "b-v1", Rules: []Rule{
		{ID: "deny-pod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	v2 := PolicySet{Version: "b-v2", Rules: []Rule{
		{ID: "warn-pod", Priority: 100, Effect: EffectWarn,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	e := mustEngine(t, v1)
	resources := []Resource{
		{"kind": "Pod", "metadata": map[string]any{"name": "p0"}},
		{"kind": "Pod", "metadata": map[string]any{"name": "p1"}},
		{"kind": "CM", "metadata": map[string]any{"name": "c0"}},
	}

	br := e.EvaluateBatch(resources)
	if br.PolicyVersion != "b-v1" || len(br.Results) != 3 {
		t.Fatalf("unexpected batch result: %+v", br)
	}
	for i, r := range resources {
		want := evaluatePolicySet(v1, r)
		if !resultsEqual(br.Results[i], want) {
			t.Fatalf("batch item %d mismatch", i)
		}
		if br.Results[i].PolicyVersion != "b-v1" {
			t.Fatalf("item %d version %s", i, br.Results[i].PolicyVersion)
		}
	}

	// 与并发热更新赛跑：每一批结果的版本必须整批一致。
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				if err := e.Update(v2); err != nil {
					t.Errorf("update failed")
					return
				}
				if err := e.Update(v1); err != nil {
					t.Errorf("update failed")
					return
				}
			}
		}
	}()
	for iter := 0; iter < 500; iter++ {
		b := e.EvaluateBatch(resources)
		for i := range b.Results {
			if b.Results[i].PolicyVersion != b.PolicyVersion {
				t.Fatalf("torn batch at iter %d item %d", iter, i)
			}
		}
	}
	close(done)
	wg.Wait()
	t.Log("EvaluateBatch: every batch observed a single complete version under hot updates")
}

// 候选非法 / 历史格式被拒 / nil 候选：线上策略不受影响。
func TestRehearse_InvalidCandidateNeverTouchesLivePolicy(t *testing.T) {
	live := PolicySet{Version: "live", Rules: []Rule{
		{ID: "live-deny", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	e := mustEngine(t, live)
	resources := []Resource{{"kind": "Pod", "metadata": map[string]any{"name": "p"}}}

	r := Resource{"kind": "Pod", "metadata": map[string]any{"name": "p"}}
	assertLive := func(stage string) {
		t.Helper()
		cur := e.Current()
		if cur.Version != "live" || len(cur.Rules) != 1 || cur.Rules[0].ID != "live-deny" {
			t.Fatalf("%s: live policy polluted: %+v", stage, cur)
		}
		if res := e.Evaluate(r); res.Decision != DecisionDeny || res.PolicyVersion != "live" {
			t.Fatalf("%s: live evaluation changed: %+v", stage, res)
		}
	}

	// 1) 现行格式候选非法（重复 ID）：Prepare 阶段整体拒绝。
	bad := PolicySet{Version: "bad", Rules: []Rule{
		{ID: "dup", Priority: 1, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
		{ID: "dup", Priority: 2, Effect: EffectAllow,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	if _, err := PrepareCandidate(bad); err == nil {
		t.Fatal("invalid current-format candidate must be rejected at prepare")
	} else {
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("want *ValidationError, got %T %v", err, err)
		}
		t.Logf("invalid current candidate rejected: reason=%s detail=%q", ve.Reason, ve.Detail)
	}
	assertLive("after invalid current candidate")

	// 2) 历史格式候选无法安全归一：Prepare 阶段整份拒绝，不跳过、不放宽。
	legacyCases := []struct {
		name string
		raw  string
	}{
		{"deprecated-advise", `{"version":"v1","rules":[{"id":"x","action":"advise","weight":1,"match":{"kind":"Pod"}}]}`},
		{"ambiguous-match", `{"version":"v1","rules":[{"id":"x","action":"permit","weight":1,"match":{"kind":"Pod","namespace":"prod"}}]}`},
		{"unsupported-version", `{"version":"v9","rules":[]}`},
	}
	for _, lc := range legacyCases {
		c, err := PrepareCandidateLegacy([]byte(lc.raw))
		if err == nil {
			t.Fatalf("%s: legacy candidate must be rejected", lc.name)
		}
		if c != nil {
			t.Fatalf("%s: rejected legacy must not yield a candidate", lc.name)
		}
		t.Logf("%s rejected: %v", lc.name, err)
		if _, err := e.Rehearse(resources, c); err == nil {
			t.Fatalf("%s: Rehearse with nil candidate must fail", lc.name)
		}
		assertLive("after rejected legacy " + lc.name)
	}

	// 3) 归一后与现行约束冲突（归一结果重复 ID）：仍然整体拒绝。
	dupLegacy := []byte(`{"version":"v1","rules":[
	  {"id":"d","action":"reject","weight":1,"match":{"kind":"Pod"}},
	  {"id":"d","action":"permit","weight":2,"match":{"kind":"Pod"}}]}`)
	if _, err := PrepareCandidateLegacy(dupLegacy); err == nil {
		t.Fatal("legacy normalizing to duplicate ids must be rejected")
	}

	// 4) Rehearse/Promote 收到 nil 候选：返回可区分错误，线上不动。
	if _, err := e.Rehearse(resources, nil); err == nil {
		t.Fatal("Rehearse(nil) must fail")
	} else {
		var re *RehearsalError
		if !errors.As(err, &re) || re.Reason != ErrReasonCandidateUnavailable {
			t.Fatalf("want RehearsalError/%s, got %v", ErrReasonCandidateUnavailable, err)
		}
	}
	if err := e.Promote(nil); err == nil {
		t.Fatal("Promote(nil) must fail")
	}
	assertLive("after nil candidate calls")
}

// 历史 v1 候选：归一后参与预演，且与真正生效后的结论一致。
func TestRehearse_LegacyCandidate(t *testing.T) {
	current := PolicySet{Version: "cur", Rules: []Rule{
		{ID: "cur-deny", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	e := mustEngine(t, current)

	raw := []byte(`{"version":"v1","rules":[
	  {"id":"leg-flag-pod","action":"flag","weight":50,"match":{"kind":"Pod"}},
	  {"id":"leg-reject-env","action":"reject","weight":900,
	   "match":{"label":{"key":"env","value":"legacy"}}}
	]}`)
	cand, err := PrepareCandidateLegacy(raw)
	if err != nil {
		t.Fatalf("PrepareCandidateLegacy: %v", err)
	}
	if cand.Source().Kind != CandidateFromLegacyV1 {
		t.Fatalf("source kind = %s", cand.Source().Kind)
	}
	normalized := cand.Policy()
	if normalized.Version != legacyNormalizedVersion {
		t.Fatalf("normalized version = %s", normalized.Version)
	}
	// 归一后的策略不可被外部通过 Policy() 篡改。
	normalized.Version = "tampered"
	normalized.Rules[0].ID = "tampered"
	if cand.Policy().Version != legacyNormalizedVersion || cand.Policy().Rules[0].ID != "leg-flag-pod" {
		t.Fatal("candidate internals mutable through Policy()")
	}

	resources := []Resource{
		{"kind": "Pod", "metadata": map[string]any{"name": "p1"}},
		{"kind": "Pod", "metadata": map[string]any{"name": "p2",
			"labels": map[string]any{"env": "legacy"}}},
		{"kind": "ConfigMap", "metadata": map[string]any{"name": "cfg"}},
	}
	rep, err := e.Rehearse(resources, cand)
	if err != nil {
		t.Fatalf("Rehearse: %v", err)
	}
	t.Logf("\n%s", rep.Text())
	if rep.CandidateVersion != legacyNormalizedVersion {
		t.Fatalf("candidate version = %s", rep.CandidateVersion)
	}

	if err := e.Promote(cand); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	for i, r := range resources {
		live := e.Evaluate(r)
		if !resultsEqual(rep.Items[i].Candidate, live) {
			t.Fatalf("legacy item %d: rehearsal candidate != post-promote live", i)
		}
	}
	// p2 命中归一后的 label reject 规则（weight 900），必须 deny 且决胜规则可追溯到历史 ID。
	if res := e.Evaluate(resources[1]); res.Decision != DecisionDeny || res.WinningRule != "leg-reject-env" {
		t.Fatalf("legacy label rule not effective: %+v", res)
	}
}

// Promote 原子切换：并发评估只看到完整旧版本或完整新版本；
// 非法候选拒绝切换，原策略保持可用。
func TestPromote_AtomicVisibility(t *testing.T) {
	v1 := PolicySet{Version: "pv1", Rules: []Rule{
		{ID: "v1-deny", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	v2 := PolicySet{Version: "pv2", Rules: []Rule{
		{ID: "v2-warn", Priority: 100, Effect: EffectWarn,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	e := mustEngine(t, v1)
	r := Resource{"kind": "Pod"}
	validFor := map[string]struct {
		decision Decision
		winner   string
	}{
		"pv1": {DecisionDeny, "v1-deny"},
		"pv2": {DecisionWarn, "v2-warn"},
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var observed int64
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
					want, ok := validFor[res.PolicyVersion]
					if !ok {
						t.Errorf("torn/unknown version %q during Promote", res.PolicyVersion)
						return
					}
					if res.Decision != want.decision || res.WinningRule != want.winner {
						t.Errorf("inconsistent result during Promote: %+v", res)
						return
					}
					atomic.AddInt64(&observed, 1)
				}
			}
		}()
	}

	cand, err := PrepareCandidate(v2)
	if err != nil {
		t.Fatalf("PrepareCandidate: %v", err)
	}
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			if err := e.Promote(cand); err != nil {
				t.Fatalf("Promote: %v", err)
			}
			// 构造一个故意被篡改的候选（正常路径不可达，仅验证防御性复查）：
			// 这里通过直接操作内部字段模拟"归一后与约束冲突"的极端情况。
			tampered := &Candidate{
				source: CandidateSource{Kind: CandidateFromCurrent},
				policy: PolicySet{Version: "", Rules: v2.Rules},
			}
			if err := e.Promote(tampered); err == nil {
				t.Fatal("Promote of invalid candidate must fail")
			}
		} else {
			cand2, _ := PrepareCandidate(v1)
			if err := e.Promote(cand2); err != nil {
				t.Fatalf("Promote back: %v", err)
			}
		}
	}
	close(stop)
	wg.Wait()

	final := e.Evaluate(r)
	logResult(t, "promote-final", r, final)
	if final.PolicyVersion != "pv1" {
		t.Fatalf("unexpected final version %s", final.PolicyVersion)
	}
	t.Logf("Promote race: %d evaluations: only complete pv1/pv2 ever visible; failed promotes had no effect",
		atomic.LoadInt64(&observed))
}
