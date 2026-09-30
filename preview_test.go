package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustCandidate(t *testing.T, ps PolicySet) *PreparedCandidate {
	t.Helper()
	c, err := PrepareCandidateNative(ps)
	if err != nil {
		t.Fatalf("PrepareCandidateNative: %v", err)
	}
	return c
}

// logPreview 打印预演输入资源、两侧命中规则、最终判定与差异原因，
// 满足预演链路的可解释性要求。
func logPreview(t *testing.T, tag string, r Resource, it PreviewItem) {
	t.Helper()
	input, _ := json.Marshal(r)
	t.Logf("[%s] #%d input=%s", tag, it.Position, input)
	t.Logf("[%s] #%d current:   decision=%s version=%s winner=%q",
		tag, it.Position, it.Current.Decision, it.Current.PolicyVersion, it.Current.WinningRule)
	for _, h := range it.Current.Hits {
		t.Logf("[%s] #%d   current hit rule=%s effect=%s priority=%d", tag, it.Position, h.RuleID, h.Effect, h.Priority)
	}
	t.Logf("[%s] #%d candidate: decision=%s version=%s winner=%q",
		tag, it.Position, it.Candidate.Decision, it.Candidate.PolicyVersion, it.Candidate.WinningRule)
	for _, h := range it.Candidate.Hits {
		t.Logf("[%s] #%d   candidate hit rule=%s effect=%s priority=%d", tag, it.Position, h.RuleID, h.Effect, h.Priority)
	}
	if it.Changed {
		t.Logf("[%s] #%d DIFF reason=%s", tag, it.Position, it.Reason)
	}
}

func TestPreview_DiffItemsAndSummary(t *testing.T) {
	// 当前版本：kind=Pod 拒绝。
	cur := PolicySet{Version: "cur-1", Rules: []Rule{
		{ID: "deny-pod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	e := mustEngine(t, cur)

	// 候选版本：Pod 降为告警，ConfigMap 新增拒绝（其余默认放行）。
	candPS := PolicySet{Version: "cand-1", Rules: []Rule{
		{ID: "warn-pod", Priority: 100, Effect: EffectWarn,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
		{ID: "deny-cm", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"ConfigMap"}}}},
	}}
	cand, err := PrepareCandidateNative(candPS)
	if err != nil {
		t.Fatalf("prepare candidate: %v", err)
	}

	resources := []Resource{
		{"kind": "Pod"},        // 0: deny -> warn（不再拒绝、告警新增）
		{"kind": "ConfigMap"},  // 1: allow -> deny（新增拒绝）
		{"kind": "Deployment"}, // 2: allow -> allow（无变化）
		{"kind": "Service"},    // 3: allow -> allow（无变化）
	}
	rep, err := e.Preview(resources, cand, BatchOptions{Workers: 2, ChunkSize: 1})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	t.Logf("\n%s", RenderReport(rep))

	if rep.CurrentVersion != "cur-1" || rep.CandidateVersion != "cand-1" ||
		rep.CandidateSource != CandidateNative {
		t.Fatalf("unexpected report header: %+v", rep)
	}
	if len(rep.Items) != 4 {
		t.Fatalf("want 4 items, got %d", len(rep.Items))
	}
	for i, r := range resources {
		logPreview(t, "diff", r, rep.Items[i])
		if rep.Items[i].Position != i {
			t.Fatalf("item %d has position %d", i, rep.Items[i].Position)
		}
	}

	want := []struct {
		decision Decision
		winner   string
		changed  bool
	}{
		{DecisionWarn, "warn-pod", true},
		{DecisionDeny, "deny-cm", true},
		{DecisionAllow, "", false},
		{DecisionAllow, "", false},
	}
	for i, w := range want {
		got := rep.Items[i]
		if got.Candidate.Decision != w.decision || got.Candidate.WinningRule != w.winner ||
			got.Changed != w.changed {
			t.Fatalf("item %d: want decision=%s winner=%q changed=%v, got %s/%q/%v",
				i, w.decision, w.winner, w.changed, got.Candidate.Decision, got.Candidate.WinningRule, got.Changed)
		}
		if w.changed && got.Reason == "" {
			t.Fatalf("item %d changed but has no diff reason", i)
		}
	}
	if rep.Items[0].Current.Decision != DecisionDeny || rep.Items[1].Current.Decision != DecisionAllow {
		t.Fatalf("current-side decisions wrong: %s %s",
			rep.Items[0].Current.Decision, rep.Items[1].Current.Decision)
	}

	s := rep.Summary
	if s.Total != 4 || s.Changed != 2 || s.Unchanged != 2 ||
		s.NewlyDenied != 1 || s.NoLongerDenied != 1 ||
		s.WarningsAdded != 1 || s.WarningsRemoved != 0 {
		t.Fatalf("summary wrong: %+v", s)
	}
	if s.DecisionTransitions["deny->warn"] != 1 || s.DecisionTransitions["allow->deny"] != 1 ||
		len(s.DecisionTransitions) != 2 {
		t.Fatalf("transition map wrong: %+v", s.DecisionTransitions)
	}
}

func TestPreview_MatchesResultAfterCommit(t *testing.T) {
	cur := PolicySet{Version: "cur", Rules: []Rule{
		{ID: "deny-prod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{
				{Field: "metadata.namespace", Op: OpEq, Values: []string{"prod"}},
				{Field: "kind", Op: OpIn, Values: []string{"Deployment", "StatefulSet"}},
			}},
		{ID: "warn-latest", Priority: 50, Effect: EffectWarn,
			Conditions: []Condition{{Field: "spec.containers.0.image", Op: OpMatches, Values: []string{"*:latest"}}}},
	}}
	e := mustEngine(t, cur)
	cand, err := PrepareCandidateNative(PolicySet{Version: "cand", Rules: []Rule{
		{ID: "warn-latest", Priority: 50, Effect: EffectWarn,
			Conditions: []Condition{{Field: "spec.containers.0.image", Op: OpMatches, Values: []string{"*:latest"}}}},
		{ID: "allow-prod-sts", Priority: 200, Effect: EffectAllow,
			Conditions: []Condition{
				{Field: "metadata.namespace", Op: OpEq, Values: []string{"prod"}},
				{Field: "kind", Op: OpEq, Values: []string{"StatefulSet"}},
			}},
	}})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	resources := []Resource{
		{"kind": "Deployment", "metadata": map[string]any{"namespace": "prod"},
			"spec": map[string]any{"containers": []any{map[string]any{"image": "nginx:1.25"}}}},
		{"kind": "StatefulSet", "metadata": map[string]any{"namespace": "prod"},
			"spec": map[string]any{"containers": []any{map[string]any{"image": "redis:latest"}}}},
		{"kind": "Pod", "metadata": map[string]any{"namespace": "dev"},
			"spec": map[string]any{"containers": []any{map[string]any{"image": "busybox:latest"}}}},
		{"kind": "ConfigMap", "metadata": map[string]any{"namespace": "dev"}},
	}
	rep, err := e.Preview(resources, cand, BatchOptions{Workers: 4, ChunkSize: 2})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	// 正式生效候选后逐资源重评，候选侧结论必须逐条一致。
	if err := e.CommitCandidate(cand); err != nil {
		t.Fatalf("commit: %v", err)
	}
	for i, r := range resources {
		live := e.Evaluate(r)
		prev := rep.Items[i].Candidate
		logResult(t, "post-commit", r, live)
		if live.Decision != prev.Decision || live.WinningRule != prev.WinningRule ||
			live.PolicyVersion != prev.PolicyVersion || len(live.Hits) != len(prev.Hits) {
			t.Fatalf("resource %d: preview candidate %+v != live after commit %+v", i, prev, live)
		}
		// 命中规则 ID 集合也要一致。
		for j := range live.Hits {
			if live.Hits[j].RuleID != prev.Hits[j].RuleID {
				t.Fatalf("resource %d hit %d: %q != %q", i, j, live.Hits[j].RuleID, prev.Hits[j].RuleID)
			}
		}
	}
	t.Logf("preview candidate-side results identical to live evaluation after commit for %d resources", len(resources))
}

func TestPreview_LegacyCandidateNormalizedThenPreviewedAndCommitted(t *testing.T) {
	cur := PolicySet{Version: "cur", Rules: []Rule{
		{ID: "modern-deny", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	e := mustEngine(t, cur)

	raw := []byte(`{
	  "version": "v1",
	  "rules": [
	    {"id": "legacy-flag", "action": "flag", "weight": 100, "match": {"kind": "Pod"}},
	    {"id": "legacy-reject-label", "action": "reject", "weight": 500,
	     "match": {"label": {"key": "env", "value": "legacy"}}}
	  ]
	}`)
	cand, err := PrepareCandidateLegacy(raw)
	if err != nil {
		t.Fatalf("prepare legacy candidate: %v", err)
	}
	if cand.Source() != CandidateLegacy || cand.PolicyVersion() != legacyNormalizedVersion {
		t.Fatalf("candidate metadata wrong: source=%s version=%s", cand.Source(), cand.PolicyVersion())
	}

	r := Resource{"kind": "Pod", "metadata": map[string]any{"labels": map[string]any{"env": "legacy"}}}
	rep, err := e.Preview([]Resource{r}, cand, BatchOptions{})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if rep.CandidateSource != CandidateLegacy {
		t.Fatalf("report source = %s", rep.CandidateSource)
	}
	previewed := rep.Items[0].Candidate
	logPreview(t, "legacy", r, rep.Items[0])

	if err := e.CommitCandidate(cand); err != nil {
		t.Fatalf("commit legacy: %v", err)
	}
	live := e.Evaluate(r)
	if live.Decision != previewed.Decision || live.WinningRule != previewed.WinningRule {
		t.Fatalf("legacy preview %s/%q != live %s/%q",
			previewed.Decision, previewed.WinningRule, live.Decision, live.WinningRule)
	}
	if live.Decision != DecisionDeny || live.WinningRule != "legacy-reject-label" {
		t.Fatalf("normalized legacy rule must deny via legacy-reject-label, got %s/%q", live.Decision, live.WinningRule)
	}
}

func TestPreview_PinnedToOneVersionAcrossHotUpdate(t *testing.T) {
	// v1/v2/v3 对 Pod 分别给出 deny/warn/allow；任何一份报告的当前侧
	// 必须全部落在同一个版本上，结论随版本自洽。候选固定为另一份策略，
	// 候选侧版本同样必须整批一致。
	v1 := PolicySet{Version: "v1", Rules: []Rule{{ID: "v1-deny", Priority: 100, Effect: EffectDeny,
		Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}}}}
	v2 := PolicySet{Version: "v2", Rules: []Rule{{ID: "v2-warn", Priority: 100, Effect: EffectWarn,
		Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}}}}
	v3 := PolicySet{Version: "v3", Rules: []Rule{{ID: "v3-allow", Priority: 100, Effect: EffectAllow,
		Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}}}}
	e := mustEngine(t, v1)

	cand := mustCandidate(t, PolicySet{Version: "cand-x", Rules: []Rule{
		{ID: "cand-deny-cm", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"ConfigMap"}}}},
	}})

	// 两批资源混合 Pod（随版本变化）与 ConfigMap（只受候选影响）。
	mkBatch := func(n int) []Resource {
		rs := make([]Resource, n)
		for i := range rs {
			if i%2 == 0 {
				rs[i] = Resource{"kind": "Pod"}
			} else {
				rs[i] = Resource{"kind": "ConfigMap"}
			}
		}
		return rs
	}
	batch := mkBatch(400)
	decisionFor := map[string]Decision{"v1": DecisionDeny, "v2": DecisionWarn, "v3": DecisionAllow}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var reports int64
	// 更新方持续热更新线上策略。
	wg.Add(1)
	go func() {
		defer wg.Done()
		next := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			switch next % 3 {
			case 0:
				_ = e.Update(v2)
			case 1:
				_ = e.Update(v3)
			case 2:
				_ = e.Update(v1)
			}
			next++
		}
	}()
	// 预演方反复整批预演：每份报告必须只对应一个当前版本。
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 20; k++ {
				rep, err := e.Preview(batch, cand, BatchOptions{Workers: 8, ChunkSize: 25})
				if err != nil {
					t.Errorf("preview: %v", err)
					return
				}
				pinnedVersion := rep.CurrentVersion
				wantDecision := decisionFor[pinnedVersion]
				for _, it := range rep.Items {
					if it.Current.PolicyVersion != pinnedVersion {
						t.Errorf("torn preview: header=%s item#%d version=%s",
							pinnedVersion, it.Position, it.Current.PolicyVersion)
						return
					}
					if it.Candidate.PolicyVersion != "cand-x" {
						t.Errorf("candidate side drifted: item#%d version=%s",
							it.Position, it.Candidate.PolicyVersion)
						return
					}
					if it.Position%2 == 0 && it.Current.Decision != wantDecision {
						t.Errorf("version %s expects %s but item#%d got %s",
							pinnedVersion, wantDecision, it.Position, it.Current.Decision)
						return
					}
					if it.Position%2 == 1 && it.Candidate.Decision != DecisionDeny {
						t.Errorf("ConfigMap item#%d candidate must deny, got %s",
							it.Position, it.Candidate.Decision)
						return
					}
				}
				atomic.AddInt64(&reports, 1)
			}
		}()
	}
	// 让竞争持续一小段时间后收尾。
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
	t.Logf("hot-update-during-preview: %d pinned reports, each used exactly one current version", atomic.LoadInt64(&reports))
}

func TestPreview_LargeBatch_NoLossNoDupStableOrder(t *testing.T) {
	cur := PolicySet{Version: "cur", Rules: []Rule{
		{ID: "deny-odd", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "metadata.namespace", Op: OpEq, Values: []string{"odd"}}}},
	}}
	e := mustEngine(t, cur)
	cand := mustCandidate(t, PolicySet{Version: "cand", Rules: []Rule{
		{ID: "warn-even", Priority: 100, Effect: EffectWarn,
			Conditions: []Condition{{Field: "metadata.namespace", Op: OpEq, Values: []string{"even"}}}},
		{ID: "deny-multi7", Priority: 200, Effect: EffectDeny,
			Conditions: []Condition{{Field: "metadata.labels.idx", Op: OpMatches, Values: []string{"*49"}}}},
	}})

	const n = 5000
	resources := make([]Resource, n)
	for i := 0; i < n; i++ {
		ns := "odd"
		if i%2 == 0 {
			ns = "even"
		}
		resources[i] = Resource{
			"kind":     "Resource",
			"metadata": map[string]any{"namespace": ns, "name": "r", "labels": map[string]any{"idx": itoa(i)}},
		}
	}

	// 多种并发/分块配置下，结果都必须与串行基线完全一致。
	serial, err := e.Preview(resources, cand, BatchOptions{})
	if err != nil {
		t.Fatalf("serial preview: %v", err)
	}
	configs := []BatchOptions{
		{Workers: 1, ChunkSize: 1},
		{Workers: 4, ChunkSize: 7},
		{Workers: 16, ChunkSize: 33},
		{Workers: 64, ChunkSize: 100},
	}
	for ci, opts := range configs {
		rep, err := e.Preview(resources, cand, opts)
		if err != nil {
			t.Fatalf("config %d preview: %v", ci, err)
		}
		if len(rep.Items) != n {
			t.Fatalf("config %d: got %d items, want %d (loss/dup)", ci, len(rep.Items), n)
		}
		var changed int
		for i := range rep.Items {
			it, base := rep.Items[i], serial.Items[i]
			if it.Position != i {
				t.Fatalf("config %d item %d has position %d (order unstable)", ci, i, it.Position)
			}
			if it.Current.Decision != base.Current.Decision ||
				it.Candidate.Decision != base.Candidate.Decision ||
				it.Changed != base.Changed || it.Reason != base.Reason {
				t.Fatalf("config %d item %d diverged from serial baseline", ci, i)
			}
			if it.Changed {
				changed++
			}
		}
		if rep.Summary.Changed != changed || rep.Summary.Total != n {
			t.Fatalf("config %d summary inconsistent with items: %+v", ci, rep.Summary)
		}
	}

	// 独立地按规则语义复核每条结论，避免“与自己一致”的假阳性。
	for i, r := range resources {
		got := serial.Items[i]
		curWant := DecisionAllow
		if i%2 != 0 {
			curWant = DecisionDeny // odd 命名空间
		}
		candWant := DecisionAllow
		switch {
		case i%100 == 49 || (i >= 100 && (i-49)%100 == 0):
			candWant = DecisionDeny // idx 字符串以 49 结尾：49,149,...4949
		case i%2 == 0:
			candWant = DecisionWarn
		}
		if got.Current.Decision != curWant || got.Candidate.Decision != candWant {
			t.Fatalf("resource %d (%v): want cur=%s cand=%s, got cur=%s cand=%s",
				i, r["metadata"], curWant, candWant, got.Current.Decision, got.Candidate.Decision)
		}
	}

	// 相同输入重复预演：整份报告（含渲染文本）必须完全一致。
	again, _ := e.Preview(resources, cand, BatchOptions{Workers: 16, ChunkSize: 33})
	if RenderReport(again) != RenderReport(serial) {
		t.Fatalf("repeated preview produced a different report")
	}
	t.Logf("large batch n=%d: no loss/dup, order stable across %d worker configs, repeatable; summary=%+v",
		n, len(configs), serial.Summary)
	logPreview(t, "large-sample", resources[49], serial.Items[49])
}

// itoa 避免在测试里引入 strconv 的语义歧义，简单手写十进制转换。
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	var buf [20]byte
	pos := len(buf)
	for i != 0 {
		pos--
		d := i % 10
		if neg {
			d = -d
		}
		buf[pos] = byte('0' + d)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func TestPrepareAndPreview_InvalidCandidateRejectedOnlineUntouched(t *testing.T) {
	cur := PolicySet{Version: "online-v1", Rules: []Rule{
		{ID: "online-deny", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	e := mustEngine(t, cur)
	r := Resource{"kind": "Pod"}

	// 1) 现行格式非法：重复规则 ID、非法 glob，必须返回可区分 ValidationError。
	badSets := []PolicySet{
		{Version: "cand", Rules: []Rule{
			{ID: "dup", Priority: 1, Effect: EffectDeny,
				Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
			{ID: "dup", Priority: 2, Effect: EffectDeny,
				Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
		}},
		{Version: "cand", Rules: []Rule{
			{ID: "badglob", Priority: 1, Effect: EffectDeny,
				Conditions: []Condition{{Field: "kind", Op: OpMatches, Values: []string{"["}}}},
		}},
	}
	for i, bad := range badSets {
		c, err := PrepareCandidateNative(bad)
		if err == nil {
			t.Fatalf("case %d: invalid candidate must be rejected", i)
		}
		if c != nil {
			t.Fatalf("case %d: rejected candidate must be nil", i)
		}
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("case %d: want *ValidationError, got %T %v", i, err, err)
		}
		t.Logf("case %d rejected: reason=%s detail=%q", i, ve.Reason, ve.Detail)

		// 用 nil/失败候选做预演或提交都必须被拒绝。
		if rep, perr := e.Preview([]Resource{r}, c, BatchOptions{}); perr == nil || rep != nil {
			t.Fatalf("case %d: preview with rejected candidate must fail", i)
		}
		if cerr := e.CommitCandidate(c); cerr == nil {
			t.Fatalf("case %d: commit of rejected candidate must fail", i)
		}
		assertStillOnlineV1(t, e, r)
	}

	// 2) 外部伪造/零值的 PreparedCandidate 同样拒绝。
	var fake *PreparedCandidate
	if _, err := e.Preview([]Resource{r}, fake, BatchOptions{}); err == nil {
		t.Fatal("nil candidate preview must fail")
	}
	fakeVal := PreparedCandidate{}
	if err := e.CommitCandidate(&fakeVal); err == nil {
		t.Fatal("zero-value candidate commit must fail")
	} else {
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Reason != ErrReasonCandidateNotPrepared {
			t.Fatalf("want candidate_not_prepared, got %v", err)
		}
		t.Logf("zero-value candidate rejected: %v", err)
	}
	assertStillOnlineV1(t, e, r)
}

func TestPrepareAndPreview_LegacyCandidateRejectedOnlineUntouched(t *testing.T) {
	cur := PolicySet{Version: "online-v1", Rules: []Rule{
		{ID: "online-deny", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	e := mustEngine(t, cur)
	r := Resource{"kind": "Pod"}

	cases := []struct {
		name   string
		raw    string
		reason string
	}{
		// 废弃动作无法安全映射，不能静默跳过。
		{"deprecated-advise",
			`{"version":"v1","rules":[{"id":"r","action":"advise","weight":1,"match":{"kind":"Pod"}}]}`,
			ConvReasonDeprecatedAction},
		// 多 selector 语义歧义，不能猜。
		{"ambiguous-match",
			`{"version":"v1","rules":[{"id":"r","action":"permit","weight":1,"match":{"kind":"Pod","namespace":"p"}}]}`,
			ConvReasonAmbiguousMatch},
		// 版本不受支持。
		{"wrong-version", `{"version":"v2","rules":[]}`, ConvReasonUnsupportedVersion},
		// 归一后与现有约束冲突：规则 ID 重复。
		{"duplicate-after-normalize", `{"version":"v1","rules":[
		   {"id":"r","action":"permit","weight":1,"match":{"kind":"Pod"}},
		   {"id":"r","action":"reject","weight":2,"match":{"kind":"Pod"}}]}`,
			ErrReasonDuplicateRuleID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := PrepareCandidateLegacy([]byte(tc.raw))
			if err == nil {
				t.Fatalf("%s: legacy candidate must be rejected", tc.name)
			}
			if c != nil {
				t.Fatalf("%s: rejected legacy candidate must be nil", tc.name)
			}
			var ce *ConversionError
			var ve *ValidationError
			switch {
			case errors.As(err, &ce):
				t.Logf("%s rejected as conversion error reason=%s detail=%q", tc.name, ce.Reason, ce.Detail)
				if ce.Reason != tc.reason {
					t.Fatalf("want %s, got %s", tc.reason, ce.Reason)
				}
			case errors.As(err, &ve):
				t.Logf("%s rejected as post-normalize validation error reason=%s", tc.name, ve.Reason)
				if ve.Reason != tc.reason {
					t.Fatalf("want %s, got %s", tc.reason, ve.Reason)
				}
			default:
				t.Fatalf("%s: want typed error, got %T", tc.name, err)
			}

			if rep, perr := e.Preview([]Resource{r}, c, BatchOptions{}); perr == nil || rep != nil {
				t.Fatalf("%s: preview with rejected candidate must fail", tc.name)
			}
			if cerr := e.CommitCandidate(c); cerr == nil {
				t.Fatalf("%s: commit of rejected candidate must fail", tc.name)
			}
			assertStillOnlineV1(t, e, r)
		})
	}
}

func assertStillOnlineV1(t *testing.T, e *Engine, r Resource) {
	t.Helper()
	cur := e.Current()
	if cur.Version != "online-v1" || len(cur.Rules) != 1 || cur.Rules[0].ID != "online-deny" {
		t.Fatalf("online policy was modified by a rejected candidate: %+v", cur)
	}
	res := e.Evaluate(r)
	if res.PolicyVersion != "online-v1" || res.Decision != DecisionDeny || res.WinningRule != "online-deny" {
		t.Fatalf("online evaluation changed after rejection: %+v", res)
	}
}

func TestCommitCandidate_AtomicVisibilityUnderConcurrency(t *testing.T) {
	e := mustEngine(t, PolicySet{Version: "v1", Rules: []Rule{
		{ID: "v1-deny", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}})
	cands := []*PreparedCandidate{
		mustCandidate(t, PolicySet{Version: "v2", Rules: []Rule{
			{ID: "v2-warn", Priority: 100, Effect: EffectWarn,
				Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
		}}),
		mustCandidate(t, PolicySet{Version: "v3", Rules: []Rule{
			{ID: "v3-allow", Priority: 100, Effect: EffectAllow,
				Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
		}}),
	}
	valid := map[string]struct {
		decision Decision
		winner   string
	}{
		"v1": {DecisionDeny, "v1-deny"},
		"v2": {DecisionWarn, "v2-warn"},
		"v3": {DecisionAllow, "v3-allow"},
	}
	r := Resource{"kind": "Pod"}

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
					want, ok := valid[res.PolicyVersion]
					if !ok {
						t.Errorf("observed torn version %q", res.PolicyVersion)
						return
					}
					if res.Decision != want.decision || res.WinningRule != want.winner {
						t.Errorf("inconsistent version=%s decision=%s winner=%s",
							res.PolicyVersion, res.Decision, res.WinningRule)
						return
					}
					atomic.AddInt64(&observed, 1)
				}
			}
		}()
	}
	for i := 0; i < 300; i++ {
		if err := e.CommitCandidate(cands[i%2]); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()

	// 最终必须停留在某次完整提交的版本上（v2 或 v3），绝不可能是混合状态。
	final := e.Evaluate(r)
	if final.PolicyVersion != "v2" && final.PolicyVersion != "v3" {
		t.Fatalf("unexpected final version %q", final.PolicyVersion)
	}
	logResult(t, "commit-race-final", r, final)
	t.Logf("commit race: %d evaluations saw only complete versions; final=%s", observed, final.PolicyVersion)
}

func TestEvaluateBatch_PinnedVersionAndOrder(t *testing.T) {
	v1 := PolicySet{Version: "v1", Rules: []Rule{
		{ID: "deny-pod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	v2 := PolicySet{Version: "v2", Rules: []Rule{
		{ID: "warn-pod", Priority: 100, Effect: EffectWarn,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	e := mustEngine(t, v1)
	resources := []Resource{{"kind": "Pod"}, {"kind": "ConfigMap"}, {"kind": "Pod"}, {"kind": "Service"}}

	stop := make(chan struct{})
	var wg sync.WaitGroup
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
	for k := 0; k < 50; k++ {
		got := e.EvaluateBatch(resources, BatchOptions{Workers: 8, ChunkSize: 1})
		if len(got) != len(resources) {
			t.Fatalf("batch lost/duplicated: %d vs %d", len(got), len(resources))
		}
		version := got[0].Result.PolicyVersion
		wantDec := DecisionDeny
		if version == "v2" {
			wantDec = DecisionWarn
		}
		for i, br := range got {
			if br.Position != i {
				t.Fatalf("position disorder: %d at %d", br.Position, i)
			}
			if br.Result.PolicyVersion != version {
				t.Fatalf("torn batch: item %d version=%s header=%s", i, br.Result.PolicyVersion, version)
			}
			if resources[i]["kind"] == "Pod" && br.Result.Decision != wantDec {
				t.Fatalf("item %d decision %s inconsistent with pinned version %s", i, br.Result.Decision, version)
			}
		}
	}
	close(stop)
	wg.Wait()
	t.Logf("EvaluateBatch: 50 batches under concurrent hot updates, each pinned to one version and order-stable")
}

func TestPreview_EmptyBatchAndNoChangeReport(t *testing.T) {
	e := mustEngine(t, PolicySet{Version: "v1", Rules: []Rule{
		{ID: "deny-pod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}})
	cand := mustCandidate(t, PolicySet{Version: "v2", Rules: []Rule{
		{ID: "deny-pod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}})

	rep, err := e.Preview(nil, cand, BatchOptions{Workers: 4, ChunkSize: 2})
	if err != nil {
		t.Fatalf("empty preview: %v", err)
	}
	if len(rep.Items) != 0 || rep.Summary.Total != 0 {
		t.Fatalf("empty batch must yield empty items, got %+v", rep.Summary)
	}
	if got := e.EvaluateBatch(nil, BatchOptions{Workers: 4}); len(got) != 0 {
		t.Fatalf("empty batch eval must be empty, got %v", got)
	}

	// 候选与当前规则等价：所有资源结论不变。
	rep2, _ := e.Preview([]Resource{{"kind": "Pod"}, {"kind": "X"}}, cand, BatchOptions{})
	text := RenderReport(rep2)
	t.Logf("\n%s", text)
	if rep2.Summary.Changed != 0 || rep2.Summary.Unchanged != 2 {
		t.Fatalf("want no changes, got %+v", rep2.Summary)
	}
	for _, frag := range []string{"current policy:", "candidate policy:", "Summary:", "unchanged=2", "No decision changes"} {
		if !strings.Contains(text, frag) {
			t.Fatalf("report missing fragment %q", frag)
		}
	}
	if RenderReport(rep2) != text {
		t.Fatal("RenderReport must be deterministic")
	}
}
