package policy

import (
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// TestRehearse_UnreadyCandidateRejectedWholesale 覆盖业务：
// 未就绪候选（nil、零值 &Candidate{}、手拼"有规则但没走 Prepare"的对象）
// 在预演开始前被整份拒绝——返回可区分原因、零报告、绝不被当成空策略评估成全放行；
// 当前生效策略在多次被拒调用前后保持不变，后续评估不受影响。
func TestRehearse_UnreadyCandidateRejectedWholesale(t *testing.T) {
	live := PolicySet{Version: "live", Rules: []Rule{
		{ID: "live-deny-pod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	e := mustEngine(t, live)

	// 该资源在线上策略下必为 deny；若错误地把未就绪候选当成空策略评估，
	// 候选侧会是 allow，从而凭空产生 deny -> allow 的差异。
	trap := Resource{"kind": "Pod", "metadata": map[string]any{
		"name": "trap", "namespace": "prod",
	}}
	resources := []Resource{trap}
	input, _ := json.Marshal(trap)
	t.Logf("[业务:未就绪候选整份拒绝] input=%s; 期望 Rehearse/Promote 均拒绝且 live 恒为 deny(live)", input)

	unready := []struct {
		name string
		c    *Candidate
		want string
	}{
		{"nil-candidate", nil, ErrReasonCandidateUnavailable},
		{"zero-value-candidate", &Candidate{}, ErrReasonCandidateNotPrepared},
		// 手拼但没走准备流程、还带了条"规则"的候选：证明拦截只依赖 prepared
		// 标记而不是规则条数——即使内部看起来"有内容"也必须拒。
		{"handbuilt-with-rules", &Candidate{
			source: CandidateSource{Kind: CandidateFromCurrent},
			policy: PolicySet{Version: "v-handbuilt", Rules: []Rule{
				{ID: "fake", Priority: 1, Effect: EffectAllow,
					Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
			}},
		}, ErrReasonCandidateNotPrepared},
	}

	for _, uc := range unready {
		t.Run(uc.name, func(t *testing.T) {
			rep, err := e.Rehearse(resources, uc.c)
			if err == nil {
				t.Fatalf("必须拒绝未就绪候选，却拿到报告: %+v", rep)
			}
			var re *RehearsalError
			if !errors.As(err, &re) || re.Reason != uc.want {
				t.Fatalf("错误类型/原因不符: want RehearsalError/%s, got %T %v", uc.want, err, err)
			}
			t.Logf("[业务:未就绪候选整份拒绝/%s] 拒绝原因=%s(区别于 ValidationError/ConversionError) detail=%q",
				uc.name, re.Reason, re.Detail)
			// 零报告：不允许任何逐条结果、版本或汇总结论。
			if rep.ResourceCount != 0 || len(rep.Items) != 0 || rep.CurrentVersion != "" ||
				rep.CandidateVersion != "" || rep.Summary != (DiffSummary{}) {
				t.Fatalf("被拒调用不得产出任何逐条结果/汇总，got=%+v", rep)
			}

			// 线上策略与后续评估均不变。
			cur := e.Current()
			if cur.Version != "live" || len(cur.Rules) != 1 || cur.Rules[0].ID != "live-deny-pod" {
				t.Fatalf("[%s] 生效策略被污染: %+v", uc.name, cur)
			}
			liveRes := e.Evaluate(trap)
			logResult(t, "live-after-reject/"+uc.name, trap, liveRes)
			if liveRes.Decision != DecisionDeny || liveRes.PolicyVersion != "live" ||
				liveRes.WinningRule != "live-deny-pod" {
				t.Fatalf("[%s] 被拒调用改变了后续评估: %+v", uc.name, liveRes)
			}
		})
	}
}

// TestRehearsePromote_ReadinessJudgmentConsistent 覆盖业务：
// 同一份候选在预演与切换上"能不能用"的判断必须一致——该拒两边同因都拒，
// 该过两边都过；合法候选真能原子切换，未就绪候选切换前后线上策略不变。
func TestRehearsePromote_ReadinessJudgmentConsistent(t *testing.T) {
	validPS := PolicySet{Version: "cand-ok", Rules: []Rule{
		{ID: "cand-warn-pod", Priority: 100, Effect: EffectWarn,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	r := Resource{"kind": "Pod", "metadata": map[string]any{"name": "p"}}
	in, _ := json.Marshal(r)

	cases := []struct {
		name       string
		candidate  func() *Candidate
		wantReject string // 空串表示应被两侧接受
	}{
		{"nil", func() *Candidate { return nil }, ErrReasonCandidateUnavailable},
		{"zero-value", func() *Candidate { return &Candidate{} }, ErrReasonCandidateNotPrepared},
		{"handbuilt", func() *Candidate {
			return &Candidate{source: CandidateSource{Kind: CandidateFromCurrent},
				policy: PolicySet{Version: "x", Rules: validPS.Rules}}
		}, ErrReasonCandidateNotPrepared},
		// 包内异常构造：带 prepared 标记但内嵌策略非法（版本为空）。
		{"prepared-but-invalid", func() *Candidate {
			return &Candidate{source: CandidateSource{Kind: CandidateFromCurrent},
				policy: PolicySet{Version: "", Rules: validPS.Rules}, prepared: true}
		}, ErrReasonCandidateInvalid},
		{"valid-prepared", func() *Candidate { return mustCandidate(t, validPS) }, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 每个子用例用全新的 live 引擎，避免相互影响。
			live := PolicySet{Version: "live", Rules: []Rule{
				{ID: "live-deny-pod", Priority: 100, Effect: EffectDeny,
					Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
			}}
			e := mustEngine(t, live)
			c := tc.candidate()
			t.Logf("[业务:预演/切换一致性/%s] input=%s", tc.name, in)

			_, rerr := e.Rehearse([]Resource{r}, c)
			perr := e.Promote(c)
			t.Logf("[业务:预演/切换一致性/%s] Rehearse.err=%v | Promote.err=%v", tc.name, rerr, perr)

			rehearsalReady := rerr == nil
			promoteReady := perr == nil
			if rehearsalReady != promoteReady {
				t.Fatalf("[%s] 预演与切换对候选可用性判断不一致: rehearseReady=%v promoteReady=%v",
					tc.name, rehearsalReady, promoteReady)
			}

			if tc.wantReject != "" {
				var rre, pre *RehearsalError
				if !errors.As(rerr, &rre) || !errors.As(perr, &pre) {
					t.Fatalf("[%s] 两侧都应是 *RehearsalError: %v / %v", tc.name, rerr, perr)
				}
				if rre.Reason != tc.wantReject || pre.Reason != tc.wantReject {
					t.Fatalf("[%s] 两侧拒绝原因不一致或不符: rehearse=%s promote=%s want=%s",
						tc.name, rre.Reason, pre.Reason, tc.wantReject)
				}
				// 被拒切换不得改动线上策略。
				cur := e.Current()
				if cur.Version != "live" || cur.Rules[0].ID != "live-deny-pod" {
					t.Fatalf("[%s] 被拒切换污染线上策略: %+v", tc.name, cur)
				}
				liveRes := e.Evaluate(r)
				logResult(t, "consistency-rejected/"+tc.name, r, liveRes)
				if liveRes.Decision != DecisionDeny || liveRes.PolicyVersion != "live" {
					t.Fatalf("[%s] 被拒后评估变化: %+v", tc.name, liveRes)
				}
				return
			}

			// 两侧都接受：Promote 必须真正切换，切换后结论与预演候选列一致。
			rep, err := e.Rehearse([]Resource{r}, c)
			if err != nil {
				t.Fatalf("[%s] 合法候选第二次预演失败: %v", tc.name, err)
			}
			if err := e.Promote(c); err != nil {
				t.Fatalf("[%s] 合法候选 Promote 失败: %v", tc.name, err)
			}
			after := e.Evaluate(r)
			logResult(t, "consistency-accepted/"+tc.name, r, after)
			t.Logf("[业务:预演/切换一致性/%s] 预演候选列 decision=%s winner=%q hits=%v; 切换后 decision=%s winner=%q",
				tc.name, rep.Items[0].Candidate.Decision, rep.Items[0].Candidate.WinningRule,
				hitIDs(rep.Items[0].Candidate), after.Decision, after.WinningRule)
			if after.PolicyVersion != "cand-ok" || !resultsEqual(rep.Items[0].Candidate, after) {
				t.Fatalf("[%s] 切换后结论与预演候选列不一致: %+v vs %+v",
					tc.name, rep.Items[0].Candidate, after)
			}
		})
	}
}

// TestRehearse_RejectedCallsLeaveNoStateUnderHotUpdate 覆盖业务：
// 并发热更新下，新拦截不破坏既有批量版本一致性——整批资源只能固定在同一个
// 完整版本上；穿插的未就绪候选被拒调用不残留任何中间状态，之后的成功批量
// 依旧整批单一版本。
func TestRehearse_RejectedCallsLeaveNoStateUnderHotUpdate(t *testing.T) {
	v1 := PolicySet{Version: "hv1", Rules: []Rule{
		{ID: "v1-deny-pod", Priority: 100, Effect: EffectDeny,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	v2 := PolicySet{Version: "hv2", Rules: []Rule{
		{ID: "v2-warn-pod", Priority: 100, Effect: EffectWarn,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}}
	cand := mustCandidate(t, PolicySet{Version: "hcand", Rules: []Rule{
		{ID: "c-allow-pod", Priority: 100, Effect: EffectAllow,
			Conditions: []Condition{{Field: "kind", Op: OpEq, Values: []string{"Pod"}}}},
	}})
	e := mustEngine(t, v1)
	resources := makePods(400)
	sets := map[string]PolicySet{"hv1": v1, "hv2": v2}

	stopUpdate := make(chan struct{})
	var updWG sync.WaitGroup
	updWG.Add(1)
	go func() {
		defer updWG.Done()
		for {
			select {
			case <-stopUpdate:
				return
			default:
				if err := e.Update(v2); err != nil {
					t.Errorf("update v2: %v", err)
					return
				}
				if err := e.Update(v1); err != nil {
					t.Errorf("update v1: %v", err)
					return
				}
			}
		}
	}()

	// 未就绪候选提供者：轮换 nil / 零值 / 手拼，全部必须被拒。
	badCandidates := []*Candidate{
		nil,
		{},
		{source: CandidateSource{Kind: CandidateFromCurrent},
			policy: PolicySet{Version: "z", Rules: v1.Rules}},
	}
	var rejectedOK int64

	// 大量交替：一次未就绪（必须拒且零报告）、一次合法（必须整批单版本）。
	var rep RehearsalReport
	for i := 0; i < 300; i++ {
		bad := badCandidates[i%len(badCandidates)]
		badRep, err := e.Rehearse(resources, bad)
		var re *RehearsalError
		if err == nil || !errors.As(err, &re) ||
			(re.Reason != ErrReasonCandidateUnavailable && re.Reason != ErrReasonCandidateNotPrepared) {
			close(stopUpdate)
			updWG.Wait()
			t.Fatalf("iter %d: 未就绪候选必须被可区分拒绝, got rep=%+v err=%v", i, badRep, err)
		}
		if badRep.ResourceCount != 0 || len(badRep.Items) != 0 || badRep.Summary != (DiffSummary{}) {
			close(stopUpdate)
			updWG.Wait()
			t.Fatalf("iter %d: 被拒调用残留中间状态: %+v", i, badRep)
		}
		atomic.AddInt64(&rejectedOK, 1)

		rep, err = e.Rehearse(resources, cand)
		if err != nil {
			close(stopUpdate)
			updWG.Wait()
			t.Fatalf("iter %d: 合法预演失败: %v", i, err)
		}
		pinnedVer := rep.CurrentVersion
		pinned, ok := sets[pinnedVer]
		if !ok {
			close(stopUpdate)
			updWG.Wait()
			t.Fatalf("iter %d: 报告固定在未知/撕裂版本 %q", i, pinnedVer)
		}
		for j, d := range rep.Items {
			if d.Current.PolicyVersion != pinnedVer {
				close(stopUpdate)
				updWG.Wait()
				t.Fatalf("iter %d item %d: 版本 %s 与整批固定版本 %s 不一致(撕裂)",
					i, j, d.Current.PolicyVersion, pinnedVer)
			}
			want := evaluatePolicySet(pinned, resources[j])
			if !resultsEqual(d.Current, want) {
				close(stopUpdate)
				updWG.Wait()
				t.Fatalf("iter %d item %d: 当前列与固定版本 %s 复算不符", i, j, pinnedVer)
			}
			if d.Candidate.PolicyVersion != "hcand" {
				close(stopUpdate)
				updWG.Wait()
				t.Fatalf("iter %d item %d: 候选版本异常 %s", i, j, d.Candidate.PolicyVersion)
			}
		}
	}
	close(stopUpdate)
	updWG.Wait()

	// 抽样打印一条成功报告的输入/命中/判定/差异原因，便于从日志看到覆盖的业务。
	idx := 0
	d := rep.Items[idx]
	in, _ := json.Marshal(resources[idx])
	t.Logf("[业务:热更新下批量版本一致] 抽样 input=%s", in)
	t.Logf("[业务:热更新下批量版本一致] current: decision=%s version=%s winner=%q hits=%v",
		d.Current.Decision, d.Current.PolicyVersion, d.Current.WinningRule, hitIDs(d.Current))
	t.Logf("[业务:热更新下批量版本一致] candidate: decision=%s version=%s winner=%q hits=%v",
		d.Candidate.Decision, d.Candidate.PolicyVersion, d.Candidate.WinningRule, hitIDs(d.Candidate))
	t.Logf("[业务:热更新下批量版本一致] decisionChanged=%v reasonChanged=%v 差异原因=%s",
		d.DecisionChanged, d.ReasonChanged, d.Reason)
	t.Logf("并发热更新: %d 次未就绪候选被整份拒绝(零残留), 300 次合法预演全部整批固定在单一完整版本(%s)",
		atomic.LoadInt64(&rejectedOK), rep.CurrentVersion)

	// 收尾：被拒穿插之后，引擎仍只呈现完整的 hv1/hv2 之一。
	final := e.Evaluate(resources[0])
	if (final.PolicyVersion != "hv1" && final.PolicyVersion != "hv2") ||
		len(final.Hits) != 1 || final.Hits[0].RuleID != sets[final.PolicyVersion].Rules[0].ID {
		t.Fatalf("收尾状态异常(疑似残留中间态): %+v", final)
	}
}

// hitIDs 按命中顺序收集规则 ID（Result.Hits 已按 ID 排序）。
func hitIDs(r Result) []string {
	ids := make([]string, 0, len(r.Hits))
	for _, h := range r.Hits {
		ids = append(ids, h.RuleID)
	}
	return ids
}
