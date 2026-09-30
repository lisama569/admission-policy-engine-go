package policy

import (
	"fmt"
	"sync"
)

// BatchOptions 控制批量预演/批量评估的执行方式。
// 零值即可用：串行执行、单批处理全部资源。
type BatchOptions struct {
	// Workers 是并行评估的 worker 数；<=0 表示串行。
	// 无论取何值，输出顺序都严格等于输入顺序。
	Workers int
	// ChunkSize 是每个 worker 一次领取的任务条数，用于限制在途中间结果规模
	// （在途结果至多 Workers*ChunkSize 条）；<=0 表示不做分块。
	ChunkSize int
}

// PreviewItem 是单条资源在当前版本与候选版本下的对比结论。
type PreviewItem struct {
	// Position 是该资源在输入切片中的下标（从 0 开始）。
	Position int `json:"position"`
	// Current 是当前生效版本下的结论。
	Current Result `json:"current"`
	// Candidate 是候选版本下的结论。
	Candidate Result `json:"candidate"`
	// Changed 为 true 当且仅当最终结论（allow/deny/warn）发生变化。
	Changed bool `json:"changed"`
	// Reason 用一句话说明差异：从什么结论变成什么结论、决胜规则如何变化；
	// 结论未变时为空。
	Reason string `json:"reason,omitempty"`
}

// PreviewSummary 是整批预演的汇总统计。
type PreviewSummary struct {
	Total               int            `json:"total"`
	Changed             int            `json:"changed"`
	Unchanged           int            `json:"unchanged"`
	NewlyDenied         int            `json:"newlyDenied"`         // 当前非 deny、候选 deny
	NoLongerDenied      int            `json:"noLongerDenied"`      // 当前 deny、候选非 deny（由拒变放行/告警）
	WarningsAdded       int            `json:"warningsAdded"`       // 当前非 warn、候选 warn
	WarningsRemoved     int            `json:"warningsRemoved"`     // 当前 warn、候选非 warn
	DecisionTransitions map[string]int `json:"decisionTransitions"` // 形如 "deny->allow" 的结论迁移计数（仅统计发生变化的）
}

// PreviewReport 是一次批量预演的完整结果。
// Items 顺序严格等于输入资源顺序，重复预演同一份输入产出完全一致的报告。
type PreviewReport struct {
	CurrentVersion   string          `json:"currentVersion"`
	CandidateVersion string          `json:"candidateVersion"`
	CandidateSource  CandidateSource `json:"candidateSource"`
	Summary          PreviewSummary  `json:"summary"`
	Items            []PreviewItem   `json:"items"`
}

// BatchResult 是 EvaluateBatch 的单条输出（位置与输入一一对应）。
type BatchResult struct {
	Position int    `json:"position"`
	Result   Result `json:"result"`
}

// Preview 对整批资源分别按当前生效版本与候选版本评估，输出确定性的对比报告。
//
// 一致性保证：
//   - 开始时一次性固定当前版本快照，整批（当前侧 + 候选侧）都落在同一对
//     （当前版本, 候选版本）上；预演期间线上热更新不影响本次预演，不会出现
//     一部分资源用旧版本、一部分用新版本的情况；
//   - 输出顺序与输入顺序严格一致，同输入重复预演报告（差异清单与顺序）完全一致；
//   - 候选侧与候选策略真正生效后调用的是同一个评估核心（evaluateWithSet），
//     候选结论必然等于生效后结论；
//   - 分块 + 固定 worker 数执行，在途中间结果有界，支持一次几百到几千条资源，
//     不丢、不重。
//
// 候选未经 PrepareCandidate* 准备（或为 nil）时整份拒绝，返回
// *ValidationError（candidate_not_prepared），不会产出半截报告。
func (e *Engine) Preview(resources []Resource, c *PreparedCandidate, opts BatchOptions) (*PreviewReport, error) {
	if !c.prepared() {
		return nil, &ValidationError{
			Reason: ErrReasonCandidateNotPrepared,
			Detail: "preview requires a candidate prepared via PrepareCandidateNative/PrepareCandidateLegacy",
		}
	}

	// 整个预演只在入口读取一次当前快照；后续即便发生热更新，本次预演的
	// 当前侧与候选侧版本配对也保持不变。
	snap := e.current.Load()
	currentSet := snap.policySet
	candidateSet := c.policy

	items := make([]PreviewItem, len(resources))
	mapBatch(len(resources), opts, func(pos int) {
		r := resources[pos]
		cur := evaluateWithSet(r, currentSet)
		cand := evaluateWithSet(r, candidateSet)
		items[pos] = PreviewItem{
			Position:  pos,
			Current:   cur,
			Candidate: cand,
			Changed:   cur.Decision != cand.Decision,
		}
	})

	rep := &PreviewReport{
		CurrentVersion:   currentSet.Version,
		CandidateVersion: candidateSet.Version,
		CandidateSource:  c.source,
		Items:            items,
	}
	rep.Summary = summarize(items)

	// 差异原因依赖汇总后的确定性格式，统一在所有结论落位后生成，
	// 避免并行写字符串带来任何顺序不确定性。
	for i := range items {
		if items[i].Changed {
			items[i].Reason = diffReason(items[i])
		}
	}
	return rep, nil
}

// EvaluateBatch 按当前生效版本批量评估资源，结果位置与输入一一对应、顺序稳定。
// 与 Preview 相同：整批固定在开始时的同一个策略快照上，期间热更新不会造成
// 一部分资源用旧版本、一部分用新版本。
func (e *Engine) EvaluateBatch(resources []Resource, opts BatchOptions) []BatchResult {
	snap := e.current.Load()
	set := snap.policySet

	out := make([]BatchResult, len(resources))
	mapBatch(len(resources), opts, func(pos int) {
		out[pos] = BatchResult{Position: pos, Result: evaluateWithSet(resources[pos], set)}
	})
	return out
}

// mapBatch 以有界 worker 池对 [0,n) 的每个下标执行一次 fn。
// fn 按下标直接写入预分配结果，因此即便并行执行，输出顺序仍与输入一致；
// 任务以 chunk 为单位派发，在途 fn 数不超过 workers、每个 worker 一次只
// 处理一个 chunk，在途中间结果规模有界。fn 恰好对每个下标执行一次，不丢不重。
func mapBatch(n int, opts BatchOptions, fn func(pos int)) {
	if n == 0 {
		return
	}
	workers := opts.Workers
	if workers <= 0 || workers > n {
		workers = 1
	}
	chunk := opts.ChunkSize
	if chunk <= 0 || chunk > n {
		chunk = n
	}

	chunks := make(chan [2]int, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rng := range chunks {
				for pos := rng[0]; pos < rng[1]; pos++ {
					fn(pos)
				}
			}
		}()
	}
	for start := 0; start < n; start += chunk {
		end := start + chunk
		if end > n {
			end = n
		}
		chunks <- [2]int{start, end}
	}
	close(chunks)
	wg.Wait()
}

// summarize 统计结论迁移；只依赖已按位置落位的 items，结果确定。
func summarize(items []PreviewItem) PreviewSummary {
	s := PreviewSummary{
		Total:               len(items),
		DecisionTransitions: map[string]int{},
	}
	for _, it := range items {
		cur, cand := it.Current.Decision, it.Candidate.Decision
		if cur == cand {
			s.Unchanged++
			continue
		}
		s.Changed++
		s.DecisionTransitions[string(cur)+"->"+string(cand)]++
		if cand == DecisionDeny && cur != DecisionDeny {
			s.NewlyDenied++
		}
		if cur == DecisionDeny && cand != DecisionDeny {
			s.NoLongerDenied++
		}
		if cand == DecisionWarn && cur != DecisionWarn {
			s.WarningsAdded++
		}
		if cur == DecisionWarn && cand != DecisionWarn {
			s.WarningsRemoved++
		}
	}
	return s
}

// diffReason 给出一条变化项的一句话依据：结论迁移方向、两侧决胜规则。
func diffReason(it PreviewItem) string {
	curWinner, candWinner := it.Current.WinningRule, it.Candidate.WinningRule
	if curWinner == "" {
		curWinner = "<none:default-allow>"
	}
	if candWinner == "" {
		candWinner = "<none:default-allow>"
	}
	return fmt.Sprintf("decision %s -> %s; winning rule %q -> %q; candidate: %s",
		it.Current.Decision, it.Candidate.Decision, curWinner, candWinner, it.Candidate.Reason)
}
