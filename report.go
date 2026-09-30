package policy

import (
	"fmt"
	"strings"
)

// RenderReport 把预演报告渲染为可读的纯文本：
//  1. 头部：当前版本、候选版本与来源格式（现行/历史 v1）；
//  2. 汇总：总数、变化数、新增拒绝、由拒变放行（不再拒绝）、告警增减，
//     以及按 "旧->新" 排列的结论迁移明细；
//  3. 逐条：只展开结论发生变化的资源，按输入位置排序，列出旧/新结论、
//     两侧决胜规则、两侧命中规则及差异原因。结论未变的资源默认折叠为计数。
//
// 输出是确定性的：相同报告渲染出的文本逐字节一致。
func RenderReport(rep *PreviewReport) string {
	if rep == nil {
		return ""
	}
	var b strings.Builder

	fmt.Fprintf(&b, "Policy preview report\n")
	fmt.Fprintf(&b, "  current policy:   version=%s\n", rep.CurrentVersion)
	fmt.Fprintf(&b, "  candidate policy: version=%s source=%s\n", rep.CandidateVersion, rep.CandidateSource)

	s := rep.Summary
	fmt.Fprintf(&b, "Summary: total=%d changed=%d unchanged=%d newlyDenied=%d noLongerDenied=%d warningsAdded=%d warningsRemoved=%d\n",
		s.Total, s.Changed, s.Unchanged, s.NewlyDenied, s.NoLongerDenied, s.WarningsAdded, s.WarningsRemoved)

	if len(s.DecisionTransitions) > 0 {
		b.WriteString("  decision transitions:\n")
		for _, k := range sortedTransitionKeys(s.DecisionTransitions) {
			fmt.Fprintf(&b, "    %s: %d\n", k, s.DecisionTransitions[k])
		}
	}

	if s.Changed == 0 {
		b.WriteString("No decision changes: every resource keeps its current decision.\n")
		return b.String()
	}

	b.WriteString("Changed resources (in input order):\n")
	for _, it := range rep.Items {
		if !it.Changed {
			continue
		}
		fmt.Fprintf(&b, "  [#%d] decision %s -> %s\n", it.Position, it.Current.Decision, it.Candidate.Decision)
		fmt.Fprintf(&b, "      current:   winner=%q hits=%s\n",
			winnerOrNone(it.Current), ruleIDList(it.Current.Hits))
		fmt.Fprintf(&b, "      candidate: winner=%q hits=%s\n",
			winnerOrNone(it.Candidate), ruleIDList(it.Candidate.Hits))
		b.WriteString("      reason: " + it.Reason + "\n")
	}
	return b.String()
}

func winnerOrNone(r Result) string {
	if r.WinningRule == "" {
		return "<none:default-allow>"
	}
	return r.WinningRule
}

// ruleIDList 输出按规则 ID 排序后的命中列表（Result.Hits 本身已排序）。
func ruleIDList(hits []RuleHit) string {
	if len(hits) == 0 {
		return "[]"
	}
	ids := make([]string, len(hits))
	for i, h := range hits {
		ids[i] = h.RuleID
	}
	return "[" + strings.Join(ids, ", ") + "]"
}

// sortedTransitionKeys 对迁移键排序，保证渲染顺序确定；
// 键形如 "deny->allow"，字典序即可给出稳定可读的顺序。
func sortedTransitionKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}
