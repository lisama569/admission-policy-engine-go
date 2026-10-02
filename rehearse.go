package policy

import (
	"fmt"
	"sort"
	"strings"
)

// CandidateSourceKind 标识候选策略的来源格式。
type CandidateSourceKind string

const (
	// CandidateFromCurrent 表示候选直接以现行 PolicySet 格式提供。
	CandidateFromCurrent CandidateSourceKind = "current-format"
	// CandidateFromLegacyV1 表示候选来自历史 v1 JSON，已经过安全归一。
	CandidateFromLegacyV1 CandidateSourceKind = "legacy-v1"
)

// CandidateSource 记录候选策略的来源，供预演报告与切换审计追溯。
type CandidateSource struct {
	Kind   CandidateSourceKind `json:"kind"`
	Detail string              `json:"detail,omitempty"`
}

// Candidate 是一份已经过解析（历史格式）、归一化与整体校验的候选策略。
// 一旦构造成功便不可变：内部持有策略集深拷贝，调用方无法从外部改写，
// 因此同一份 Candidate 的预演结论与 Promote 生效后的结论必然一致。
type Candidate struct {
	source CandidateSource
	policy PolicySet
	// prepared 只能由 PrepareCandidate / PrepareCandidateLegacy 在归一与整体
	// 校验全部通过后置为 true。外部直接构造的零值 Candidate（含 &Candidate{}）
	// 该字段恒为 false：它不代表"一份空策略"，而是"一份从未走完准备流程、
	// 不可使用的候选"，必须在任何评估/切换之前被整份拒绝。
	prepared bool
}

// ResourceRef 是资源在预演批次中的稳定定位信息：以输入下标为主键，
// 辅以 kind/name/namespace 便于人工阅读，不要求资源自带唯一 ID。
type ResourceRef struct {
	Index     int    `json:"index"`
	Kind      string `json:"kind,omitempty"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// ResourceDiff 是单条资源在当前生效版本与候选版本下的逐条对比。
type ResourceDiff struct {
	Resource ResourceRef `json:"resource"`
	// Current/Candidate 分别是当前生效版本与候选版本下的完整、可解释结论。
	Current   Result `json:"current"`
	Candidate Result `json:"candidate"`
	// DecisionChanged 为 true 表示最终结论（allow/deny/warn）发生变化。
	DecisionChanged bool `json:"decisionChanged"`
	// ReasonChanged 为 true 表示结论虽未变，但决胜规则或命中规则集合发生变化。
	ReasonChanged bool `json:"reasonChanged"`
	// Reason 是本条差异的可读说明：从什么变成什么、决胜规则如何变化。
	Reason string `json:"reason,omitempty"`
}

// DiffSummary 是整批预演的差异汇总计数。
type DiffSummary struct {
	Total             int `json:"total"`
	Unchanged         int `json:"unchanged"`
	DecisionChanged   int `json:"decisionChanged"`
	ReasonChangedOnly int `json:"reasonChangedOnly"`
	AddedDeny         int `json:"addedDeny"`   // 新增拒绝：!deny -> deny
	RemovedDeny       int `json:"removedDeny"` // 由拒变非拒：deny -> !deny
	DenyToAllow       int `json:"denyToAllow"` // 由拒变放行
	DenyToWarn        int `json:"denyToWarn"`
	WarnToDeny        int `json:"warnToDeny"`
	WarnToAllow       int `json:"warnToAllow"`
	AllowToDeny       int `json:"allowToDeny"`
	AllowToWarn       int `json:"allowToWarn"`
	AddedWarn         int `json:"addedWarn"`   // 新增告警：!warn -> warn
	RemovedWarn       int `json:"removedWarn"` // 告警消失：warn -> !warn
}

// RehearsalReport 是一次批量预演的完整对比结果，顺序与输入资源一致。
type RehearsalReport struct {
	// CurrentVersion 是本次预演固定（pin）住的当前生效版本；预演期间
	// 线上即使发生热更新，报告内所有条目仍全部来自该版本，不会新旧混用。
	CurrentVersion   string          `json:"currentVersion"`
	CandidateVersion string          `json:"candidateVersion"`
	CandidateSource  CandidateSource `json:"candidateSource"`
	ResourceCount    int             `json:"resourceCount"`
	Items            []ResourceDiff  `json:"items"`
	Summary          DiffSummary     `json:"summary"`
}

// BatchResult 是一次批量评估的结果：整批资源固定在同一个策略版本上。
type BatchResult struct {
	PolicyVersion string   `json:"policyVersion"`
	Results       []Result `json:"results"`
}

// 预演/切换流程相关的可区分失败原因。
const (
	// ErrReasonCandidateUnavailable 表示根本没有提供候选（传了 nil）。
	ErrReasonCandidateUnavailable = "candidate_unavailable"
	// ErrReasonCandidateNotPrepared 表示候选指针非 nil，但从未经过
	// PrepareCandidate / PrepareCandidateLegacy 的归一与整体校验
	// （例如直接构造的零值 &Candidate{}、准备中途夭折留下的对象）。
	// 它不是"一份空策略"：绝不允许被当成空策略评估成默认全放行。
	ErrReasonCandidateNotPrepared = "candidate_not_prepared"
)

// RehearsalError 表示预演/切换流程本身的使用错误（区别于策略非法的
// ValidationError 与历史格式无法归一的 ConversionError）。
type RehearsalError struct {
	Reason string
	Detail string
}

func (e *RehearsalError) Error() string {
	return fmt.Sprintf("rehearsal failed (%s): %s", e.Reason, e.Detail)
}

// PrepareCandidate 以现行格式构造不可变候选。先做整体自洽性校验，通过后
// 深拷贝入藏，避免调用方在预演/切换前通过原切片改写候选。
func PrepareCandidate(ps PolicySet) (*Candidate, error) {
	if err := ValidatePolicySet(ps); err != nil {
		return nil, err
	}
	return &Candidate{
		source: CandidateSource{
			Kind:   CandidateFromCurrent,
			Detail: "provided in current policy format",
		},
		policy:   clonePolicySet(ps),
		prepared: true,
	}, nil
}

// PrepareCandidateLegacy 以历史 v1 JSON 构造候选。归一严格复用
// ConvertLegacyV1 的兼容与拒绝规则：无法安全转换即整份拒绝，
// 不会静默跳过任何规则，也不会放宽为放行。
func PrepareCandidateLegacy(raw []byte) (*Candidate, error) {
	ps, err := ConvertLegacyV1(raw)
	if err != nil {
		return nil, err
	}
	return &Candidate{
		source: CandidateSource{
			Kind:   CandidateFromLegacyV1,
			Detail: "normalized from legacy v1 JSON via ConvertLegacyV1",
		},
		policy:   clonePolicySet(ps),
		prepared: true,
	}, nil
}

// Policy 返回候选归一后策略集的深拷贝。
func (c *Candidate) Policy() PolicySet {
	return clonePolicySet(c.policy)
}

// Source 返回候选的来源格式信息。
func (c *Candidate) Source() CandidateSource {
	return c.source
}

// Ready 报告候选是否已经走完准备流程（PrepareCandidate 或
// PrepareCandidateLegacy）且通过整体校验。未就绪的候选不是"空策略"，
// Rehearse 与 Promote 都会以 candidate_not_prepared 整份拒绝它。
func (c *Candidate) Ready() bool {
	return c != nil && c.prepared
}

// pinSnapshot 在操作开始瞬间固定一个完整的策略版本。后续即使线上发生热更新，
// 本批评估仍全部基于该不可变快照，杜绝一部分资源用旧版本、一部分用新版本。
func (e *Engine) pinSnapshot() engineSnapshot {
	return *e.current.Load()
}

// EvaluateBatch 在同一个策略版本快照上评估整批资源：从开始到结束不会与
// 热更新交错，结果顺序与输入一致，不丢不重。
func (e *Engine) EvaluateBatch(resources []Resource) BatchResult {
	snap := e.pinSnapshot()
	// 一次按批大小预分配，避免中间结果反复扩容；评估是逐条就地完成的，
	// 不会产生额外的待聚合堆积。
	out := make([]Result, len(resources))
	for i, r := range resources {
		out[i] = evaluatePolicySet(snap.policySet, r)
	}
	return BatchResult{PolicyVersion: snap.policySet.Version, Results: out}
}

// Rehearse 对一批资源同时按当前生效版本与候选版本评估，输出确定性的对比报告。
// 整批固定在预演开始瞬间的当前版本上；候选不可用或被拒绝时返回错误，
// 不产生任何部分结果。候选评估直接复用线上评估的同一函数
// （evaluatePolicySet），因此报告里的候选结论与候选真正 Promote 生效后
// 对同一批资源的结论逐条一致。
func (e *Engine) Rehearse(resources []Resource, c *Candidate) (RehearsalReport, error) {
	if err := requireCandidate(c); err != nil {
		return RehearsalReport{}, err
	}
	// 先固定当前版本，再取候选版本：整个报告自始至终引用这两个不可变快照。
	snap := e.pinSnapshot()
	cand := clonePolicySet(c.policy)

	report := RehearsalReport{
		CurrentVersion:   snap.policySet.Version,
		CandidateVersion: cand.Version,
		CandidateSource:  c.source,
		ResourceCount:    len(resources),
		Items:            make([]ResourceDiff, len(resources)),
	}
	for i, r := range resources {
		cur := evaluatePolicySet(snap.policySet, r)
		newRes := evaluatePolicySet(cand, r)
		report.Items[i] = buildResourceDiff(i, r, cur, newRes)
	}
	report.Summary = summarize(report.Items)
	return report, nil
}

// Promote 将候选策略原子切换为新生效版本：要么整份生效，要么完全不生效。
// 并发评估只能看到完整的旧版本或完整的新版本（atomic 指针一次切换）。
// 候选在 Prepare 阶段已完成归一与校验，这里只做一次防御性复查：若复查
// 失败则原版本原封不动，不会出现半生效状态。
func (e *Engine) Promote(c *Candidate) error {
	if err := requireCandidate(c); err != nil {
		return err
	}
	next := clonePolicySet(c.policy)
	if err := ValidatePolicySet(next); err != nil {
		return err
	}
	e.current.Store(&engineSnapshot{policySet: next})
	return nil
}

// requireCandidate 是 Rehearse 与 Promote 共用的、也是唯一的候选可用性
// 判定入口：两者对同一个候选对象"能不能用"的回答在构造上必然一致，不会
// 出现预演放行、切换被拒（或反过来）的分歧。
//
// 未就绪候选绝不能进入 evaluatePolicySet：否则零规则命中会按默认放行，
// 凭空得到一份"全放行、空版本号"的误导性报告。
func requireCandidate(c *Candidate) error {
	if c == nil {
		return &RehearsalError{
			Reason: ErrReasonCandidateUnavailable,
			Detail: "no candidate provided (nil); prepare it with PrepareCandidate or PrepareCandidateLegacy",
		}
	}
	if !c.prepared {
		return &RehearsalError{
			Reason: ErrReasonCandidateNotPrepared,
			Detail: "candidate was never prepared or failed preparation; " +
				"build it with PrepareCandidate or PrepareCandidateLegacy instead of constructing Candidate directly",
		}
	}
	return nil
}

// buildResourceDiff 对单条资源的两份结论做结构化对比。命中规则集合与决胜
// 规则均按 ID 比较，与规则加载顺序无关，因此相同输入重复预演，差异结论
// 与输出顺序完全一致。
func buildResourceDiff(index int, r Resource, cur, cand Result) ResourceDiff {
	curHits := hitIDSet(cur)
	candHits := hitIDSet(cand)
	decisionChanged := cur.Decision != cand.Decision
	reasonChanged := !decisionChanged &&
		(cur.WinningRule != cand.WinningRule || !sameStringSet(curHits, candHits))

	d := ResourceDiff{
		Resource:        resourceRef(index, r),
		Current:         cur,
		Candidate:       cand,
		DecisionChanged: decisionChanged,
		ReasonChanged:   reasonChanged,
		Reason:          explainDiff(cur, cand, curHits, candHits, decisionChanged, reasonChanged),
	}
	return d
}

func resourceRef(index int, r Resource) ResourceRef {
	ref := ResourceRef{Index: index}
	if v, ok := getField(r, "kind"); ok {
		ref.Kind = canonical(v)
	}
	if v, ok := getField(r, "metadata.name"); ok {
		ref.Name = canonical(v)
	}
	if v, ok := getField(r, "metadata.namespace"); ok {
		ref.Namespace = canonical(v)
	}
	return ref
}

func hitIDSet(res Result) map[string]struct{} {
	set := make(map[string]struct{}, len(res.Hits))
	for _, h := range res.Hits {
		set[h.RuleID] = struct{}{}
	}
	return set
}

func sameStringSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func explainDiff(cur, cand Result, curHits, candHits map[string]struct{},
	decisionChanged, reasonChanged bool) string {
	var b strings.Builder
	switch {
	case decisionChanged:
		fmt.Fprintf(&b, "decision changed: %s -> %s", cur.Decision, cand.Decision)
	case reasonChanged:
		b.WriteString("decision unchanged, but basis changed")
	default:
		b.WriteString("no change")
	}
	fmt.Fprintf(&b, " (policy %s -> %s); current winner=%q candidate winner=%q",
		cur.PolicyVersion, cand.PolicyVersion, cur.WinningRule, cand.WinningRule)
	if added := setDiff(candHits, curHits); len(added) > 0 {
		fmt.Fprintf(&b, "; newly matched rules=%v", added)
	}
	if removed := setDiff(curHits, candHits); len(removed) > 0 {
		fmt.Fprintf(&b, "; no-longer-matched rules=%v", removed)
	}
	if !decisionChanged && !reasonChanged {
		b.WriteString("; same winning rule and matched rule set")
	}
	return b.String()
}

// setDiff 返回 in 有、other 没有的元素，按字典序排列。
func setDiff(in, other map[string]struct{}) []string {
	var out []string
	for k := range in {
		if _, ok := other[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// summarize 只依赖逐条结果做纯函数式聚合，逐条顺序处理，无额外中间堆积。
func summarize(items []ResourceDiff) DiffSummary {
	s := DiffSummary{Total: len(items)}
	for _, d := range items {
		from, to := d.Current.Decision, d.Candidate.Decision
		switch {
		case d.DecisionChanged:
			s.DecisionChanged++
		case d.ReasonChanged:
			s.ReasonChangedOnly++
		default:
			s.Unchanged++
		}
		switch {
		case from == DecisionDeny && to == DecisionAllow:
			s.RemovedDeny++
			s.DenyToAllow++
		case from == DecisionDeny && to == DecisionWarn:
			s.RemovedDeny++
			s.DenyToWarn++
			s.AddedWarn++
		case from == DecisionWarn && to == DecisionDeny:
			s.AddedDeny++
			s.RemovedWarn++
			s.WarnToDeny++
		case from == DecisionWarn && to == DecisionAllow:
			s.RemovedWarn++
			s.WarnToAllow++
		case from == DecisionAllow && to == DecisionDeny:
			s.AddedDeny++
			s.AllowToDeny++
		case from == DecisionAllow && to == DecisionWarn:
			s.AddedWarn++
			s.AllowToWarn++
		}
	}
	return s
}

// Text 输出人类可读的预演对比报告：头部给出固定的两个版本与候选来源，
// 随后是差异汇总，最后按输入顺序逐条列出结论变化与命中规则依据。
func (r RehearsalReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Rehearsal report: current=%s candidate=%s (source=%s), %d resource(s)\n",
		r.CurrentVersion, r.CandidateVersion, r.CandidateSource.Kind, r.ResourceCount)
	s := r.Summary
	fmt.Fprintf(&b, "Summary: unchanged=%d decision-changed=%d basis-only-changed=%d total=%d\n",
		s.Unchanged, s.DecisionChanged, s.ReasonChangedOnly, s.Total)
	fmt.Fprintf(&b, "  added deny:   %d (allow->deny=%d, warn->deny=%d)\n",
		s.AddedDeny, s.AllowToDeny, s.WarnToDeny)
	fmt.Fprintf(&b, "  removed deny: %d (deny->allow=%d, deny->warn=%d)\n",
		s.RemovedDeny, s.DenyToAllow, s.DenyToWarn)
	fmt.Fprintf(&b, "  added warn:   %d (allow->warn=%d, deny->warn=%d)\n",
		s.AddedWarn, s.AllowToWarn, s.DenyToWarn)
	fmt.Fprintf(&b, "  removed warn: %d (warn->allow=%d, warn->deny=%d)\n",
		s.RemovedWarn, s.WarnToAllow, s.WarnToDeny)

	for _, d := range r.Items {
		ref := d.Resource
		fmt.Fprintf(&b, "\n[%d] kind=%s name=%q namespace=%q\n",
			ref.Index, ref.Kind, ref.Name, ref.Namespace)
		mark := "="
		if d.DecisionChanged {
			mark = "!"
		} else if d.ReasonChanged {
			mark = "~"
		}
		fmt.Fprintf(&b, "  %s %s -> %s | %s\n", mark, d.Current.Decision, d.Candidate.Decision, d.Reason)
		writeResultHits(&b, "current  ", d.Current)
		writeResultHits(&b, "candidate", d.Candidate)
	}
	return b.String()
}

func writeResultHits(b *strings.Builder, side string, res Result) {
	if len(res.Hits) == 0 {
		fmt.Fprintf(b, "    %s: no rule matched (default allow)\n", side)
		return
	}
	ids := make([]string, 0, len(res.Hits))
	byID := make(map[string]RuleHit, len(res.Hits))
	for _, h := range res.Hits {
		ids = append(ids, h.RuleID)
		byID[h.RuleID] = h
	}
	sort.Strings(ids)
	for _, id := range ids {
		h := byID[id]
		win := ""
		if id == res.WinningRule {
			win = " [WINNER]"
		}
		fmt.Fprintf(b, "    %s hit %s effect=%s priority=%d%s\n",
			side, h.RuleID, h.Effect, h.Priority, win)
		for _, mc := range h.MatchedConditions {
			fmt.Fprintf(b, "        field=%s op=%s want=%v got=%q present=%v\n",
				mc.Field, mc.Op, mc.WantValues, mc.GotValue, mc.Present)
		}
	}
}
