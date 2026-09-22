package policy

import (
	"fmt"
	"path"
	"sort"
	"sync/atomic"
)

// engineSnapshot 是一次原子生效的不可变策略版本。一旦构造完成便不再修改，
// 评估方只需持有该指针，就能保证看到完整的旧版本或完整的新版本。
type engineSnapshot struct {
	policySet PolicySet
}

// Engine 支持并发评估与原子热更新的准入引擎。
// 零值不可用，必须通过 NewEngine 构造。
type Engine struct {
	current atomic.Pointer[engineSnapshot]
}

// NewEngine 用已校验的初始策略集构造引擎；校验失败返回错误。
func NewEngine(ps PolicySet) (*Engine, error) {
	if err := ValidatePolicySet(ps); err != nil {
		return nil, err
	}
	e := &Engine{}
	e.current.Store(&engineSnapshot{policySet: clonePolicySet(ps)})
	return e, nil
}

// ValidatePolicySet 对策略集做整体自洽性校验；任一规则非法则整体失败，
// 调用方必须拒绝整个策略集，不得部分加载。
func ValidatePolicySet(ps PolicySet) error {
	if ps.Version == "" {
		return &ValidationError{Reason: ErrReasonEmptyPolicyVersion, Detail: "policy set version is required"}
	}
	seen := make(map[string]bool, len(ps.Rules))
	for _, r := range ps.Rules {
		if r.ID == "" {
			return &ValidationError{Reason: ErrReasonEmptyRuleID, Detail: "every rule requires a non-empty id"}
		}
		if seen[r.ID] {
			return &ValidationError{Reason: ErrReasonDuplicateRuleID, Detail: fmt.Sprintf("duplicate rule id %q", r.ID)}
		}
		seen[r.ID] = true

		switch r.Effect {
		case EffectAllow, EffectDeny, EffectWarn:
		default:
			return &ValidationError{
				Reason: ErrReasonInvalidEffect,
				Detail: fmt.Sprintf("rule %q has invalid effect %q", r.ID, r.Effect),
			}
		}

		if len(r.Conditions) == 0 {
			return &ValidationError{
				Reason: ErrReasonEmptyConditions,
				Detail: fmt.Sprintf("rule %q has no conditions; unconditional rules are not allowed", r.ID),
			}
		}
		for _, c := range r.Conditions {
			if err := validateCondition(r.ID, c); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCondition(ruleID string, c Condition) error {
	if c.Field == "" {
		return &ValidationError{
			Reason: ErrReasonEmptyField,
			Detail: fmt.Sprintf("rule %q contains a condition with an empty field", ruleID),
		}
	}
	switch c.Op {
	case OpEq, OpNotEq, OpMatches:
		if len(c.Values) != 1 {
			return &ValidationError{
				Reason: ErrReasonMissingValue,
				Detail: fmt.Sprintf("rule %q field %q: op %s requires exactly one value", ruleID, c.Field, c.Op),
			}
		}
	case OpIn, OpNotIn:
		if len(c.Values) == 0 {
			return &ValidationError{
				Reason: ErrReasonMissingValue,
				Detail: fmt.Sprintf("rule %q field %q: op %s requires at least one value", ruleID, c.Field, c.Op),
			}
		}
	case OpExists:
		// exists 不需要 Values。
	default:
		return &ValidationError{
			Reason: ErrReasonInvalidOperator,
			Detail: fmt.Sprintf("rule %q field %q has invalid operator %q", ruleID, c.Field, c.Op),
		}
	}
	if c.Op == OpMatches {
		if _, err := path.Match(c.Values[0], ""); err != nil {
			return &ValidationError{
				Reason: ErrReasonInvalidGlob,
				Detail: fmt.Sprintf("rule %q field %q: %v", ruleID, c.Field, err),
			}
		}
	}
	return nil
}

// effectRank 定义同优先级下效果的决胜顺序：deny > warn > allow。
func effectRank(e Effect) int {
	switch e {
	case EffectDeny:
		return 3
	case EffectWarn:
		return 2
	case EffectAllow:
		return 1
	default:
		return 0
	}
}

// chooseWinner 从全部命中规则中确定性地选出决胜规则：
//  1. 优先级（priority）数值最大者；
//  2. 同优先级时按效果 deny > warn > allow；
//  3. 仍然相同时按规则 ID 字典序最小者。
//
// 该顺序与规则加载顺序完全无关，因此冲突结论可复现、可解释。
func chooseWinner(hits []RuleHit) RuleHit {
	winner := hits[0]
	for _, h := range hits[1:] {
		if higherPriority(h, winner) {
			winner = h
		}
	}
	return winner
}

func higherPriority(a, b RuleHit) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if ra, rb := effectRank(a.Effect), effectRank(b.Effect); ra != rb {
		return ra > rb
	}
	return a.RuleID < b.RuleID
}

// Evaluate 基于当前生效版本对资源做确定性评估。
// 无任何规则命中时结论为 allow（默认放行），并在 Reason 中明确说明。
func (e *Engine) Evaluate(r Resource) Result {
	snap := e.current.Load()
	ps := snap.policySet

	hits := make([]RuleHit, 0)
	for _, rule := range ps.Rules {
		h, ok, err := matchRule(r, rule)
		if err != nil {
			// 引擎内的策略集均经过校验，匹配期不应出现非法操作符/取值；
			// 若真的发生，按失败闭合（fail-closed）处理为 deny，绝不静默放行。
			return Result{
				Decision:      DecisionDeny,
				PolicyVersion: ps.Version,
				Reason:        "evaluation internal error (fail-closed): " + err.Error(),
			}
		}
		if ok {
			hits = append(hits, h)
		}
	}

	// 命中列表按规则 ID 排序，保证可复现的解释输出。
	sort.Slice(hits, func(i, j int) bool { return hits[i].RuleID < hits[j].RuleID })

	res := Result{PolicyVersion: ps.Version, Hits: hits}
	if len(hits) == 0 {
		res.Decision = DecisionAllow
		res.Reason = "no rule matched; default decision is allow"
		return res
	}

	winner := chooseWinner(hits)
	res.WinningRule = winner.RuleID
	res.Reason = explainWinner(winner, len(hits))
	switch winner.Effect {
	case EffectDeny:
		res.Decision = DecisionDeny
	case EffectWarn:
		res.Decision = DecisionWarn
	default:
		res.Decision = DecisionAllow
	}
	return res
}

func explainWinner(w RuleHit, hitCount int) string {
	return fmt.Sprintf(
		"%d rule(s) matched; winner is %q (priority=%d, effect=%s) under tie-break deny>warn>allow then rule-id; effect applied to decision",
		hitCount, w.RuleID, w.Priority, w.Effect)
}

// Update 原子替换策略集：先完整校验新版本，通过后一次性切换快照指针。
// 校验失败时原版本保持不变，并返回可区分的 ValidationError。
func (e *Engine) Update(ps PolicySet) error {
	if err := ValidatePolicySet(ps); err != nil {
		return err
	}
	e.current.Store(&engineSnapshot{policySet: clonePolicySet(ps)})
	return nil
}

// Current 返回当前生效策略集的深拷贝，调用方修改不会影响引擎内部版本。
func (e *Engine) Current() PolicySet {
	snap := e.current.Load()
	return clonePolicySet(snap.policySet)
}

func clonePolicySet(ps PolicySet) PolicySet {
	out := PolicySet{Version: ps.Version, Rules: make([]Rule, len(ps.Rules))}
	for i, r := range ps.Rules {
		cp := Rule{
			ID:          r.ID,
			Description: r.Description,
			Priority:    r.Priority,
			Effect:      r.Effect,
			Conditions:  make([]Condition, len(r.Conditions)),
		}
		for j, c := range r.Conditions {
			vals := make([]string, len(c.Values))
			copy(vals, c.Values)
			cp.Conditions[j] = Condition{Field: c.Field, Op: c.Op, Values: vals}
		}
		out.Rules[i] = cp
	}
	return out
}
