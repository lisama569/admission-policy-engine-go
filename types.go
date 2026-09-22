package policy

// Effect 是规则命中后产生的效果。
type Effect string

const (
	EffectAllow Effect = "allow" // 放行
	EffectDeny  Effect = "deny"  // 拒绝
	EffectWarn  Effect = "warn"  // 告警（不阻断，但要求显式确认）
)

// Operator 是条件支持的匹配操作符。
type Operator string

const (
	OpEq      Operator = "eq"      // 字段存在且字符串化后等于 Values[0]
	OpNotEq   Operator = "neq"     // 字段存在且字符串化后不等于 Values[0]
	OpIn      Operator = "in"      // 字段存在且字符串化后属于 Values 集合
	OpNotIn   Operator = "notin"   // 字段存在且字符串化后不属于 Values 集合
	OpMatches Operator = "matches" // 字段存在且字符串化后匹配 glob（path.Match 语法）
	OpExists  Operator = "exists"  // 字段存在
)

// Condition 描述对资源单个字段的判断；同一条规则内多个条件为 AND 语义。
type Condition struct {
	Field  string   `json:"field"`
	Op     Operator `json:"op"`
	Values []string `json:"values,omitempty"`
}

// Rule 是归一化后的准入规则。
type Rule struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	// Priority 数值越大优先级越高；同优先级按效果与规则 ID 确定性决胜。
	Priority   int         `json:"priority"`
	Effect     Effect      `json:"effect"`
	Conditions []Condition `json:"conditions"`
}

// PolicySet 是一次生效的完整策略集（一个不可变版本）。
type PolicySet struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

// Resource 是待评估资源，使用嵌套 map（类 Kubernetes 结构）。
type Resource map[string]any

// Decision 是对资源的最终准入结论。
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionWarn  Decision = "warn"
)

// RuleHit 记录一条命中的规则及其判定依据。
type RuleHit struct {
	RuleID      string `json:"ruleId"`
	Effect      Effect `json:"effect"`
	Priority    int    `json:"priority"`
	Description string `json:"description,omitempty"`
	// MatchedConditions 列出实际命中的条件（字段、操作符、实际值）。
	MatchedConditions []MatchedCondition `json:"matchedConditions"`
}

// MatchedCondition 描述一个条件与资源实际值的匹配事实。
type MatchedCondition struct {
	Field      string   `json:"field"`
	Op         Operator `json:"op"`
	WantValues []string `json:"wantValues,omitempty"`
	GotValue   string   `json:"gotValue"`
	Present    bool     `json:"present"`
}

// Result 是一次评估的完整、可解释结论。
type Result struct {
	Decision      Decision `json:"decision"`
	PolicyVersion string   `json:"policyVersion"`
	// Hits 为全部命中规则，按规则 ID 字典序排列，与加载顺序无关。
	Hits []RuleHit `json:"hits"`
	// WinningRule 是按确定性优先级规则决胜出的规则 ID；无命中时为空。
	WinningRule string `json:"winningRule,omitempty"`
	// Reason 是最终结论的文字依据。
	Reason string `json:"reason"`
}
