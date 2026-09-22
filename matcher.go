package policy

import (
	"fmt"
	"path"
	"strconv"
	"strings"
)

// getField 按点号路径从资源中读取字段。
// 支持 map[string]any 嵌套与 []any 数组数字索引，例如 "metadata.labels.app"、
// "spec.containers.0.image"。路径不存在、类型不可继续下钻时 present=false。
func getField(r Resource, p string) (any, bool) {
	if p == "" {
		return nil, false
	}
	var cur any = map[string]any(r)
	for _, seg := range strings.Split(p, ".") {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

// canonical 将字段值确定性地字符串化：字符串原样，数字/布尔按 Go 标准格式
// （fmt %v），nil 为 "<nil>"。比较类操作符一律基于该字符串形式。
func canonical(v any) string {
	if v == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%v", v)
}

// matchCondition 判断单个条件是否命中资源，并返回匹配事实用于解释。
// 除 exists 外，字段缺失一律视为不命中（而不是错误），因为规则只在
// 字段存在且满足约束时才应触发。
func matchCondition(r Resource, c Condition) (MatchedCondition, bool, error) {
	mc := MatchedCondition{Field: c.Field, Op: c.Op, WantValues: c.Values}
	got, present := getField(r, c.Field)
	mc.Present = present
	if present {
		mc.GotValue = canonical(got)
	}

	switch c.Op {
	case OpExists:
		return mc, present, nil
	case OpEq, OpNotEq:
		if len(c.Values) != 1 {
			return mc, false, fmt.Errorf("%w: op %s needs exactly 1 value, field %s",
				errInvalidCondition, c.Op, c.Field)
		}
		if !present {
			return mc, false, nil
		}
		eq := mc.GotValue == c.Values[0]
		if c.Op == OpEq {
			return mc, eq, nil
		}
		return mc, !eq, nil
	case OpIn, OpNotIn:
		if len(c.Values) == 0 {
			return mc, false, fmt.Errorf("%w: op %s needs at least 1 value, field %s",
				errInvalidCondition, c.Op, c.Field)
		}
		if !present {
			return mc, false, nil
		}
		in := false
		for _, v := range c.Values {
			if mc.GotValue == v {
				in = true
				break
			}
		}
		if c.Op == OpIn {
			return mc, in, nil
		}
		return mc, !in, nil
	case OpMatches:
		if len(c.Values) != 1 {
			return mc, false, fmt.Errorf("%w: op matches needs exactly 1 value, field %s",
				errInvalidCondition, c.Field)
		}
		if !present {
			return mc, false, nil
		}
		ok, err := path.Match(c.Values[0], mc.GotValue)
		if err != nil {
			return mc, false, fmt.Errorf("%w: %v", errInvalidCondition, err)
		}
		return mc, ok, nil
	default:
		return mc, false, fmt.Errorf("%w: unknown operator %q", errInvalidCondition, c.Op)
	}
}

// errInvalidCondition 供 matcher 内部复用，最终由引擎包装为可区分错误。
var errInvalidCondition = fmt.Errorf("invalid condition")

// matchRule 判断规则是否命中：规则内所有条件为 AND。
func matchRule(r Resource, rule Rule) (RuleHit, bool, error) {
	hit := RuleHit{
		RuleID:      rule.ID,
		Effect:      rule.Effect,
		Priority:    rule.Priority,
		Description: rule.Description,
	}
	for _, c := range rule.Conditions {
		mc, ok, err := matchCondition(r, c)
		if err != nil {
			return RuleHit{}, false, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		if !ok {
			return RuleHit{}, false, nil
		}
		hit.MatchedConditions = append(hit.MatchedConditions, mc)
	}
	if len(rule.Conditions) == 0 {
		// 无条件规则视为恒命中（已在校验阶段按策略允许）。
		return hit, true, nil
	}
	return hit, true, nil
}
