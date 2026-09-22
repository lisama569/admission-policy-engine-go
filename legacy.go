package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// 历史格式唯一支持的版本号。
const LegacyV1Version = "v1"

// 归一化后策略集使用的版本标识，便于在评估结果中追溯来源。
const legacyNormalizedVersion = "legacy-v1-normalized"

// V1PolicySet 是历史策略配置的外层结构。
type V1PolicySet struct {
	Version string   `json:"version"`
	Rules   []V1Rule `json:"rules"`
}

// V1Rule 是历史规则结构：action + weight + match。
type V1Rule struct {
	ID     string         `json:"id"`
	Action string         `json:"action"`
	Weight *int           `json:"weight,omitempty"`
	Match  map[string]any `json:"match,omitempty"`
}

// v1 规则允许的顶层字段，其余一律拒绝（防止语义被静默忽略）。
var v1RuleFields = map[string]bool{"id": true, "action": true, "weight": true, "match": true}

// v1 match 允许的字段；规则有且只能有一个，多义即拒绝。
var v1MatchFields = map[string]bool{"kind": true, "name": true, "namespace": true, "label": true}

// ConvertLegacyV1 解析并归一历史 v1 配置。
//
// 兼容范围（见 docs/legacy-format.md）：
//   - action: permit→allow、reject→deny、flag→warn；
//     advise 已废弃，按 deprecated_action 明确拒绝；其它取值按 unknown_action 拒绝。
//   - weight: 0..1000 的整数，直接映射为 priority；缺失或缺省值非法时拒绝。
//   - match: 仅支持 kind/name/namespace/label 四选一，一律按精确字符串相等
//     （op=eq）转换——历史格式未定义通配/正则语义，按 glob 猜测会引入歧义，
//     因此不安全；同时出现多个 selector 即歧义拒绝；
//     label 必须是 {"key": string, "value": string}。
//
// 任何语义不明确、未知字段或无法安全转换的规则都会让整份配置被拒绝，
// 不会静默忽略，也不会降级为放行。
func ConvertLegacyV1(raw []byte) (PolicySet, error) {
	// 先以 raw map 解析，以便对未知顶层字段做严格检测。
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&top); err != nil {
		return PolicySet{}, fmt.Errorf("legacy config is not valid JSON: %w", err)
	}
	for k := range top {
		if k != "version" && k != "rules" {
			return PolicySet{}, &ConversionError{
				Reason: ConvReasonUnknownTopField,
				Detail: fmt.Sprintf("unknown top-level field %q", k),
			}
		}
	}

	versionRaw, ok := top["version"]
	if !ok {
		return PolicySet{}, &ConversionError{Reason: ConvReasonUnsupportedVersion, Detail: "missing version"}
	}
	var version string
	if err := json.Unmarshal(versionRaw, &version); err != nil {
		return PolicySet{}, &ConversionError{Reason: ConvReasonUnsupportedVersion, Detail: "version must be a string"}
	}
	if version != LegacyV1Version {
		return PolicySet{}, &ConversionError{
			Reason: ConvReasonUnsupportedVersion,
			Detail: fmt.Sprintf("unsupported legacy version %q, only %q is supported", version, LegacyV1Version),
		}
	}

	rulesRaw, ok := top["rules"]
	if !ok {
		return PolicySet{}, &ConversionError{Reason: ConvReasonMissingMatch, Detail: "missing rules array"}
	}
	var ruleItems []json.RawMessage
	if err := json.Unmarshal(rulesRaw, &ruleItems); err != nil {
		return PolicySet{}, &ConversionError{Reason: ConvReasonUnknownTopField, Detail: "rules must be an array"}
	}

	out := PolicySet{Version: legacyNormalizedVersion, Rules: make([]Rule, 0, len(ruleItems))}
	for _, item := range ruleItems {
		r, err := convertV1Rule(item)
		if err != nil {
			return PolicySet{}, err
		}
		out.Rules = append(out.Rules, r)
	}

	// 归一后仍需通过现行策略集的全部自洽性校验（如规则 ID 重复）。
	if err := ValidatePolicySet(out); err != nil {
		return PolicySet{}, err
	}
	return out, nil
}

func convertV1Rule(raw json.RawMessage) (Rule, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Rule{}, &ConversionError{Reason: ConvReasonUnknownTopField, Detail: "rule is not a JSON object: " + err.Error()}
	}
	for k := range fields {
		if !v1RuleFields[k] {
			return Rule{}, &ConversionError{
				Reason: ConvReasonUnknownTopField,
				Detail: fmt.Sprintf("unknown rule field %q", k),
			}
		}
	}

	rule := Rule{}

	if idRaw, ok := fields["id"]; ok {
		if err := json.Unmarshal(idRaw, &rule.ID); err != nil {
			return Rule{}, &ConversionError{Reason: ConvReasonEmptyRuleID, Detail: "id must be a string"}
		}
	}
	if rule.ID == "" {
		return Rule{}, &ConversionError{Reason: ConvReasonEmptyRuleID, Detail: "every legacy rule requires a non-empty id"}
	}
	convErr := func(reason, detail string) error {
		return &ConversionError{LegacyRuleID: rule.ID, Reason: reason, Detail: detail}
	}

	actionRaw, ok := fields["action"]
	if !ok {
		return Rule{}, convErr(ConvReasonUnknownAction, "missing action")
	}
	var action string
	if err := json.Unmarshal(actionRaw, &action); err != nil {
		return Rule{}, convErr(ConvReasonUnknownAction, "action must be a string")
	}
	switch action {
	case "permit":
		rule.Effect = EffectAllow
	case "reject":
		rule.Effect = EffectDeny
	case "flag":
		rule.Effect = EffectWarn
	case "advise":
		return Rule{}, convErr(ConvReasonDeprecatedAction,
			"action \"advise\" is deprecated and cannot be mapped safely; use flag/warn instead")
	default:
		return Rule{}, convErr(ConvReasonUnknownAction, fmt.Sprintf("unknown action %q", action))
	}

	if weightRaw, ok := fields["weight"]; !ok {
		return Rule{}, convErr(ConvReasonInvalidWeight, "missing weight")
	} else {
		var weight int
		if err := json.Unmarshal(weightRaw, &weight); err != nil {
			return Rule{}, convErr(ConvReasonInvalidWeight, "weight must be an integer")
		}
		if weight < 0 || weight > 1000 {
			return Rule{}, convErr(ConvReasonInvalidWeight, fmt.Sprintf("weight %d out of allowed range 0..1000", weight))
		}
		rule.Priority = weight
	}

	matchRaw, ok := fields["match"]
	if !ok {
		return Rule{}, convErr(ConvReasonMissingMatch, "missing match")
	}
	var match map[string]json.RawMessage
	if err := json.Unmarshal(matchRaw, &match); err != nil {
		return Rule{}, convErr(ConvReasonAmbiguousMatch, "match must be an object")
	}
	if len(match) == 0 {
		return Rule{}, convErr(ConvReasonMissingMatch, "match is empty")
	}
	if len(match) > 1 {
		keys := make([]string, 0, len(match))
		for k := range match {
			keys = append(keys, k)
		}
		return Rule{}, convErr(ConvReasonAmbiguousMatch,
			fmt.Sprintf("match contains %d selectors %v; exactly one of kind/name/namespace/label is required", len(keys), keys))
	}

	var field, want string
	for sel, selRaw := range match {
		switch sel {
		case "kind", "name", "namespace":
			if !v1MatchFields[sel] {
				return Rule{}, convErr(ConvReasonUnknownMatchField, fmt.Sprintf("unknown match selector %q", sel))
			}
			var s string
			if err := json.Unmarshal(selRaw, &s); err != nil {
				return Rule{}, convErr(ConvReasonAmbiguousMatch, fmt.Sprintf("match.%s must be a string", sel))
			}
			switch sel {
			case "kind":
				field = "kind"
			case "name":
				field = "metadata.name"
			case "namespace":
				field = "metadata.namespace"
			}
			want = s
		case "label":
			var label map[string]json.RawMessage
			if err := json.Unmarshal(selRaw, &label); err != nil {
				return Rule{}, convErr(ConvReasonAmbiguousMatch, "match.label must be an object")
			}
			keyRaw, hasKey := label["key"]
			if !hasKey {
				return Rule{}, convErr(ConvReasonAmbiguousMatch, "match.label requires both \"key\" and \"value\"")
			}
			valRaw, hasVal := label["value"]
			if !hasVal {
				return Rule{}, convErr(ConvReasonAmbiguousMatch, "match.label requires \"value\"")
			}
			for k := range label {
				if k != "key" && k != "value" {
					return Rule{}, convErr(ConvReasonAmbiguousMatch, fmt.Sprintf("unknown label field %q", k))
				}
			}
			var key, val string
			if err := json.Unmarshal(keyRaw, &key); err != nil {
				return Rule{}, convErr(ConvReasonAmbiguousMatch, "label.key must be a string")
			}
			if err := json.Unmarshal(valRaw, &val); err != nil {
				return Rule{}, convErr(ConvReasonAmbiguousMatch, "label.value must be a string")
			}
			if key == "" {
				return Rule{}, convErr(ConvReasonAmbiguousMatch, "label.key must not be empty")
			}
			field = "metadata.labels." + key
			want = val
		default:
			return Rule{}, convErr(ConvReasonUnknownMatchField, fmt.Sprintf("unknown match selector %q", sel))
		}
	}

	rule.Conditions = []Condition{{Field: field, Op: OpEq, Values: []string{want}}}
	rule.Description = fmt.Sprintf("converted from legacy v1 rule (action=%s)", rule.effectLegacyName())
	return rule, nil
}

func (r Rule) effectLegacyName() string {
	switch r.Effect {
	case EffectAllow:
		return "permit"
	case EffectDeny:
		return "reject"
	case EffectWarn:
		return "flag"
	default:
		return string(r.Effect)
	}
}
