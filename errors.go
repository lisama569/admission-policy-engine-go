package policy

import "fmt"

// 校验新格式策略集时的可区分失败原因。
const (
	ErrReasonEmptyPolicyVersion = "empty_policy_version"
	ErrReasonEmptyRuleID        = "empty_rule_id"
	ErrReasonDuplicateRuleID    = "duplicate_rule_id"
	ErrReasonInvalidEffect      = "invalid_effect"
	ErrReasonInvalidOperator    = "invalid_operator"
	ErrReasonEmptyField         = "empty_condition_field"
	ErrReasonMissingValue       = "missing_condition_value"
	ErrReasonInvalidGlob        = "invalid_glob_pattern"
	ErrReasonEmptyConditions    = "empty_conditions"
)

// ValidationError 表示新格式策略集整体校验失败，更新必须被整体拒绝。
type ValidationError struct {
	Reason string
	Detail string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("policy validation failed (%s): %s", e.Reason, e.Detail)
}

// 历史 v1 格式转换时的可区分失败原因。
const (
	ConvReasonUnsupportedVersion = "unsupported_version"
	ConvReasonEmptyRuleID        = "empty_legacy_rule_id"
	ConvReasonUnknownAction      = "unknown_action"
	ConvReasonDeprecatedAction   = "deprecated_action"
	ConvReasonInvalidWeight      = "invalid_weight"
	ConvReasonMissingMatch       = "missing_match"
	ConvReasonAmbiguousMatch     = "ambiguous_match"
	ConvReasonUnknownMatchField  = "unknown_match_field"
	ConvReasonUnknownTopField    = "unknown_top_level_field"
)

// ConversionError 表示某条历史规则无法被安全、无歧义地归一。
type ConversionError struct {
	LegacyRuleID string
	Reason       string
	Detail       string
}

func (e *ConversionError) Error() string {
	return fmt.Sprintf("legacy rule %q conversion failed (%s): %s", e.LegacyRuleID, e.Reason, e.Detail)
}
