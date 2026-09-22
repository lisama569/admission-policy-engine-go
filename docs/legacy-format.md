# 历史策略格式（v1）兼容转换

入口：`ConvertLegacyV1(raw []byte) (PolicySet, error)`。转换产物会再通过
一遍现行 `ValidatePolicySet` 自洽性校验，然后才能装入引擎参与评估。
归一后的版本标识为 `legacy-v1-normalized`，可在评估结果中追溯来源。

## 历史格式

```json
{
  "version": "v1",
  "rules": [
    {"id": "r1", "action": "reject", "weight": 500,
     "match": {"label": {"key": "env", "value": "prod"}}}
  ]
}
```

## 兼容范围（只有这些被接受）

- 顶层只允许 `version` 与 `rules`；`version` 必须恰好为 `"v1"`。
- 规则只允许字段 `id` / `action` / `weight` / `match`，任何未知字段拒绝。
- `action` 映射：`permit→allow`、`reject→deny`、`flag→warn`。
  - `advise` 历史语义不明（既非放行也非明确告警），**废弃且拒绝**
    （`deprecated_action`），不做猜测映射；
  - 其它未知 action 一律 `unknown_action` 拒绝。
- `weight` 必填，必须是 **JSON 整数**且在 `0..1000`，直接映射为
  `priority`；缺失、越界、小数、非数字均为 `invalid_weight`。
- `match` 必填，是一个对象，且**有且仅有一个**选择器：
  - `{"kind": "X"}`        → `kind eq X`
  - `{"name": "X"}`        → `metadata.name eq X`
  - `{"namespace": "X"}`   → `metadata.namespace eq X`
  - `{"label": {"key": "K", "value": "V"}}`
    → `metadata.labels.K eq V`（label 对象只允许 key/value，key 非空）
  - 所有匹配一律按**精确字符串相等**转换。旧格式没有定义通配/正则语义，
    若把 `edge-*` 之类的值擅自解释为 glob 属于无依据的语义假设，可能放大
    或缩小命中范围，因此不做这种转换。
- 空 match、多个选择器并存（AND 还是 OR 不明确）、未知选择器、label
  缺字段/多字段/空 key 等，分别以 `missing_match` / `ambiguous_match` /
  `unknown_match_field` 拒绝。

## 安全原则

语义不明确、存在歧义或无法安全转换的规则**整份配置被拒绝**，返回带稳定
原因码的 `ConversionError`（含 legacy 规则 ID 与细节），不会：

- 静默忽略某条规则或某个字段；
- 丢弃部分规则后返回“半成品”策略集（出错时返回零值 `PolicySet`）；
- 把无法识别的规则降级为放行。

可区分原因码见 `errors.go`：`unsupported_version`、`empty_legacy_rule_id`、
`unknown_action`、`deprecated_action`、`invalid_weight`、`missing_match`、
`ambiguous_match`、`unknown_match_field`、`unknown_top_level_field`。
归一后若出现规则 ID 重复等问题，返回现行校验原因（如
`duplicate_rule_id`）。

## 验证方法

`go test ./... -run TestConvertLegacyV1 -v`：

- `TestConvertLegacyV1_Success`：四类选择器与三种 action 正确归一，打印
  归一后的完整策略集；用归一结果构造引擎评估历史资源，断言 weight 最高
  的 label 拒绝规则决胜，并在日志中打印输入、命中规则与判定依据。
- `TestConvertLegacyV1_RejectionReasons`：表驱动覆盖 21 个拒绝场景
  （版本/字段/action/weight/match/label/重复 ID/非法 JSON），逐一断言
  原因码可区分。
- `TestConvertLegacyV1_DoesNotSilentlyPass`：未知 action 必须失败且不返回
  任何可被当作“默认全放行”的非空策略集。
