# 策略匹配与优先级规则

## 数据模型

- `PolicySet`：一次生效的完整策略集，含 `version` 与若干 `Rule`。
- `Rule`：`id`（集合内唯一）、`priority`（整数，越大越高）、`effect`
  （`allow` / `deny` / `warn`）、`conditions`（至少一个，规则内为 **AND**）。
- `Resource`：嵌套 `map[string]any`，字段路径用点号访问，支持数组数字索引，
  例如 `metadata.labels.app`、`spec.containers.0.image`。

## 字段与操作符

| 操作符 | 取值数量 | 含义 |
| --- | --- | --- |
| `eq` | 恰好 1 个 | 字段存在，且字符串化后等于该值 |
| `neq` | 恰好 1 个 | 字段存在，且字符串化后不等于该值 |
| `in` | ≥1 个 | 字段存在，且字符串化后属于取值集合 |
| `notin` | ≥1 个 | 字段存在，且字符串化后不属于取值集合 |
| `matches` | 恰好 1 个 | 字段存在，且匹配 glob（Go `path.Match` 语法） |
| `exists` | 0 个 | 字段存在（含显式 `null`） |

说明：

- 除 `exists` 外，**字段缺失一律视为条件不命中**，而不是报错，规则不会因此触发。
- 比较基于确定性字符串化：字符串原样；数字/布尔用 Go 标准格式；`null` 为 `<nil>`。
- 一条规则的全部条件都命中，该规则才命中。

## 结论判定（确定性、与加载顺序无关）

1. 收集**全部命中规则**（结果 `hits` 按规则 ID 字典序输出，纯为可复现展示）。
2. 从命中规则中按以下**全序**选出唯一决胜规则（`winningRule`）：
   1. `priority` 数值最大；
   2. 同优先级时按效果决胜：`deny > warn > allow`（失败优先的安全取向）；
   3. 仍相同时按规则 ID 字典序最小。
3. 决胜规则的效果即最终结论：`deny`→拒绝、`warn`→告警、`allow`→放行。
4. 没有任何规则命中时，默认结论为 **allow**（`reason` 中明确写出
   “no rule matched; default decision is allow”）。

因为决胜规则只依赖 priority/effect/id，与规则在输入数组中的位置无关，
所以同一资源的冲突结论是确定、可复现、可解释的。`Result.Reason` 会说明
命中规则数量、决胜规则 ID、优先级与所用决胜次序；每条命中还附带
`MatchedCondition`（字段、操作符、期望值、资源实际值、字段是否存在）。

## 失败闭合

策略集均在加载/更新时完成校验，评估期不应遇到非法操作符或取值。
若评估中出现内部错误，引擎按 fail-closed 返回 `deny`，绝不静默放行。

## 自洽性校验（任一失败则整份策略集被拒绝）

`version` 非空；规则 ID 非空且集合内唯一；effect 合法；至少一个条件；
条件字段非空；操作符合法且取值数量正确；`matches` 的 glob 必须可解析。
失败原因以稳定字符串给出，见 `errors.go` 中的 `ErrReason*`，例如
`duplicate_rule_id`、`invalid_effect`、`invalid_glob_pattern` 等。
