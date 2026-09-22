# 本地准入策略评估引擎

在资源提交前，依据策略集对资源进行本地评估，给出 **allow / warn / deny**
结论，并输出命中的规则、排序依据与最终判定理由。核心目标：

- 结论**可解释、可复现**：命中规则列表 + 文字化裁决理由；冲突仲裁与加载顺序无关；
- 策略**热更新原子生效**：评估只看到完整旧版或完整新版，拒绝半套规则；
- 历史 v1 格式**兼容转换**：能安全归一才转换，语义不明的规则显式拒绝，绝不静默放行；
- 并发评估结论与串行完全一致（`go test -race` 验证）。

## 目录结构

```
pkg/policy/    核心模型、匹配器、不可变快照引擎、v2 解析与校验
pkg/legacy/    v1 历史格式 -> v2 归一转换（歧义显式拒绝）
pkg/loader/    按 version 字段自动分发 v1/v2
cmd/admissionctl/  命令行：加载策略 + 批量评估资源
examples/      v1/v2 策略与资源示例
```

## 快速开始

```bash
go test ./... -race -count=1

go run ./cmd/admissionctl \
  -policy examples/policies-v2.json \
  -resources examples/resources.json
```

stderr 逐条打印输入资源、判定与依据；stdout 输出评估结果 JSON 数组。

## v2 策略格式

```json
{
  "version": "v2",
  "name": "cluster-default",
  "defaultEffect": "deny",
  "rules": [
    {
      "id": "deny-privileged",
      "description": "可选描述",
      "priority": 100,
      "effect": "deny",
      "message": "命中后展示的信息",
      "match": {
        "all": [ {"field": "kind", "operator": "eq", "value": "Pod"} ],
        "any": [ ... ],
        "not": [ ... ]
      }
    }
  ]
}
```

- `version` 必须是 `"v2"`；未知顶层字段会被拒绝（`DisallowUnknownFields`），
  防止作者写错字段却被静默忽略。
- `defaultEffect`：无规则命中时的兜底动作，取值 `allow/warn/deny`，
  **缺省为 `deny`（fail-closed）**；显式写成非法值会被拒绝。
- 每条规则必须有非空且唯一的 `id`；`effect` 必须是 `allow/warn/deny`。
- `match.all` 全部成立（AND）、`match.any` 至少一个成立（OR，空 any 不构成约束）、
  `match.not` 全部不成立（NOT）；三个组同时存在时为 `all AND any(OR) AND not`。
  空 `match` 表示匹配一切（合法，但需作者显式写出）。

### 资源字段路径

`field` 为点分路径：

| 路径 | 含义 |
| --- | --- |
| `apiVersion` / `kind` / `namespace` / `name` | 资源核心字段 |
| `labels.<key>` / `annotations.<key>` | 标签/注解映射 |
| `labels` / `annotations` | 整个 map（一般配合 contains 使用） |
| 其他，如 `spec.replicas` | 从 `resource.extra` 中按点分路径逐级查找，也支持 flat key |

路径不允许空段、前导/尾随点；裸字段名不要求预先声明（会落到 `extra`）。

### 操作符

| operator | 操作数 | 语义 |
| --- | --- | --- |
| `eq` / `ne` | `value` | 标量相等/不等（数字按数值比较，`3` 与 `3.0` 等价） |
| `in` / `notIn` | `values` 非空数组 | 字段值属于/不属于列表；字段缺失时 `in=false`、`notIn=true` |
| `exists` | 无 | 字段是否存在 |
| `gt` / `gte` / `lt` / `lte` | `value` | 数字按数值、字符串按字典序比较；类型不匹配判定为校验/求值错误 |
| `contains` | `value` | 字符串子串，或数组元素包含 |
| `startsWith` | `value`（字符串） | 前缀匹配 |

**缺失字段规则**：除 `exists`（false）与 `notIn`（true）外，对缺失字段的
谓词一律为 false；“字段不存在”必须用 `exists` 显式表达，避免“没值”被
误当成“值不满足”。

## 匹配与优先级规则（冲突仲裁）

所有规则逐条参与匹配，命中规则按下面的**全序键**排序，第一名决定结论：

1. **效果强度**：`deny > warn > allow`（任何优先级的 deny 都压过 allow/warn）；
2. **显式优先级**：`priority` 数值大者在前；
3. **规则 ID 字典序**：效果与优先级都相同时，ID 小者在前（最终决胜键）。

因此：

- 仲裁结果**与规则在文件中的顺序、加载顺序无关**（有测试对照正序/逆序文档）；
- 即使两条规则效果、优先级完全相同，也有确定性的赢家；
- `Result.Matched` 按上述顺序输出全部命中规则，`Result.Reason` 用文字说明
  赢家是谁、压过了哪些规则、依据哪条仲裁规则，便于审计复现。

无任何规则命中时，应用 `defaultEffect`（默认 deny）。

## 热更新与可见性保证

引擎内部持有一个 `atomic.Pointer[snapshot]`：

- 每个 `PolicySet` 在安装时会被**深拷贝 + 规范化 + 整体校验**，冻结成不可变快照；
  调用方在 `Update` 之后继续修改自己手里的结构，不会影响引擎。
- `Evaluate` 开始时只读取一次快照指针，之后全程基于该不可变快照计算，
  所以一次评估要么看到**完整旧版**，要么看到**完整新版**，不可能看到半套规则。
- `Update` 先在副本上完成全部校验，通过后用一次 CAS 原子替换；
  版本号单调递增，被拒绝的更新不递增版本、不触碰旧快照。
- **无效或不自洽的更新整体拒绝**（重复 ID、非法 effect/operator、缺操作数、
  非法 defaultEffect 等），原有策略继续可用。
- 评估无锁、只读快照，可与更新及彼此并发；并发结论与串行一致
  （见 `TestConcurrentEvaluation_MatchesSerial`、`TestHotUpdate_AtomicVisibility`，
  均在 `-race` 下运行）。

## v1 历史格式兼容范围

v1 文档（`"version": "v1"`）由 `pkg/legacy` 归一为 v2，规则 ID 统一加
`legacy-` 前缀；转换后的集合仍会跑一遍 v2 全量校验。**任一规则无法安全
转换，整个文档被拒绝**，返回带类型码的 `policy.LoadError`。

| v1 元素 | 归一方式 |
| --- | --- |
| `action`: `permit/allow`、`reject/deny`、`warn/warning` | `allow` / `deny` / `warn` |
| `severity`: critical/high/medium/low/info | 优先级 30/20/10/5/1（缺省 medium=10） |
| `targetKind` | `all: kind eq <targetKind>` |
| `selector`（label map） | 每个标签一个 `labels.<k> eq <v>`（AND，输出按 key 排序） |
| constraint `op`: `eq/=/==、ne/!=、gt/>、gte/>=、lt/<、lte/<=、in、notin、exists/present` | 对应 v2 操作符 |
| constraint `op`: `missing/absent` | `not: [ {field, exists} ]` |
| constraint `op`: `like/glob`，形如 `abc*` | `startsWith "abc"` |
| constraint `op`: `like/glob`，形如 `*abc` | `contains "abc"` |
| `extra.message` / `extra.description` | 规则 message / description |

**显式拒绝（不静默忽略、不降级放行）**：

- 未知/缺失 `action` → `INVALID_LEGACY_ACTION`；
- 未知 `severity`、**无任何匹配范围的无条件规则**（无 targetKind/selector/constraint）、
  内部通配符（如 `a*b`、`*a*` 这类 v1 未形式化定义的模式）、未知 `extra` 键
  → `AMBIGUOUS_LEGACY_RULE`；
- `regex/regexp/match` 等 v2 无安全结构等价物的操作符、未知 op
  → `UNSUPPORTED_LEGACY_OPERATOR`；
- 约束缺字段/缺值、`in` 操作数不是非空数组 → `INVALID_FIELD_PATH` / `MISSING_VALUE` / `INVALID_VALUE`；
- JSON 非法、版本缺失/不支持、转换后出现重复 ID 等，同样带可区分错误码拒绝。

v1 没有显式默认动作，转换后的 `defaultEffect` 固定为 **deny**（fail-closed）。

### 错误码对照

`LoadError.Code`（可用于程序区分失败原因）：

```
INVALID_JSON  MISSING_VERSION  UNSUPPORTED_VERSION
MISSING_RULE_ID  DUPLICATE_RULE_ID  INVALID_EFFECT
INVALID_OPERATOR  INVALID_FIELD_PATH  MISSING_VALUE  INVALID_VALUE
DEFAULT_EFFECT_INVALID
INVALID_LEGACY_ACTION  AMBIGUOUS_LEGACY_RULE  UNSUPPORTED_LEGACY_OPERATOR
```

`LoadError.Path` 指向具体规则/条件，例如 `rules[2].match.all[0]`。

## 验证方法

```bash
# 全量单测（含并发/热更新/兼容），开启竞态检测
go test ./... -race -count=1 -v

# 只看热更新与并发
go test ./pkg/policy/ -race -run 'TestConcurrent|TestHotUpdate' -v

# 只看历史格式拒绝原因
go test ./pkg/legacy/ -run TestConvert_RejectionReasonsAreDistinguishable -v
```

测试覆盖点：

- **并发结论与串行一致**：32 goroutine × 200 轮，对 18 个资源比对判定与命中顺序；
- **热更新竞争**：16 个读协程持续评估期间写入新版，检查每次读到的命中规则 ID
  只能来自完整 v1 或完整 v2，且决策与快照自洽；
- **非法更新不污染**：重复 ID / 非法 effect / 非法 operator / nil 全部被拒后，
  快照指针、版本号与评估结论保持原样；调用方修改已安装的结构不影响引擎；
- **历史格式**：正常归一（action/severity/selector/in/like/missing）、
  fail-closed 默认值，以及 14 类可区分拒绝原因；
- 每个关键用例均通过 `t.Logf` 打印**输入资源、命中规则与判定依据**，`-v` 可见。

## 编程式用法

```go
set, err := loader.Load(rawPolicy)   // v1/v2 自动识别
engine, _ := policy.NewEngine(set)
result := engine.Evaluate(&policy.Resource{Kind: "Pod", /* ... */})
// result.Decision / result.Matched / result.Reason

if err := engine.Update(newSet); err != nil {
    var le *policy.LoadError
    if errors.As(err, &le) { /* 按 le.Code 区分原因；旧策略仍生效 */ }
}
```
