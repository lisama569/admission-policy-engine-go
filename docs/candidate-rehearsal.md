# 候选策略预演与安全切换

在把新策略真正切成生效版本之前，先对一批待提交资源做“双跑对比”：同一条资源
分别按**当前生效策略**和**尚未生效的候选策略**评估，输出逐条差异与汇总计数；
确认无误后再原子切换。本文覆盖用法、结果读法、一致性与规模保证、候选
（含历史 v1 格式）的兼容与拒绝范围，以及本地验证方法。

## 1. 基本用法

```go
// 1) 准备候选：现行格式（整体校验，失败即拒绝）
cand, err := policy.PrepareCandidate(candidatePolicySet)

//    或历史 v1 JSON（先按既有兼容规则归一，再整体校验）
cand, err = policy.PrepareCandidateLegacy(rawV1JSON)
if err != nil {
    // 一定是可区分的两类错误之一：
    //   *policy.ValidationError —— 策略集自洽性失败（含归一后冲突）
    //   *policy.ConversionError —— 历史规则无法安全、无歧义归一
    // 此时没有任何候选产生，线上策略纹丝不动。
}

// 2) 批量预演：一次几百到几千条资源
report, err := engine.Rehearse(resources, cand)
fmt.Print(report.Text()) // 人类可读报告；结构体字段也可直接做机器处理

// 3) 确认差异可接受后，整份原子生效（要么全生效，要么完全不动）
if err := engine.Promote(cand); err != nil { /* 原策略仍完整可用 */ }
```

只需要“同一版本批量评估”而不做对比时，使用：

```go
br := engine.EvaluateBatch(resources) // 整批固定在同一个策略版本上
```

`Candidate` 一旦构造成功即为**不可变**：内部持有归一策略集的深拷贝，外部
无法通过原切片或 `Candidate.Policy()`（同样返回深拷贝）改写它。

## 2. 报告与差异清单怎么读

`RehearsalReport` 字段：

| 字段 | 含义 |
| --- | --- |
| `CurrentVersion` / `CandidateVersion` | 本次预演固定住的两个策略版本号 |
| `CandidateSource` | 候选来源（`current-format` 或 `legacy-v1`），便于审计 |
| `Items` | 逐条对比，**顺序与输入资源完全一致**，按下标定位 |
| `Summary` | 整批差异汇总计数 |

每条 `ResourceDiff`：

- `Resource`：`index`（输入下标，主键）+ `kind/name/namespace`（可读定位信息，
  取自 `kind`、`metadata.name`、`metadata.namespace`，不要求资源自带唯一 ID）；
- `Current` / `Candidate`：两侧的**完整可解释 `Result`**——最终结论、版本、
  全部命中规则（含每个条件的期望值、资源实际值、是否存在）、决胜规则与文字理由；
- `DecisionChanged`：最终结论（allow/deny/warn）是否变化；
- `ReasonChanged`：结论未变，但决胜规则或命中规则集合变了（依据变化）；
- `Reason`：一句话说明“从什么变成什么”、两侧决胜规则、新增/消失的命中规则。

文本报告中条目前缀：`!` 表示结论变化，`~` 表示仅依据变化，`=` 表示无变化。

`Summary` 计数（互斥地把每条资源归入 不变 / 结论变化 / 仅依据变化）：

- `AddedDeny` 新增拒绝（`!deny → deny`），细分为 `AllowToDeny`、`WarnToDeny`；
- `RemovedDeny` 由拒变非拒，细分为 `DenyToAllow`（由拒变放行）、`DenyToWarn`；
- `AddedWarn` / `RemovedWarn`：`!warn → warn` 与 `warn → !warn`
  （并给出 `AllowToWarn`、`WarnToAllow` 等方向计数）；
- `Total` / `Unchanged` / `DecisionChanged` / `ReasonChangedOnly` 三者满足
  `Total = Unchanged + DecisionChanged + ReasonChangedOnly`。

## 3. 一致性与规模保证

- **整批同一版本（不新旧混用）**：`Rehearse`/`EvaluateBatch` 在开始瞬间固定
  （pin）一份不可变策略快照，整批资源全部基于该快照；预演期间线上即使发生
  热更新，也不会出现一部分资源用旧版本、一部分用新版本。报告里每条的
  `Current.PolicyVersion` 都等于 `CurrentVersion`。
- **预演即生效（结论一致）**：预演的候选侧与线上评估共用同一条纯评估函数
  `evaluatePolicySet`，候选又不可变，因此预演结论与 `Promote` 生效后对同一批
  资源的结论在构造上逐条一致（结论、决胜规则、命中规则集合、版本号）。
- **确定性（可重复）**：决胜规则与命中列表均与规则加载顺序无关
  （见 [策略匹配与优先级规则](policy-matching.md)），差异清单顺序等于输入顺序；
  相同输入重复预演，差异清单、计数与顺序完全一致。
- **规模**：按批大小一次性预分配结果切片、逐条就地评估，没有额外的待聚合
  中间结构，几百到几千条资源不丢、不重、内存占用与批次规模成线性关系。
- **原子切换**：`Promote` 是一次原子指针替换，并发评估只能看到完整的旧版本
  或完整的新版本；切换前对候选再做一次防御性整体校验，失败则原版本原封不动，
  不存在半生效状态。

## 4. 候选（含历史格式）的兼容与拒绝范围

- 现行格式候选走 `ValidatePolicySet`：空版本、空/重复规则 ID、非法 effect、
  非法操作符、缺字段/缺取值、非法 glob、空条件等一律**整份拒绝**，错误带可
  区分的 `Reason`（见 `errors.go`）。
- 历史 v1 候选严格复用 [历史格式兼容转换](legacy-format.md) 的 `ConvertLegacyV1`：
  `permit/reject/flag → allow/deny/warn`，weight 0..1000 映射 priority，
  match 仅接受 kind/name/namespace/label 四选一的精确相等转换。任何不明确语义
  （废弃的 `advise`、未知 action/字段、多 selector 歧义、label 结构不符等）都让
  整份候选被拒绝并返回 `*ConversionError`；归一后还需通过现行全部校验
  （如规则 ID 重复则 `*ValidationError`）。**不会静默跳过单条规则，也不会放宽
  成默认放行。**
- 预演/切换 API 收到 `nil` 候选时返回 `*RehearsalError`（reason
  `candidate_unavailable`），同样不触碰线上策略。

## 5. 从预演到正式生效的本地验证方法

```sh
# 全量测试（含 -race）：预演/批量/切换一致性 + 既有能力无回归
go test ./... -race -count=1 -v
```

重点用例（均在 `rehearse_test.go`）：

- `TestRehearse_MatchesPostPromoteEvaluation`：候选侧逐条结论与 `Promote`
  生效后实际评估一致；
- `TestRehearse_PinnedAcrossHotUpdate`：预演期间并发高频热更新，整批仍固定在
  同一个完整版本，无撕裂；
- `TestRehearse_LargeBatchNoLossNoDupStableOrder`：3000 条资源不丢不重、顺序
  稳定，打乱规则加载顺序后重复预演结果完全一致，并独立核对汇总计数；
- `TestEvaluateBatch_PinnedAndInOrder`：批量评估在热更新竞争下每批只呈现单一
  完整版本；
- `TestRehearse_InvalidCandidateNeverTouchesLivePolicy`：现行格式非法、历史
  格式拒绝（含归一后 ID 冲突）、nil 候选等场景线上策略与结论均不变；
- `TestRehearse_LegacyCandidate`：历史 v1 候选归一、预演、生效全链路一致；
- `TestPromote_AtomicVisibility`：切换竞争下只观测到完整旧/新版本，失败切换
  无任何效果。

建议的人工上线流程：

1. `PrepareCandidate(Legacy)` 准备候选，失败按可区分 reason 修正后重来；
2. `Rehearse` 代表性批次（或全量待提交资源），查看 `Text()` 与 `Summary`；
3. 重点核对 `!`/`~` 条目的命中规则与理由，确认新增拒绝、由拒变放行、告警变化
   数量符合预期；
4. `Promote` 原子生效；如需回滚，把旧策略集再 `PrepareCandidate` + `Promote`
   即可（旧版本可通过 `Engine.Current()` 深拷贝留存）。
