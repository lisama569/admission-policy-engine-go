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

> **候选只能由上述两个 `Prepare*` 函数构造。** 直接传 `nil`、零值
> `&policy.Candidate{}`，或绕过准备流程手工拼出的候选对象，都属于
> “不可用候选”，会在预演/切换开始前被整份拒绝（见
> [第 4 节](#4-候选可用性闸门与可区分拒绝原因)）。

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
- **预演/切换同一道闸门（可用性判断一致）**：`Rehearse` 与 `Promote` 共用
  `requireCandidate` 判定候选能不能用（nil / 未就绪 / 防御性校验失败）。
  同一份候选在预演和切换上的结论必然一致，不会一个放行评估、一个拒绝切换；
  被拒调用在触碰引擎状态之前返回。
- **原子切换**：`Promote` 在闸门通过后执行一次原子指针替换，并发评估只能
  看到完整的旧版本或完整的新版本；闸门失败则原版本原封不动，不存在半生效
  状态。

## 4. 候选可用性闸门与可区分拒绝原因

`Rehearse` 与 `Promote` 在**固定快照、产出任何逐条结果或触碰引擎状态之前**，
共用同一道、也是唯一的候选可用性闸门 `requireCandidate`。因此同一份候选在
“预演”与“切换”上**能不能用的判断构造上必然一致**：不可能出现预演说能用、
切换又被拒（或反过来）。

闸门按以下顺序判定，全部返回 `*RehearsalError`，靠 `Reason` 与策略非法的
`*ValidationError`、历史格式无法归一的 `*ConversionError` 区分：

| 情形 | `RehearsalError.Reason` | 含义 |
| --- | --- | --- |
| 调用方传了 `nil` | `candidate_unavailable` | 根本没有提供候选 |
| 零值 `&Candidate{}`、绕过 `Prepare*` 手拼的对象（哪怕内部塞了“规则”） | `candidate_not_prepared` | 候选没走准备流程，不携带已校验、可评估的策略 |
| 带准备标记但内嵌策略防御性校验失败（正常公共路径不可达） | `candidate_invalid` | 候选内部异常（细节中会带出底层 `ValidationError`） |

关键安全语义：

- **未就绪不等于“空策略”。** 一份没有规则的合法策略集会让所有资源命中默认
  放行（allow）。如果把“空的、没准备的候选”误当成这种空策略去评估，就会
  凭空得到一份“全放行、候选版本为空、到处是结论变化”的误导性报告。闸门在
  评估之前就整体拒绝，**不产出任何逐条结果，也不汇总任何差异**（返回的
  `RehearsalReport` 为零值：`Items` 为空、版本为空、`Summary` 为零）。
- **不改动当前生效策略、不留中间状态。** 闸门只读：被拒调用不会 pin 快照、
  不会替换生效指针，线上策略与后续评估完全不受影响；即使被拒调用与热更新
  并发穿插，成功的预演/批量依旧整批固定在同一个完整版本上。
- **策略本身非法**（版本为空、重复 ID、非法 effect/glob 等）在更早的
  `Prepare*` 阶段就以 `*ValidationError` / `*ConversionError` 被整体拒绝，
  根本不会产生候选；详见下文兼容与拒绝范围。

## 5. 候选（含历史格式）的兼容与拒绝范围

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
- 预演/切换 API 收到 `nil`、零值/手拼的未就绪候选时，在评估前统一返回
  `*RehearsalError`（reason 分别为 `candidate_unavailable` /
  `candidate_not_prepared`），不产出逐条结果，也不触碰线上策略
  （见[第 4 节](#4-候选可用性闸门与可区分拒绝原因)）。

## 6. 从预演到正式生效的本地验证方法

```sh
# 全量测试（含 -race）：预演/批量/切换一致性 + 既有能力无回归
go test ./... -race -count=1 -v
```

只看“未就绪候选拦截 / 预演切换一致 / 热更新下批量一致”这组新用例：

```sh
go test -run 'TestRehearse_UnreadyCandidateRejectedWholesale|TestRehearsePromote_ReadinessJudgmentConsistent|TestRehearse_RejectedCallsLeaveNoStateUnderHotUpdate' -v -count=1 .
```

日志会逐条打印覆盖的业务（`[业务:...]`）、输入资源 JSON、两侧命中规则、
最终判定与差异原因；可以直接看到未就绪候选被什么 `Reason` 拒绝、线上策略为何
保持不变。

本地手工复现“踩坑 → 修复后行为”的最小片段：

```go
e, _ := policy.NewEngine(livePolicy) // live: Pod 一律 deny
res := []policy.Resource{{"kind": "Pod", "metadata": map[string]any{"name": "p"}}}

bad := &policy.Candidate{} // 空的、没走 Prepare 的候选

// 修复前：不报错，候选侧把资源判成 allow（默认放行）、候选版本为空、凭空出现差异；
//         而 Promote(bad) 又因 empty_policy_version 被拒——预演与切换矛盾。
// 修复后：Rehearse 直接返回 *RehearsalError，Reason=candidate_not_prepared，
//         报告为零值（无任何逐条结果）；Promote(bad) 以同一 Reason 被拒；
//         e.Current() 仍是 live，后续 Evaluate 结论不变。
_, err := e.Rehearse(res, bad)   // rehearsal failed (candidate_not_prepared): ...
err = e.Promote(bad)             // 同样 candidate_not_prepared，线上策略不动
```

重点用例：

候选可用性（`candidate_readiness_test.go`，新增）：

- `TestRehearse_UnreadyCandidateRejectedWholesale`：`nil`、零值、手拼（带
  “规则”）三类未就绪候选均在评估前被整份拒绝（可区分 reason、零报告），线上
  策略与后续评估不变，且不会被当成全放行空策略；
- `TestRehearsePromote_ReadinessJudgmentConsistent`：同一份候选在
  `Rehearse` 与 `Promote` 上可用性判断一致（该拒两边同因、该过两边都过），
  合法候选切换后结论与预演候选列逐条一致；
- `TestRehearse_RejectedCallsLeaveNoStateUnderHotUpdate`：并发热更新中大量
  穿插被拒预演，全部零报告零残留，随后的合法预演整批固定在同一个完整版本。

预演/批量/历史（`rehearse_test.go` 等，既有，无回归）：

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
  无任何效果；
- 另有 `engine_test.go`（单资源评估与冲突决胜）、`concurrent_test.go`
  （并发评估与合法热更新）、`legacy_test.go`（历史格式成功与拒绝原因）、
  `validation_test.go`（校验原因与失败热更新不污染旧版本）覆盖既有能力。

建议的人工上线流程：

1. `PrepareCandidate(Legacy)` 准备候选，失败按可区分 reason 修正后重来；
2. `Rehearse` 代表性批次（或全量待提交资源），查看 `Text()` 与 `Summary`；
3. 重点核对 `!`/`~` 条目的命中规则与理由，确认新增拒绝、由拒变放行、告警变化
   数量符合预期；
4. `Promote` 原子生效；如需回滚，把旧策略集再 `PrepareCandidate` + `Promote`
   即可（旧版本可通过 `Engine.Current()` 深拷贝留存）。
