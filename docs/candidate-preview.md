# 候选策略预演与安全切换

在把一份新策略（或一份历史格式策略）真正切成生效版本之前，先对**一整批
待提交资源**同时按“当前生效版本”和“候选版本”各评估一遍，产出逐条对比与
汇总；确认差异符合预期后，再把候选**原子切换**为新生效版本。

整体流程分三步：

```
准备候选（校验/归一）  ->  批量预演（读报告、看差异）  ->  原子生效（整份切换）
PrepareCandidate*            Engine.Preview                 Engine.CommitCandidate
```

## 1. 准备候选

候选有两种来源，都会在预演前完成“整份可用”的判定：

- `PrepareCandidateNative(ps PolicySet) (*PreparedCandidate, error)`：
  现行格式。内部调用 `ValidatePolicySet`，任一规则非法（空版本、重复 ID、
  非法 effect/operator/glob、缺条件取值等）即**整份拒绝**，返回带稳定
  `Reason` 的 `*ValidationError`，绝不部分接受。
- `PrepareCandidateLegacy(raw []byte) (*PreparedCandidate, error)`：
  历史 v1 格式。先按[历史格式兼容规则](legacy-format.md)完整归一，
  再跑一遍现行策略集的全部自洽性校验。任何规则无法安全、无歧义转换
  （废弃 action、多 selector 歧义、未知字段、weight 越界等）都返回
  `*ConversionError`；归一后与现有约束冲突（如规则 ID 重复）返回
  `*ValidationError`。**不会静默跳过规则，也不会放宽为放行。**

`PreparedCandidate` 只能由上述两个函数构造，对调用方只读，内部持有策略集
的深拷贝；`Source()`/`PolicyVersion()`/`PolicySet()` 可查看来源、版本与
深拷贝内容。准备失败时返回 `nil` 候选，后续预演/提交无法进行。

## 2. 批量预演

```go
rep, err := e.Preview(resources, candidate, policy.BatchOptions{
    Workers: 8, ChunkSize: 64,
})
fmt.Println(policy.RenderReport(rep))
```

- `Workers`：并行评估 worker 数，`<=0` 串行；`ChunkSize`：每个 worker
  一次领取的资源条数，用于约束在途中间结果规模，`<=0` 表示不拆块。
  两者都不影响结果，只影响执行方式。
- 空资源批是合法输入，产出空 `Items` 与全 0 汇总。
- 另有 `EvaluateBatch(resources, opts)`，只按当前生效版本批量评估，
  与预演共享同一套版本一致性保证。

### 报告怎么读

`PreviewReport`：

- `CurrentVersion` / `CandidateVersion` / `CandidateSource`
  （`native` 或 `legacy`）说明本次对比落在哪一对版本上。
- `Items[]`：**顺序与输入资源严格一一对应**，每条含：
  - `Current` / `Candidate`：两侧完整结论（decision、命中规则及每条命中
    条件的期望值/实际值、决胜规则、文字依据），字段结构与单资源 `Result`
    相同；
  - `Changed`：最终结论（allow/deny/warn）是否改变；
  - `Reason`：一句话差异依据，形如
    `decision deny -> warn; winning rule "deny-pod" -> "warn-pod"; candidate: ...`，
    说明“从什么变成什么、决胜规则如何切换”。
  注意：只改命中规则但最终结论不变的资源 `Changed=false`，两侧完整命中
  明细仍可在 `Current`/`Candidate` 中对照。
- `Summary` 汇总数量：
  - `Total` / `Changed` / `Unchanged`；
  - `NewlyDenied`（新增拒绝：当前非 deny、候选 deny）；
  - `NoLongerDenied`（由拒变放行/告警：当前 deny、候选非 deny）；
  - `WarningsAdded` / `WarningsRemoved`（告警变化）；
  - `DecisionTransitions`：形如 `"allow->deny"` 的结论迁移计数，
    覆盖全部 6 个可能的迁移方向。

`RenderReport(rep)` 输出确定性纯文本：头部版本与来源、汇总与迁移明细、
再按输入位置逐条展开**结论发生变化**的资源（未变化的折叠为计数），
便于贴到变更单或评审记录中。

### 一致性与规模保证

1. **整批固定在同一对版本上**：`Preview` 入口只读取一次当前快照，
   当前侧与候选侧整批复用同一对不可变策略集。预演进行中即使线上发生
   热更新，本次报告也不会出现“一部分资源按旧版本、一部分按新版本”的
   情况。
2. **预演结论 == 生效后结论**：预演候选侧与候选生效后的 `Evaluate`
   调用的是同一个评估核心（`evaluateWithSet`），且候选内部策略集与
   提交时写入快照的是同一份数据，因此对同一批资源结论必然一致。
3. **可重复、顺序稳定**：评估是规则与资源的确定性纯函数（决胜由
   priority/effect/id 全序决定），`Items` 按下标预分配、并行 worker
   只按位置写入，差异原因在全部结论落位后统一生成。相同输入重复预演，
   差异清单、顺序乃至渲染文本逐字节一致。
4. **不丢、不重、内存有界**：每条资源恰好评估两侧各一次，结果按下标
   落位；任务以 chunk 派发，在途结果不超过 `Workers * ChunkSize` 条，
   可一次处理几百到几千条资源，不会因中间结果堆积导致内存失控。

## 3. 原子生效

```go
if err := e.CommitCandidate(candidate); err != nil {
    // 只有一种可能：候选不是 PrepareCandidate* 产出的（candidate_not_prepared）
}
```

- 切换先构造完整新快照、再一次性替换原子指针：**要么整份生效，要么完全
  不生效**，并发评估只能看到完整旧版本或完整新版本，不存在半生效状态。
- 候选在准备阶段已经被整体接受（现行格式合法，或历史格式成功安全归一
  且通过现行约束校验）；任一检查失败都拿不到 `PreparedCandidate`，
  因此“不合法的候选”没有机会触碰线上版本，切换失败时原策略照常可用。
- 外部构造的零值/伪造 `PreparedCandidate` 一律以
  `ValidationError{Reason: "candidate_not_prepared"}` 拒绝。
- 也可以继续使用既有的 `Engine.Update(PolicySet)` 直接热更新；预演链路
  与它操作的是同一个原子指针。

## 本地验证方法

```sh
go test ./... -race -count=1 -v
```

重点用例（均含输入资源、命中规则、最终判定与差异原因的 `-v` 日志）：

| 用例 | 验证内容 |
| --- | --- |
| `TestPreview_DiffItemsAndSummary` | 逐条差异、决胜规则变化、汇总与迁移计数正确性 |
| `TestPreview_MatchesResultAfterCommit` | 预演候选侧结论与正式生效后逐条一致（现行格式） |
| `TestPreview_LegacyCandidateNormalizedThenPreviewedAndCommitted` | 历史候选先归一再预演，且生效后结论一致 |
| `TestPreview_PinnedToOneVersionAcrossHotUpdate` | 预演期间持续热更新，每份报告仍整批落在同一版本 |
| `TestPreview_LargeBatch_NoLossNoDupStableOrder` | 5000 条、多组 worker/chunk 配置下不丢不重、顺序稳定、重复预演一致 |
| `TestPrepareAndPreview_InvalidCandidateRejectedOnlineUntouched` | 非法现行候选被整份拒绝，预演/提交均失败，线上不变 |
| `TestPrepareAndPreview_LegacyCandidateRejectedOnlineUntouched` | 历史候选无法安全归一或归一后冲突时整份拒绝，线上不变 |
| `TestCommitCandidate_AtomicVisibilityUnderConcurrency` | 高频切换期间并发评估只看到完整版本 |
| `TestEvaluateBatch_PinnedVersionAndOrder` | 批量评估整批固定一个版本、位置与输入一一对应 |
| `TestPreview_EmptyBatchAndNoChangeReport` | 空批与“无差异”报告的可读性、渲染确定性 |

既有的单资源评估、冲突决胜、合法热更新、历史格式成功/拒绝用例保持不变，
可用于确认无回归。
