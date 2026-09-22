# 热更新与并发可见性保证

## 模型：不可变快照 + 原子指针

- 每次生效的策略集封装为一个**不可变**快照 `engineSnapshot`，构造完成后
  不再修改；`Engine` 内部只用一个 `atomic.Pointer[engineSnapshot]` 指向
  当前快照。
- `Evaluate` 在入口处一次性 `Load()` 当前快照，随后整次评估只使用该
  快照内的数据结构。
- `Update` 先在快照外完成**整份新策略集的校验与深拷贝**，全部通过后才
  `Store()` 新指针；失败时根本不动指针。

由此得到的保证：

1. **原子生效 / 无半套规则**：指针切换是原子的，任一评估只能看到完整的
   旧版本或完整的新版本，不可能看到部分规则来自旧集、部分来自新集。
2. **只读快照，无锁评估**：评估路径不获取互斥锁、不修改共享状态，可与
   更新及其它评估并发执行。
3. **并发结论与串行一致**：给定同一个版本快照，评估是纯函数（只依赖
   不可变规则与入参资源），决胜规则由 priority/effect/id 的全序决定，
   因此多 goroutine 并发评估同一资源必然得到与串行完全相同的结论。
4. **无效更新被整体拒绝**：校验失败（空版本、重复 ID、非法 effect/
   operator/glob、空条件等）时返回带稳定 `Reason` 的 `ValidationError`，
   生效版本保持原样，不被污染。
5. **防外部篡改**：`NewEngine`/`Update` 对传入策略做深拷贝，`Current()`
   也返回深拷贝，调用方在引擎外修改切片/数组不会影响生效快照。

注意：更新之间的先后顺序由调用方决定（引擎不做版本号单调约束）；
`Update(v2)` 成功后又 `Update(v1)` 是允许的显式回滚。引擎保证的是
“每次评估看到一个完整一致的版本”，而不是“版本号只能递增”。

## 验证方法

- `go test ./... -race`：
  - `TestConcurrentEvaluation_MatchesSerial`：64 goroutine × 200 轮并发
    评估，与逐资源串行基准逐一比对 decision / winningRule / hits /
    policyVersion，任何分歧即失败。
  - `TestHotUpdate_AtomicVisibility`：评估 goroutine 在更新线程交替推送
    合法版本与非法更新期间持续评估，断言每次结果的 `policyVersion` 与
    `decision/winningRule` 严格自洽（只能是 v1/v2/v3 三个完整版本之一），
    且最终生效版本不被最后一次非法更新污染。
  - race detector 用于发现任何数据竞争。
- `TestUpdate_InvalidPolicyKeepsOldVersion`：多类非法更新后检查
    `Current()` 仍是旧版本，随后一次合法更新整体切换成功。
