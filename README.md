# 本地准入策略评估引擎

在资源提交前，依据策略集给出**允许（allow）/ 拒绝（deny）/ 告警（warn）**
的可解释、可复现结论；支持原子热更新、并发评估、历史 v1 格式兼容转换，以及
**候选策略批量预演与安全切换**。

## 快速开始

```go
e, err := policy.NewEngine(policy.PolicySet{
    Version: "2026-09-22",
    Rules: []policy.Rule{{
        ID: "no-latest", Priority: 100, Effect: policy.EffectDeny,
        Conditions: []policy.Condition{{
            Field: "spec.containers.0.image",
            Op:    policy.OpMatches, Values: []string{"*:latest"},
        }},
    }},
})
res := e.Evaluate(resource) // res.Decision / res.Hits / res.WinningRule / res.Reason
_ = e.Update(newPolicySet)  // 先校验后原子切换；失败保留旧版本

// 候选策略预演 -> 确认差异 -> 原子生效（整份生效或完全不生效）
cand, _ := policy.PrepareCandidate(candidatePolicySet)         // 现行格式
cand, _ = policy.PrepareCandidateLegacy(rawLegacyV1JSON)        // 或历史 v1 JSON
report, _ := e.Rehearse(batchResources, cand)                   // 逐条差异 + 汇总计数
fmt.Print(report.Text())
_ = e.Promote(cand)
// 注意：nil / &Candidate{} / 绕过 Prepare 手拼的“未就绪候选”会在评估前被
// Rehearse 与 Promote 以同一道闸门、同一原因整份拒绝（*RehearsalError），
// 不会被当成全放行空策略，也不改动当前生效策略。

br := e.EvaluateBatch(batchResources) // 只需批量评估时：整批固定同一版本
```

历史配置：`ps, err := policy.ConvertLegacyV1(rawV1JSON)`，成功后再 `NewEngine`/`Update`。

## 文档

- [策略匹配与优先级规则](docs/policy-matching.md)
- [热更新与并发可见性保证](docs/hot-update.md)
- [历史策略格式（v1）兼容转换](docs/legacy-format.md)
- [候选策略预演与安全切换](docs/candidate-rehearsal.md)

## 测试

```sh
go test ./... -race -count=1 -v   # 并发一致性、热更新竞争、历史格式拒绝原因
```

测试日志会打印每个评估的输入资源、命中的规则（含每个条件的期望值与资源
实际值）、决胜规则与文字判定依据。
