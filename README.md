# 本地准入策略评估引擎

在资源提交前，依据策略集给出**允许（allow）/ 拒绝（deny）/ 告警（warn）**
的可解释、可复现结论；支持原子热更新、并发评估与历史 v1 格式兼容转换。

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
```

历史配置：`ps, err := policy.ConvertLegacyV1(rawV1JSON)`，成功后再 `NewEngine`/`Update`。

## 候选策略预演与安全切换

新策略（或历史格式策略）生效前，先对整批资源做“当前版本 vs 候选版本”的
对比预演，确认差异后再原子切换：

```go
// 1. 准备候选：现行格式走 Native；历史 v1 走 Legacy（内部先安全归一）。
cand, err := policy.PrepareCandidateNative(candidatePolicySet)
// cand, err := policy.PrepareCandidateLegacy(rawV1JSON)

// 2. 批量预演：整批固定在同一对版本上，输出逐条差异与汇总。
rep, err := e.Preview(resources, cand, policy.BatchOptions{Workers: 8, ChunkSize: 64})
fmt.Print(policy.RenderReport(rep)) // 新增拒绝/由拒变放行/告警变化 + 逐条依据

// 3. 确认无误后原子生效：要么整份生效，要么完全不生效。
_ = e.CommitCandidate(cand)
```

候选配置非法、历史格式无法安全归一、或归一后与现有约束冲突时，候选在
准备阶段即被**整份拒绝**（可区分的 `ValidationError`/`ConversionError`），
线上策略不受影响。

## 文档

- [策略匹配与优先级规则](docs/policy-matching.md)
- [热更新与并发可见性保证](docs/hot-update.md)
- [历史策略格式（v1）兼容转换](docs/legacy-format.md)
- [候选策略预演与安全切换](docs/candidate-preview.md)

## 测试

```sh
go test ./... -race -count=1 -v   # 并发一致性、热更新竞争、历史格式拒绝原因
```

测试日志会打印每个评估的输入资源、命中的规则（含每个条件的期望值与资源
实际值）、决胜规则与文字判定依据。
