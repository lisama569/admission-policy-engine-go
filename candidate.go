package policy

// CandidateSource 标识候选策略的来源格式。
type CandidateSource string

const (
	CandidateNative CandidateSource = "native" // 现行格式
	CandidateLegacy CandidateSource = "legacy" // 历史 v1 格式，需先归一
)

// PreparedCandidate 是一份已经通过“解析/归一 + 整体自洽性校验”的候选策略。
// 该类型只能通过 PrepareCandidate 构造，对调用方是只读的；
// 预演与正式生效复用同一个内部策略集，保证预演结论即生效后结论。
type PreparedCandidate struct {
	source CandidateSource
	policy PolicySet
}

// PrepareCandidateNative 校验现行格式的候选策略；任一规则非法则整份拒绝，
// 返回 *ValidationError，绝不部分接受。返回的候选持有入参的深拷贝，
// 调用方之后修改入参不会影响候选。
func PrepareCandidateNative(ps PolicySet) (*PreparedCandidate, error) {
	if err := ValidatePolicySet(ps); err != nil {
		return nil, err
	}
	return &PreparedCandidate{source: CandidateNative, policy: clonePolicySet(ps)}, nil
}

// PrepareCandidateLegacy 解析并归一历史 v1 候选策略：
// 无法安全转换的规则让整份候选被拒绝（*ConversionError），
// 归一后仍须通过现行策略集的全部自洽性校验（*ValidationError）。
// 任何失败都不会返回部分归一的候选，也不会放宽为放行。
func PrepareCandidateLegacy(raw []byte) (*PreparedCandidate, error) {
	ps, err := ConvertLegacyV1(raw)
	if err != nil {
		return nil, err
	}
	return &PreparedCandidate{source: CandidateLegacy, policy: clonePolicySet(ps)}, nil
}

// Source 返回候选策略来源格式（native/legacy）。
func (c *PreparedCandidate) Source() CandidateSource { return c.source }

// PolicyVersion 返回候选策略集的版本标识
// （历史格式归一后为 legacy-v1-normalized）。
func (c *PreparedCandidate) PolicyVersion() string { return c.policy.Version }

// PolicySet 返回候选策略集的深拷贝，调用方修改不影响候选本身。
func (c *PreparedCandidate) PolicySet() PolicySet { return clonePolicySet(c.policy) }

// prepared 判断候选是否来自 PrepareCandidate*（外部无法构造出 source 非空
// 的值，零值/伪造值一律视为未准备）。
func (c *PreparedCandidate) prepared() bool {
	return c != nil && c.source != "" && c.policy.Version != ""
}

// CommitCandidate 把候选策略原子切换为新生效版本。
//
// 候选只能来自 PrepareCandidateNative/PrepareCandidateLegacy；未经过准备的
// 值返回可区分的 *ValidationError（candidate_not_prepared）。
//
// 切换先构造完整的新快照、再一次性替换指针：要么整份生效、要么完全不生效，
// 并发评估只会看到完整的旧版本或完整的新版本，不存在半生效状态。
// 候选在校验阶段已被整体接受，因此提交本身不会因“配置不合法”而部分写入。
func (e *Engine) CommitCandidate(c *PreparedCandidate) error {
	if !c.prepared() {
		return &ValidationError{
			Reason: ErrReasonCandidateNotPrepared,
			Detail: "candidate was not prepared via PrepareCandidateNative/PrepareCandidateLegacy; commit refused",
		}
	}
	// 再次按克隆写入，与 Update 的 clone-on-store 纪律保持一致：
	// 即便同包代码持有候选内部切片，引擎快照也自成一份不可变副本。
	e.current.Store(&engineSnapshot{policySet: clonePolicySet(c.policy)})
	return nil
}
