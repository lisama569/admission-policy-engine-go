package policy

import "sync/atomic"

// Engine evaluates resources against an atomic, hot-swappable policy set.
//
// Concurrency model: every installed PolicySet is frozen into an immutable
// snapshot. Evaluate loads the snapshot pointer once, so an in-flight
// evaluation observes either the complete old set or the complete new set,
// never a mixture. Update validates and freezes its input *before* the
// single atomic pointer swap; a rejected update leaves the old snapshot
// untouched.
//
// The zero value is not usable; create one with NewEngine.
type Engine struct {
	current atomic.Pointer[snapshot]
}

// snapshot is the immutable evaluation state.
type snapshot struct {
	set     *PolicySet
	version int64
}

// NewEngine creates an engine holding an initial validated policy set.
// The engine keeps its own deep copy, so later mutation of initial by the
// caller cannot affect evaluations.
func NewEngine(initial *PolicySet) (*Engine, error) {
	if initial == nil {
		return nil, &LoadError{Code: ErrMissingVersion,
			Message: "initial policy set is nil"}
	}
	frozen, err := freeze(initial)
	if err != nil {
		return nil, err
	}
	e := &Engine{}
	e.current.Store(&snapshot{set: frozen, version: 1})
	return e, nil
}

// Evaluate evaluates one resource against the currently active snapshot.
// It is safe for concurrent use.
func (e *Engine) Evaluate(r *Resource) Result {
	snap := e.current.Load()
	if snap == nil {
		// Unreachable through NewEngine; fail closed defensively.
		return Result{Decision: DECISION_DENY, Reason: "no active policy set; failing closed"}
	}
	return evaluateAgainst(snap, r)
}

// Update atomically replaces the active policy set. The candidate is
// deep-copied and validated as a whole first; an invalid or
// self-inconsistent set is rejected and the previously active set remains
// in effect unchanged.
func (e *Engine) Update(set *PolicySet) error {
	if set == nil {
		return &LoadError{Code: ErrMissingVersion, Message: "candidate policy set is nil"}
	}
	frozen, err := freeze(set)
	if err != nil {
		return err
	}
	for {
		cur := e.current.Load()
		next := &snapshot{set: frozen, version: cur.version + 1}
		if e.current.CompareAndSwap(cur, next) {
			return nil
		}
	}
}

// ActiveVersion returns the monotonically increasing snapshot version.
// Successful updates increment it; rejected updates do not.
func (e *Engine) ActiveVersion() int64 {
	snap := e.current.Load()
	if snap == nil {
		return 0
	}
	return snap.version
}

// ActivePolicySet returns the currently active, immutable policy set.
// Callers must not mutate the returned value.
func (e *Engine) ActivePolicySet() *PolicySet {
	snap := e.current.Load()
	if snap == nil {
		return nil
	}
	return snap.set
}

// freeze deep-copies a set so the engine never shares mutable slices/maps
// with callers, then validates the copy as a whole.
func freeze(in *PolicySet) (*PolicySet, error) {
	cp, err := deepCopySet(in)
	if err != nil {
		return nil, err
	}
	for i := range cp.Rules {
		r := &cp.Rules[i]
		for j := range r.Match.All {
			normalizeCondition(&r.Match.All[j])
		}
		for j := range r.Match.Any {
			normalizeCondition(&r.Match.Any[j])
		}
		for j := range r.Match.Not {
			normalizeCondition(&r.Match.Not[j])
		}
	}
	if err := cp.Validate(); err != nil {
		return nil, err
	}
	return cp, nil
}
