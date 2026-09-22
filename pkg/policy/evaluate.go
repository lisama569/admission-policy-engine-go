package policy

import (
	"encoding/json"
	"sort"
	"strings"
)

// evaluateAgainst runs the deterministic evaluation algorithm:
//
//  1. Every rule in the immutable snapshot is tested; rule *loading* order
//     has no effect on the outcome.
//  2. Matching rules are ranked by a total key:
//     (a) effect strength: deny > warn > allow;
//     (b) explicit Priority: higher numeric value first;
//     (c) rule ID: lexicographically smallest first (final tie-break).
//  3. The top-ranked rule determines the decision. If no rule matches,
//     the set's defaultEffect applies (default deny, fail closed).
//
// Step (c) makes the result reproducible even when two rules have the same
// effect and priority, regardless of file/load order.
func evaluateAgainst(snap *snapshot, r *Resource) Result {
	set := snap.set
	res := Result{PolicyName: set.Name, PolicyVersion: set.Version}

	if r == nil {
		res.Decision = DECISION_DENY
		res.Reason = "resource is nil; failing closed"
		return res
	}

	hits := make([]HitRule, 0)
	for _, rule := range set.Rules {
		if rule.Match.Matches(r) {
			hits = append(hits, HitRule{
				RuleID:      rule.ID,
				Effect:      rule.Effect,
				Priority:    rule.Priority,
				Message:     rule.Message,
				Description: rule.Description,
			})
		}
	}

	sort.SliceStable(hits, func(i, j int) bool {
		return rankLess(hits[i], hits[j])
	})
	res.Matched = hits

	if len(hits) == 0 {
		res.Decision = decisionOf(set.DefaultEffect)
		res.Reason = "no rule matched; applying defaultEffect=" + string(set.DefaultEffect)
		return res
	}

	winner := hits[0]
	res.Decision = decisionOf(winner.Effect)

	var b strings.Builder
	b.WriteString("winning rule ")
	b.WriteString(winner.RuleID)
	b.WriteString(" (effect=")
	b.WriteString(string(winner.Effect))
	b.WriteString(", priority=")
	b.WriteString(itoa(winner.Priority))
	b.WriteString(")")
	if len(hits) > 1 {
		ids := make([]string, 0, len(hits)-1)
		for _, h := range hits[1:] {
			ids = append(ids, h.RuleID)
		}
		b.WriteString(" outranks [")
		b.WriteString(strings.Join(ids, ", "))
		b.WriteString("] by deny>warn>allow, then higher priority, then rule id")
	}
	if winner.Message != "" {
		b.WriteString(": ")
		b.WriteString(winner.Message)
	}
	res.Reason = b.String()
	return res
}

// rankLess implements the total ranking described on evaluateAgainst.
func rankLess(a, b HitRule) bool {
	if sa, sb := effectStrength(a.Effect), effectStrength(b.Effect); sa != sb {
		return sa > sb
	}
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	return a.RuleID < b.RuleID
}

func decisionOf(e Effect) Decision {
	switch e {
	case EFFECT_DENY:
		return DECISION_DENY
	case EFFECT_WARN:
		return DECISION_WARN
	default:
		return DECISION_ALLOW
	}
}

// deepCopySet returns a value-level copy of set whose slices/maps do not
// alias the input, via a JSON round trip. PolicySets only contain
// JSON-compatible types by construction.
func deepCopySet(in *PolicySet) (*PolicySet, error) {
	data, err := json.Marshal(in)
	if err != nil {
		return nil, &LoadError{Code: ErrInvalidValue,
			Message: "failed to encode policy set: " + err.Error()}
	}
	var out PolicySet
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, &LoadError{Code: ErrInvalidValue,
			Message: "failed to decode policy set copy: " + err.Error()}
	}
	return &out, nil
}
