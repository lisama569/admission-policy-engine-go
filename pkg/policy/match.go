package policy

// Matches reports whether m matches resource r.
//
// Semantics: every condition in All must hold (AND), at least one in Any
// must hold (OR; an empty Any is vacuously true), and none in Not may hold
// (NOT). A zero Match matches every resource.
//
// Policy sets are validated before installation; a malformed condition
// that survived validation is treated as non-matching defensively.
func (m Match) Matches(r *Resource) bool {
	for _, c := range m.All {
		ok, err := evalCondition(r, c)
		if err != nil || !ok {
			return false
		}
	}
	if len(m.Any) > 0 {
		anyMatched := false
		for _, c := range m.Any {
			ok, err := evalCondition(r, c)
			if err == nil && ok {
				anyMatched = true
				break
			}
		}
		if !anyMatched {
			return false
		}
	}
	for _, c := range m.Not {
		ok, err := evalCondition(r, c)
		if err == nil && ok {
			return false
		}
	}
	return true
}

// evalCondition evaluates one condition against r.
//
// Missing-field rule: apart from "exists" (false) and "notIn" (true, the
// absent value is provably not in the list), every predicate on a missing
// field evaluates to false. An absent field must be tested explicitly with
// "exists".
func evalCondition(r *Resource, c Condition) (bool, error) {
	fieldValue, present := r.Field(c.Field)

	switch c.Operator {
	case OP_EXISTS:
		return present, nil
	case OP_IN:
		if !present {
			return false, nil
		}
		for _, candidate := range c.Values {
			if valuesEqual(fieldValue, candidate) {
				return true, nil
			}
		}
		return false, nil
	case OP_NOT_IN:
		if !present {
			return true, nil
		}
		for _, candidate := range c.Values {
			if valuesEqual(fieldValue, candidate) {
				return false, nil
			}
		}
		return true, nil
	case OP_CONTAINS:
		if !present {
			return false, nil
		}
		return containsValue(fieldValue, c.Value)
	case OP_STARTS_WITH:
		s, ok := fieldValue.(string)
		if !ok || !present {
			return false, nil
		}
		prefix, ok := c.Value.(string)
		if !ok {
			return false, nil
		}
		return len(s) >= len(prefix) && s[:len(prefix)] == prefix, nil
	}

	// Remaining operators need a present field and a scalar value.
	if !present {
		return false, nil
	}
	switch c.Operator {
	case OP_EQ:
		return valuesEqual(fieldValue, c.Value), nil
	case OP_NE:
		return !valuesEqual(fieldValue, c.Value), nil
	case OP_GT, OP_GTE, OP_LT, OP_LTE:
		cmp, err := compareOrdered(fieldValue, c.Value)
		if err != nil {
			return false, err
		}
		switch c.Operator {
		case OP_GT:
			return cmp > 0, nil
		case OP_GTE:
			return cmp >= 0, nil
		case OP_LT:
			return cmp < 0, nil
		default:
			return cmp <= 0, nil
		}
	default:
		return false, &LoadError{Code: ErrInvalidOperator, Path: c.Field,
			Message: "unknown operator: " + string(c.Operator)}
	}
}
