package policy

// valuesEqual compares two JSON-derived scalars. JSON numbers decoded into
// float64 are compared numerically, so int64-normalized values and raw
// float64 values compare equal when numerically identical.
func valuesEqual(a, b interface{}) bool {
	if an, aok := toFloat64(a); aok {
		if bn, bok := toFloat64(b); bok {
			return an == bn
		}
		return false
	}
	if as, ok := a.(string); ok {
		bs, ok := b.(string)
		return ok && as == bs
	}
	if ab, ok := a.(bool); ok {
		bb, ok := b.(bool)
		return ok && ab == bb
	}
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return false
}

// containsValue implements "contains": substring for strings, element
// membership for slices/arrays.
func containsValue(haystack, needle interface{}) (bool, error) {
	switch h := haystack.(type) {
	case string:
		s, ok := needle.(string)
		if !ok {
			return false, nil
		}
		return indexOf(h, s) >= 0, nil
	case []interface{}:
		for _, item := range h {
			if valuesEqual(item, needle) {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, nil
	}
}

func indexOf(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// compareOrdered compares numbers numerically and strings lexicographically.
// Mixed types are an error rather than a silent false, because they
// indicate an invalid rule/value pairing.
func compareOrdered(a, b interface{}) (int, error) {
	if an, aok := toFloat64(a); aok {
		bn, bok := toFloat64(b)
		if !bok {
			return 0, &LoadError{Code: ErrInvalidValue,
				Message: "numeric field compared with non-numeric value"}
		}
		switch {
		case an < bn:
			return -1, nil
		case an > bn:
			return 1, nil
		default:
			return 0, nil
		}
	}
	if as, ok := a.(string); ok {
		bs, ok := b.(string)
		if !ok {
			return 0, &LoadError{Code: ErrInvalidValue,
				Message: "string field compared with non-string value"}
		}
		switch {
		case as < bs:
			return -1, nil
		case as > bs:
			return 1, nil
		default:
			return 0, nil
		}
	}
	return 0, &LoadError{Code: ErrInvalidValue,
		Message: "field is not ordered-comparable (number or string required)"}
}

// toFloat64 accepts JSON float64 values and integral int64 values.
func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}
