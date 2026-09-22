package loader

import (
	"errors"
	"testing"

	"github.com/lisama569/admission-policy-engine-go/pkg/policy"
)

func TestLoad_VersionDispatch(t *testing.T) {
	v1 := `{"version":"v1","rules":[{"name":"r","action":"reject","targetKind":"Pod"}]}`
	v2 := `{"version":"v2","rules":[{"id":"r","effect":"deny","match":{"all":[{"field":"kind","operator":"eq","value":"Pod"}]}}]}`

	s1, err := Load([]byte(v1))
	if err != nil {
		t.Fatalf("v1 load: %v", err)
	}
	s2, err := Load([]byte(v2))
	if err != nil {
		t.Fatalf("v2 load: %v", err)
	}
	if s1.Version != "v2" || s1.Rules[0].ID != "legacy-r" {
		t.Fatalf("v1 was not normalized: %+v", s1)
	}
	t.Logf("v1 normalized -> id=%s effect=%s; v2 loaded id=%s effect=%s",
		s1.Rules[0].ID, s1.Rules[0].Effect, s2.Rules[0].ID, s2.Rules[0].Effect)
}

func TestLoad_Rejections(t *testing.T) {
	cases := []struct {
		raw  string
		code policy.LoadErrorCode
	}{
		{`{`, policy.ErrInvalidJSON},
		{`{"rules":[]}`, policy.ErrMissingVersion},
		{`{"version":"v7","rules":[]}`, policy.ErrUnsupportedVersion},
		{`{"version":"v1","rules":[{"name":"r","action":"deny"}]}`, policy.ErrAmbiguousLegacyRule},
	}
	for i, tc := range cases {
		_, err := Load([]byte(tc.raw))
		var le *policy.LoadError
		if !errors.As(err, &le) {
			t.Fatalf("case %d: want LoadError, got %v", i, err)
		}
		if le.Code != tc.code {
			t.Fatalf("case %d: want %s got %s (%s)", i, tc.code, le.Code, le.Message)
		}
		t.Logf("case %d rejected: %s: %s", i, le.Code, le.Message)
	}
}
