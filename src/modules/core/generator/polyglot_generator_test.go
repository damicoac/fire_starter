package generator

import (
	"testing"
)

func TestNewPolyglotGenerator(t *testing.T) {
	g := NewPolyglotGenerator()
	if g == nil {
		t.Fatal("NewPolyglotGenerator() returned nil")
	}
}

func TestPolyglotGenerator_PolyglotCollections(t *testing.T) {
	g := NewPolyglotGenerator()

	polyglotFuncs := []struct {
		name string
		fn   func() []Polyglot
	}{
		{"GenerateUniversalPolyglots", g.GenerateUniversalPolyglots},
		{"GenerateWAFBypassPolyglots", g.GenerateWAFBypassPolyglots},
		{"GenerateTimeBasedPolyglots", g.GenerateTimeBasedPolyglots},
	}

	for _, tt := range polyglotFuncs {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			if len(result) == 0 {
				t.Fatalf("%s() returned empty slice", tt.name)
			}
			if result[0].Payload == "" {
				t.Errorf("%s() first element has empty payload", tt.name)
			}
			if result[0].Description == "" {
				t.Errorf("%s() first element has empty description", tt.name)
			}
		})
	}
}
