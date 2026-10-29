package generator

import (
	"strings"
	"testing"
)

// knownDBMS is the set of DBMS labels the generator is expected to emit.
var knownDBMS = map[string]bool{
	"MySQL":      true,
	"MariaDB":    true,
	"PostgreSQL": true,
	"MSSQL":      true,
	"SQLite":     true,
	"Oracle":     true,
}

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
			for i, poly := range result {
				if poly.Payload == "" {
					t.Errorf("%s() entry %d has empty payload", tt.name, i)
				}
				if poly.Description == "" {
					t.Errorf("%s() entry %d has empty description", tt.name, i)
				}
				if len(poly.DBMS) == 0 {
					t.Errorf("%s() entry %d has no DBMS labels", tt.name, i)
				}
				for _, db := range poly.DBMS {
					if !knownDBMS[db] {
						t.Errorf("%s() entry %d has unknown DBMS label %q", tt.name, i, db)
					}
				}
			}
		})
	}
}

func TestPolyglotGenerator_BENCHMARKIterations(t *testing.T) {
	// A single-digit-million BENCHMARK runs in well under typical time-based
	// thresholds; the payload must use enough iterations to be observable.
	g := NewPolyglotGenerator()
	found := false
	for _, poly := range g.GenerateTimeBasedPolyglots() {
		if strings.Contains(poly.Payload, "BENCHMARK(") {
			found = true
			if !strings.Contains(poly.Payload, "BENCHMARK(10000000,") {
				t.Errorf("BENCHMARK payload has too few iterations: %q", poly.Payload)
			}
		}
	}
	if !found {
		t.Fatal("Expected a BENCHMARK-based time payload")
	}
}
