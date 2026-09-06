package matrix

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Phase represents a professional red team engagement phase
type Phase string

const (
	PhasePreEngagement         Phase = "pre-engagement"
	PhaseReconnaissance        Phase = "reconnaissance"
	PhaseScanning              Phase = "scanning-enumeration"
	PhaseVulnerabilityAnalysis Phase = "vulnerability-analysis"
	PhaseExploitation          Phase = "exploitation"
	PhasePostExploitation      Phase = "post-exploitation"
	PhaseReporting             Phase = "reporting"
)

type RulesOfEngagement struct {
	AllowedIPs     []string `json:"allowed_ips"`
	BlacklistedIPs []string `json:"blacklisted_ips"`
	AllowedDomains []string `json:"allowed_domains"`
}

type Decision struct {
	UseCase              string         `json:"use_case"`
	Technique            string         `json:"technique"`
	Function             string         `json:"function"`
	ProblemTheToolSolves string         `json:"problem_the_tool_solves"`
	Identifier           string         `json:"identifier"`
	Payload              map[string]any `json:"payload,omitempty"`
}

type DecisionData struct {
	Decisions []Decision `json:"decisions"`
}

type ExecutionResult struct {
	DecisionSelected Decision
	ResultData       string
	Timestamp        time.Time
}

type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Identifier  string         `json:"identifier"`
	Technique   string         `json:"technique"`
	InputSchema map[string]any `json:"input_schema"`
}

//go:embed decisions.json
var embeddedDecisions []byte

// Add to the bottom of src/matrix/models.go
func ReadDecisionsFile(path string) ([]byte, error) {
	if len(embeddedDecisions) > 0 {
		return embeddedDecisions, nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		path = filepath.Join("..", "..", "src", "matrix", "decisions.json")
	}
	return os.ReadFile(path)
}

// LoadDecisions reads and parses the decisions configuration into a slice of Decisions.
func LoadDecisions(path ...string) ([]Decision, error) {
	p := "src/matrix/decisions.json"
	if len(path) > 0 && path[0] != "" {
		p = path[0]
	}
	bytes, err := ReadDecisionsFile(p)
	if err != nil {
		return nil, err
	}
	var data DecisionData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, err
	}
	return data.Decisions, nil
}

func NextPhase(current Phase) Phase {
	switch current {
	case PhasePreEngagement:
		return PhaseReconnaissance
	case PhaseReconnaissance:
		return PhaseScanning
	case PhaseScanning:
		return PhaseVulnerabilityAnalysis
	case PhaseVulnerabilityAnalysis:
		return PhaseExploitation
	case PhaseExploitation:
		return PhasePostExploitation
	case PhasePostExploitation:
		return PhaseReporting
	default:
		return PhaseReporting
	}
}
