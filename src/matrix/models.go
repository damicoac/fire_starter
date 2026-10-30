package matrix

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
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

// IsValidPhase reports whether the given phase name matches a defined
// engagement phase. Used to hard-fail on catalog drift at startup.
func IsValidPhase(phase string) bool {
	switch Phase(phase) {
	case PhasePreEngagement, PhaseReconnaissance, PhaseScanning,
		PhaseVulnerabilityAnalysis, PhaseExploitation, PhasePostExploitation,
		PhaseReporting:
		return true
	}
	return false
}

type Decision struct {
	UseCase              string         `json:"use_case"`
	Technique            string         `json:"technique"`
	Function             string         `json:"function"`
	ProblemTheToolSolves string         `json:"problem_the_tool_solves"`
	Identifier           string         `json:"identifier"`
	Payload              map[string]any `json:"payload,omitempty"`
	Phase                string         `json:"phase,omitempty"`
}

type DecisionData struct {
	Decisions []Decision `json:"decisions"`
}

// Description renders the per-tool LLM description from the decision's own
// data; NewToolRegistry uses it for each tool's description.
func (d Decision) Description() string {
	return fmt.Sprintf(
		"%s (id %s). Use case: %s. Problem solved: %s. Implements: %s",
		d.Technique, d.Identifier, d.UseCase, d.ProblemTheToolSolves, d.Function,
	)
}

type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Identifier  string         `json:"identifier"`
	Technique   string         `json:"technique"`
	Phase       string         `json:"phase,omitempty"`
	InputSchema map[string]any `json:"input_schema"`
}

//go:embed decisions.json
var embeddedDecisions []byte

// ReadDecisionsFile returns the decisions catalog. When path is non-empty and
// the file exists on disk, the on-disk file wins; otherwise the embedded copy
// (kept in sync with src/matrix/decisions.json at build time) is returned so
// packaged binaries keep working without the source tree.
func ReadDecisionsFile(path string) ([]byte, error) {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return os.ReadFile(path)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return embeddedDecisions, nil
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
