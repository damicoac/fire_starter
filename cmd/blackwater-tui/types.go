// File overview:
// Primary TUI data model definitions. These structures exist to make UI state explicit and serializable in-memory so each stage transition is observable and debuggable.

package main

import (
	"blackwater/decisiontree"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
)

const (
	stageTargetReceived             = "target.received"
	stageAPITestingRecon            = "api-testing.recon"
	stageApplicationMappingExplore  = "application-mapping.explore"
	stageActiveTestingAccessControl = "active-testing.access-control"
	stopDecisionStage               = "__stop__"
	defaultOpenAIModel              = "gpt-4.1-mini"
	inputState              appState = iota
	runningState
	decisionState
	doneState
	errorState
)

// appState is a coarse UI mode switch.
// It exists so update/render logic can branch on a small stable enum instead
// of inferring state from scattered fields.
type appState int

// moduleOption represents a jump target into a module's entry stage.
// Keeping this as a small struct makes cross-module switching explicit and
// avoids embedding stage literals throughout decision-building code.
type moduleOption struct {
	name       string
	startStage string
}

// decisionItem is the UI-facing unit for a selectable next action.
// It carries both human-readable rationale and machine-usable next stage so
// operators can understand why a branch is offered before executing it.
type decisionItem struct {
	title     string
	desc      string
	nextStage string
}

func (d decisionItem) Title() string       { return d.title }
func (d decisionItem) Description() string { return d.desc }
func (d decisionItem) FilterValue() string { return d.title }

// stageExecutedMsg is the async boundary between stage execution and UI state.
// A dedicated message struct prevents partial updates by delivering all stage
// outcomes (result, transition, and errors) as one atomic payload.
type stageExecutedMsg struct {
	toolName      string
	result        decisiontree.ToolResult
	nextInput     decisiontree.ThirdPartyInput
	continueFlow  bool
	errorMessage  string
	currentInput  decisiontree.ThirdPartyInput
	finishedStage string
}

// decisionsReadyMsg carries ranked options back into the main event loop.
// Separating this from execution messages keeps decision-generation failures
// isolated and allows safe fallback behavior without corrupting run state.
type decisionsReadyMsg struct {
	items []decisionItem
	err   error
}

// pendingTransition stores the most recent stage hop awaiting reinforcement
// feedback so reward logging can be delayed until success/failure is known.
type pendingTransition struct {
	previousStage string
	currentStage  string
}

// model is the single source of truth for all TUI runtime state.
// Consolidating UI inputs, execution context, decisions, and rendering data in
// one struct makes behavior deterministic across Bubble Tea update cycles.
type model struct {
	state appState

	ipInput   textinput.Model
	portInput textinput.Model
	focus     int

	tree                *decisiontree.Tree
	llm                 decisiontree.StageGuidanceGenerator
	reinforcement       decisiontree.ReinforcementLearner
	auditLogger         decisiontree.AuditLogger
	pendingReinforcement pendingTransition
	automation          bool
	ip                  string
	port                string
	current             decisiontree.ThirdPartyInput
	currentTool         string
	currentMod          string
	currentStep         string

	statusMessage string
	errorMessage  string

	results         []string
	resultsViewport viewport.Model
	decisionList    list.Model
	decisions       []decisionItem

	width  int
	height int
}
