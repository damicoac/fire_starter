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

type appState int

type moduleOption struct {
	name       string
	startStage string
}

type decisionItem struct {
	title     string
	desc      string
	nextStage string
}

func (d decisionItem) Title() string       { return d.title }
func (d decisionItem) Description() string { return d.desc }
func (d decisionItem) FilterValue() string { return d.title }

type stageExecutedMsg struct {
	toolName      string
	result        decisiontree.ToolResult
	nextInput     decisiontree.ThirdPartyInput
	continueFlow  bool
	errorMessage  string
	currentInput  decisiontree.ThirdPartyInput
	finishedStage string
}

type decisionsReadyMsg struct {
	items []decisionItem
	err   error
}

type pendingTransition struct {
	previousStage string
	currentStage  string
}

type model struct {
	state appState

	ipInput   textinput.Model
	portInput textinput.Model
	focus     int

	tree                *decisiontree.Tree
	llm                 decisiontree.StageGuidanceGenerator
	reinforcement       decisiontree.ReinforcementLearner
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
