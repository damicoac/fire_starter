package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"blackwater/decisiontree"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
)

func initialModel() model {
	ipInput := textinput.New()
	ipInput.Placeholder = "10.10.10.10"
	ipInput.Prompt = "IP: "
	ipInput.Focus()

	portInput := textinput.New()
	portInput.Placeholder = "optional (80, 443, 8080)"
	portInput.Prompt = "Port: "

	items := []list.Item{}
	decisionList := list.New(items, list.NewDefaultDelegate(), 10, 10)
	decisionList.Title = "Top 3 Decisions"
	decisionList.SetShowStatusBar(false)
	decisionList.SetFilteringEnabled(false)
	decisionList.SetShowHelp(true)

	vp := viewport.New(10, 10)

	logger := log.NewWithOptions(io.Discard, log.Options{})
	tree, treeErr := decisiontree.NewTreeFromRegistry(logger)

	var generator decisiontree.StageGuidanceGenerator
	var reinforcement decisiontree.ReinforcementLearner
	if treeErr == nil {
		modelName := strings.TrimSpace(os.Getenv("BLACKWATER_OPENAI_MODEL"))
		if modelName == "" {
			modelName = defaultOpenAIModel
		}
		client, err := decisiontree.NewOpenAIResponsesClientFromEnv(modelName)
		if err == nil {
			generator = client
		}

		reinforcementPath := strings.TrimSpace(os.Getenv("BLACKWATER_REINFORCEMENT_DB"))
		reinforcement, err = decisiontree.NewSQLiteReinforcementLearner(reinforcementPath)
		if err != nil {
			treeErr = err
		}
	}

	m := model{
		state:           inputState,
		ipInput:         ipInput,
		portInput:       portInput,
		tree:            tree,
		llm:             generator,
		reinforcement:   reinforcement,
		resultsViewport: vp,
		decisionList:    decisionList,
		statusMessage:   "Enter target IP and optional port, then press Enter.",
	}

	if treeErr != nil {
		m.state = errorState
		m.errorMessage = treeErr.Error()
	}

	return m
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m *model) runSelectedDecisionCmd(index int) tea.Cmd {
	if index < 0 || index >= len(m.decisions) {
		return nil
	}
	choice := m.decisions[index]
	if choice.nextStage == stopDecisionStage {
		m.pendingReinforcement = pendingTransition{}
		m.state = doneState
		m.statusMessage = "Flow stopped."
		return nil
	}
	m.pendingReinforcement = pendingTransition{
		previousStage: m.current.Stage,
		currentStage:  choice.nextStage,
	}
	m.current = buildInputForStage(m.current, choice.nextStage, m.ip, m.port)
	m.currentStep = m.current.Stage
	m.currentMod = moduleFromStage(m.current.Stage)
	m.state = runningState
	m.statusMessage = "Running stage..."
	return runStageCmd(m.tree, m.current)
}

func (m *model) appendResultBlock(block string) {
	if strings.TrimSpace(block) == "" {
		return
	}
	m.results = append(m.results, block)
	m.resultsViewport.SetContent(strings.Join(m.results, "\n\n"))
	m.resultsViewport.GotoBottom()
}

func (m *model) loadDecisionList() {
	items := make([]list.Item, len(m.decisions))
	for i := range m.decisions {
		items[i] = m.decisions[i]
	}
	m.decisionList.SetItems(items)
	if len(items) > 0 {
		m.decisionList.Select(0)
	}
}

func (m model) View() string {
	headerStyle := lipgloss.NewStyle().Bold(true)
	panelStyle := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)

	statusBody := strings.Join([]string{
		fmt.Sprintf("Target: %s", formatTarget(m.ip, m.port)),
		fmt.Sprintf("Current stage: %s", emptyFallback(m.currentStep, "-")),
		fmt.Sprintf("Current module: %s", emptyFallback(m.currentMod, "-")),
		fmt.Sprintf("Current running module: %s", emptyFallback(m.currentTool, "-")),
		fmt.Sprintf("Automation mode: %s", onOff(m.automation)),
		"",
		m.statusMessage,
	}, "\n")
	statusPanel := panelStyle.Render(headerStyle.Render("Status") + "\n" + statusBody)

	switch m.state {
	case inputState:
		form := strings.Join([]string{
			headerStyle.Render("Blackwater TUI"),
			"",
			m.ipInput.View(),
			m.portInput.View(),
			"",
			"Tab to switch fields, Enter to start.",
		}, "\n")
		return lipgloss.JoinVertical(lipgloss.Left, statusPanel, panelStyle.Render(form))
	case runningState, decisionState:
		resultsPanel := panelStyle.Render(headerStyle.Render("Module Results") + "\n" + m.resultsViewport.View())
		decisionsPanel := panelStyle.Render(headerStyle.Render("Top 3 Decisions") + "\n" + m.decisionList.View())
		return lipgloss.JoinVertical(lipgloss.Left, statusPanel, resultsPanel, decisionsPanel)
	case doneState:
		doneBody := panelStyle.Render("Execution complete. Press Enter to exit.")
		return lipgloss.JoinVertical(lipgloss.Left, statusPanel, doneBody)
	case errorState:
		errBody := panelStyle.Render(errorStyle.Render("Error") + "\n" + m.errorMessage + "\n\nPress Enter to exit.")
		return lipgloss.JoinVertical(lipgloss.Left, statusPanel, errBody)
	default:
		return statusPanel
	}
}
