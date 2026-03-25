// File overview:
// TUI state transition engine. It translates keyboard/input events and stage execution messages into deterministic UI behavior so operators can trust what action happens next.

package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		resultsHeight := maxInt(8, msg.Height-17)
		m.resultsViewport.Width = maxInt(20, msg.Width-6)
		m.resultsViewport.Height = resultsHeight
		m.resultsViewport.SetContent(strings.Join(m.results, "\n\n"))
		m.decisionList.SetSize(maxInt(20, msg.Width-6), 7)
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.closeResources()
			return m, tea.Quit
		}
	}

	switch m.state {
	case inputState:
		return m.updateInput(msg)
	case runningState:
		return m.updateRunning(msg)
	case decisionState:
		return m.updateDecision(msg)
	case doneState, errorState:
		if keyMsg, ok := msg.(tea.KeyMsg); ok {
			if keyMsg.String() == "enter" {
				m.closeResources()
				return m, tea.Quit
			}
		}
		return m, nil
	default:
		return m, nil
	}
}

func (m model) updateInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "tab", "shift+tab", "up", "down":
			if m.focus == 0 {
				m.focus = 1
				m.ipInput.Blur()
				m.portInput.Focus()
			} else {
				m.focus = 0
				m.portInput.Blur()
				m.ipInput.Focus()
			}
			return m, nil
		case "enter":
			ip := strings.TrimSpace(m.ipInput.Value())
			port := strings.TrimSpace(m.portInput.Value())
			if net.ParseIP(ip) == nil {
				m.statusMessage = "Invalid IP address."
				return m, nil
			}
			if port != "" {
				p, err := strconv.Atoi(port)
				if err != nil || p < 1 || p > 65535 {
					m.statusMessage = "Port must be empty or 1-65535."
					return m, nil
				}
			}
			if m.tree == nil {
				m.state = errorState
				m.errorMessage = "decision tree failed to initialize"
				return m, nil
			}
			m.ip = ip
			m.port = port
			m.current = buildInitialInput(ip, port)
			m.currentStep = m.current.Stage
			m.currentMod = moduleFromStage(m.current.Stage)
			m.currentTool = ""
			m.pendingReinforcement = pendingTransition{}
			m.statusMessage = "Running stage..."
			m.state = runningState
			return m, runStageCmd(m.tree, m.current)
		}
	}

	var cmd tea.Cmd
	if m.focus == 0 {
		m.ipInput, cmd = m.ipInput.Update(msg)
	} else {
		m.portInput, cmd = m.portInput.Update(msg)
	}
	return m, cmd
}

func (m model) updateRunning(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case stageExecutedMsg:
		if msg.errorMessage != "" {
			m.logPendingReinforcementOutcome(-1)
			m.state = errorState
			m.errorMessage = msg.errorMessage
			return m, nil
		}
		m.logPendingReinforcementOutcome(1)
		m.currentTool = msg.toolName
		m.currentStep = msg.finishedStage
		m.currentMod = moduleFromStage(msg.finishedStage)
		m.current = msg.currentInput
		m.appendResultBlock(formatResultBlock(msg.result, msg.finishedStage))
		m.statusMessage = "Review decisions (Enter to pick, A to automate)."
		m.state = decisionState
		return m, buildDecisionsCmd(m.llm, m.reinforcement, msg.currentInput, msg.result, msg.nextInput, msg.continueFlow)
	case decisionsReadyMsg:
		if msg.err != nil {
			m.appendResultBlock("decision generation error: " + msg.err.Error())
		}
		m.decisions = msg.items
		m.loadDecisionList()
		if m.automation {
			return m, m.runSelectedDecisionCmd(0)
		}
		return m, nil
	default:
		return m, nil
	}
}

func (m *model) logPendingReinforcementOutcome(reward int) {
	if m.reinforcement == nil {
		m.pendingReinforcement = pendingTransition{}
		return
	}
	if m.pendingReinforcement.previousStage == "" || m.pendingReinforcement.currentStage == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = m.reinforcement.RecordTransition(ctx, m.pendingReinforcement.previousStage, m.pendingReinforcement.currentStage, reward)
	m.pendingReinforcement = pendingTransition{}
}

func (m model) updateDecision(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "a":
			m.automation = !m.automation
			if m.automation {
				m.statusMessage = "Automation enabled."
				if len(m.decisions) > 0 {
					return m, m.runSelectedDecisionCmd(0)
				}
			} else {
				m.statusMessage = "Automation disabled."
			}
			return m, nil
		case "enter":
			idx := m.decisionList.Index()
			if idx < 0 || idx >= len(m.decisions) {
				return m, nil
			}
			return m, m.runSelectedDecisionCmd(idx)
		}
	case decisionsReadyMsg:
		if msg.err != nil {
			m.appendResultBlock("decision generation error: " + msg.err.Error())
		}
		m.decisions = msg.items
		m.loadDecisionList()
		if m.automation {
			return m, m.runSelectedDecisionCmd(0)
		}
		return m, nil
	case stageExecutedMsg:
		if msg.errorMessage != "" {
			m.logPendingReinforcementOutcome(-1)
			m.state = errorState
			m.errorMessage = msg.errorMessage
			return m, nil
		}
		m.logPendingReinforcementOutcome(1)
		m.currentTool = msg.toolName
		m.currentStep = msg.finishedStage
		m.currentMod = moduleFromStage(msg.finishedStage)
		m.current = msg.currentInput
		m.appendResultBlock(formatResultBlock(msg.result, msg.finishedStage))
		return m, buildDecisionsCmd(m.llm, m.reinforcement, msg.currentInput, msg.result, msg.nextInput, msg.continueFlow)
	}

	var cmd tea.Cmd
	m.decisionList, cmd = m.decisionList.Update(msg)
	return m, cmd
}
