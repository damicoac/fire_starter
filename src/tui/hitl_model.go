package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/wordwrap"
)

type ExecuteFunc func(moduleName, target string) tea.Msg
type RecommendFunc func(target string) tea.Msg
type ReportFunc func() tea.Msg

type HITLModule struct {
	Name        string
	Description string
}

type ModulesLoadedMsg struct {
	Modules []HITLModule
}

type ExecutionResultMsg struct {
	Result       string
	Intelligence string
	Err          error
}

type Recommendation struct {
	Name        string
	Description string
}

type RecommendationsMsg struct {
	Recommendations []Recommendation
}

// Implement list.Item for Recommendation
type recItem struct {
	rec Recommendation
}

func (i recItem) Title() string       { return i.rec.Name }
func (i recItem) Description() string { return i.rec.Description }
func (i recItem) FilterValue() string { return i.rec.Name }

// Implement list.Item for Modules
type moduleItem struct {
	name, desc string
}

func (i moduleItem) Title() string       { return i.name }
func (i moduleItem) Description() string { return i.desc }
func (i moduleItem) FilterValue() string { return i.name }

// Implement list.Item for Targets
type targetItem struct {
	target KGTarget
}

func (i targetItem) Title() string       { return i.target.Value }
func (i targetItem) Description() string { return fmt.Sprintf("Type: %s | Score: %d", i.target.Type, i.target.Score) }
func (i targetItem) FilterValue() string { return i.target.Value }

// Implement list.Item for Logs
type logItem struct {
	short string
	full  string
}

func (i logItem) Title() string       { return i.short }
func (i logItem) Description() string { return "" }
func (i logItem) FilterValue() string { return i.short }

type HITLModel struct {
	executeFn   ExecuteFunc
	recommendFn RecommendFunc
	reportFn    ReportFunc

	activeTab int // 0: Dashboard, 1: Targets, 2: Modules, 3: Recommendations

	// Data
	logs            []logItem
	kgTargets       []KGTarget
	modules         []moduleItem
	recommendations []string
	activeTarget    string

	// Viewports & Lists
	logsList      list.Model
	logsDetailView viewport.Model
	targetList    list.Model
	moduleList    list.Model
	recommendList list.Model
	detailView    viewport.Model

	spinner spinner.Model

	width, height int
	ready         bool
	working       bool
	statusMsg     string
}

func InitialHITLModel(exec ExecuteFunc, rec RecommendFunc, rep ReportFunc) HITLModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	ld := list.NewDefaultDelegate()
	ld.ShowDescription = false
	ld.SetSpacing(0)

	ll := list.New([]list.Item{}, ld, 0, 0)
	ll.Title = "Execution Logs"
	ll.SetShowStatusBar(false)
	ll.SetFilteringEnabled(true)

	tl := list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0)
	tl.Title = "Discovered Targets"
	tl.SetShowStatusBar(false)
	tl.SetFilteringEnabled(true)

	ml := list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0)
	ml.Title = "Available Modules"
	ml.SetShowStatusBar(false)
	ml.SetFilteringEnabled(true)

	rl := list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0)
	rl.Title = "Recommended Modules"
	rl.SetShowStatusBar(false)
	rl.SetFilteringEnabled(true)

	return HITLModel{
		executeFn:     exec,
		recommendFn:   rec,
		reportFn:      rep,
		spinner:       s,
		logs:          make([]logItem, 0),
		logsList:      ll,
		targetList:    tl,
		moduleList:    ml,
		recommendList: rl,
		statusMsg:     "Initializing...",
	}
}

func (m HITLModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m HITLModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.targetList.FilterState() == list.Filtering || m.moduleList.FilterState() == list.Filtering || m.recommendList.FilterState() == list.Filtering {
			// Let list handle input
			goto HandleComponents
		}

		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab":
			m.activeTab = (m.activeTab + 1) % 4
		case "shift+tab":
			m.activeTab = (m.activeTab - 1 + 4) % 4
		case "enter":
			if m.activeTab == 1 {
				// Select active target
				if i, ok := m.targetList.SelectedItem().(targetItem); ok {
					m.activeTarget = i.target.Value
					m.statusMsg = fmt.Sprintf("Active Target set to: %s", m.activeTarget)
				}
			} else if m.activeTab == 2 {
				// Execute module
				if m.activeTarget == "" {
					m.statusMsg = "Cannot execute: No target selected! Go to Targets tab first."
				} else if m.working {
					m.statusMsg = "Already executing a task. Please wait."
				} else {
					if i, ok := m.moduleList.SelectedItem().(moduleItem); ok {
						m.working = true
						m.statusMsg = fmt.Sprintf("Executing %s on %s...", i.name, m.activeTarget)
						m.logs = append(m.logs, logItem{short: m.statusMsg, full: m.statusMsg})
						m.refreshLogs()
						cmds = append(cmds, func() tea.Msg {
							return m.executeFn(i.name, m.activeTarget)
						})
					}
				}
			} else if m.activeTab == 3 {
				// Execute recommended module
				if m.activeTarget == "" {
					m.statusMsg = "Cannot execute: No target selected! Go to Targets tab first."
				} else if m.working {
					m.statusMsg = "Already executing a task. Please wait."
				} else {
					if len(m.recommendList.Items()) > 0 {
						if i, ok := m.recommendList.SelectedItem().(recItem); ok {
							m.working = true
							m.statusMsg = fmt.Sprintf("Executing %s on %s...", i.rec.Name, m.activeTarget)
							m.logs = append(m.logs, logItem{short: m.statusMsg, full: m.statusMsg})
							m.refreshLogs()
							cmds = append(cmds, func() tea.Msg {
								return m.executeFn(i.rec.Name, m.activeTarget)
							})
						}
					}
				}
			}
		case "r":
			// Fetch recommendations
			if m.activeTab == 3 {
				if m.activeTarget == "" {
					m.statusMsg = "Cannot get recommendations: No target selected!"
				} else if m.working {
					m.statusMsg = "Already executing a task. Please wait."
				} else {
					m.working = true
					m.statusMsg = fmt.Sprintf("Fetching LLM recommendations for %s...", m.activeTarget)
					cmds = append(cmds, func() tea.Msg {
						return m.recommendFn(m.activeTarget)
					})
				}
			}
		case "ctrl+r":
			if m.working {
				m.statusMsg = "Already executing a task. Please wait."
			} else {
				m.working = true
				m.statusMsg = "Generating final report..."
				m.logs = append(m.logs, logItem{short: m.statusMsg, full: m.statusMsg})
				m.refreshLogs()
				cmds = append(cmds, func() tea.Msg {
					return m.reportFn()
				})
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true

		headerHeight := lipgloss.Height(m.headerView())
		footerHeight := lipgloss.Height(m.footerView())
		contentHeight := msg.Height - headerHeight - footerHeight - 2
		if contentHeight < 0 {
			contentHeight = 0
		}

		// Logs viewport gets less height to accommodate metrics row in dashboard
		logsHeight := contentHeight - 7
		if logsHeight < 0 {
			logsHeight = 0
		}
		m.logsList.SetSize(msg.Width/2-2, logsHeight)
		m.logsDetailView = viewport.New((msg.Width/2)-4, logsHeight)
		m.detailView = viewport.New((msg.Width/2)-4, contentHeight)

		m.targetList.SetSize(msg.Width/2, contentHeight)
		m.moduleList.SetSize(msg.Width/2, contentHeight)
		m.recommendList.SetSize(msg.Width/2, contentHeight)

		m.refreshLogs()
		m.refreshDetailView()

	case spinner.TickMsg:
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case LogMsg:
		shortText := msg.Text
		if strings.Contains(shortText, "\n") {
			shortText = strings.ReplaceAll(shortText, "\n", " ")
			if len(shortText) > 200 {
				shortText = shortText[:200] + "..."
			}
		}
		m.logs = append(m.logs, logItem{short: shortText, full: msg.Text})
		m.refreshLogs()

	case KGUpdateMsg:
		m.kgTargets, _ = parseKG(msg.Data, m.kgTargets)
		var items []list.Item
		for _, t := range m.kgTargets {
			items = append(items, targetItem{target: t})
		}
		cmd = m.targetList.SetItems(items)
		cmds = append(cmds, cmd)
		m.statusMsg = "Knowledge Graph updated."

	case ModulesLoadedMsg:
		var items []list.Item
		for _, mod := range msg.Modules {
			items = append(items, moduleItem{name: mod.Name, desc: mod.Description})
		}
		cmd = m.moduleList.SetItems(items)
		cmds = append(cmds, cmd)
		m.statusMsg = fmt.Sprintf("Loaded %d modules.", len(msg.Modules))

	case ExecutionResultMsg:
		m.working = false
		if msg.Err != nil {
			m.statusMsg = fmt.Sprintf("Execution failed: %v", msg.Err)
			errStr := fmt.Sprintf("[ERROR] %v", msg.Err)
			m.logs = append(m.logs, logItem{short: errStr, full: errStr})
		} else {
			m.statusMsg = "Execution completed successfully."
			resStr := msg.Result
			fullStr := resStr
			if len(resStr) > 200 {
				resStr = resStr[:200] + "... [TRUNCATED]"
			}
			resStr = strings.ReplaceAll(resStr, "\n", " ")
			
			fullText := fmt.Sprintf("[RESULT]\n%s", fullStr)
			if msg.Intelligence != "" {
				fullText = fmt.Sprintf("%s\n\n%s", fullText, msg.Intelligence)
			}
			
			m.logs = append(m.logs, logItem{
				short: fmt.Sprintf("[RESULT] %s", resStr),
				full:  fullText,
			})
		}
		m.refreshLogs()

	case RecommendationsMsg:
		m.working = false
		var items []list.Item
		for _, rec := range msg.Recommendations {
			items = append(items, recItem{rec: rec})
		}
		cmd = m.recommendList.SetItems(items)
		cmds = append(cmds, cmd)
		m.statusMsg = "Recommendations loaded."
		m.refreshDetailView()
	}

HandleComponents:
	if m.ready {
		switch m.activeTab {
		case 0:
			m.logsList, cmd = m.logsList.Update(msg)
			cmds = append(cmds, cmd)
			m.logsDetailView, cmd = m.logsDetailView.Update(msg)
			cmds = append(cmds, cmd)
		case 1:
			m.targetList, cmd = m.targetList.Update(msg)
			cmds = append(cmds, cmd)
			m.detailView, cmd = m.detailView.Update(msg)
			cmds = append(cmds, cmd)
		case 2:
			m.moduleList, cmd = m.moduleList.Update(msg)
			cmds = append(cmds, cmd)
			m.detailView, cmd = m.detailView.Update(msg)
			cmds = append(cmds, cmd)
		case 3:
			m.recommendList, cmd = m.recommendList.Update(msg)
			cmds = append(cmds, cmd)
			m.detailView, cmd = m.detailView.Update(msg)
			cmds = append(cmds, cmd)
		}
		m.refreshDetailView()
	}

	return m, tea.Batch(cmds...)
}

func (m *HITLModel) refreshLogs() {
	if !m.ready {
		return
	}
	var items []list.Item
	for _, l := range m.logs {
		items = append(items, l)
	}
	m.logsList.SetItems(items)
	m.logsList.Select(len(items) - 1)
}

func (m *HITLModel) refreshDetailView() {
	if !m.ready {
		return
	}
	var content string

	headlineStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true).Underline(true)
	subHeadStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).MarginTop(1)
	badgeStyle := lipgloss.NewStyle().Background(lipgloss.Color("62")).Foreground(lipgloss.Color("255")).Padding(0, 1).MarginRight(1)
	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Italic(true).MarginTop(2)
	errHintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Italic(true).Bold(true).MarginTop(2)
	listStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("250")).MarginLeft(2)

	switch m.activeTab {
	case 0:
		if i, ok := m.logsList.SelectedItem().(logItem); ok {
			content = lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Render(i.full)
		} else {
			content = hintStyle.Render("No log selected.")
		}
		m.logsDetailView.SetContent(wordwrap.String(content, m.logsDetailView.Width))
	case 1:
		if i, ok := m.targetList.SelectedItem().(targetItem); ok {
			t := i.target
			b1 := badgeStyle.Render(fmt.Sprintf("Type: %s", t.Type))
			b2 := badgeStyle.Render(fmt.Sprintf("Score: %d", t.Score))
			
			content = headlineStyle.Render(t.Value) + "\n\n" + b1 + b2 + "\n"
			
			if len(t.OpenPorts) > 0 {
				content += subHeadStyle.Render("Open Ports:") + "\n"
				content += listStyle.Render(fmt.Sprintf("%v", t.OpenPorts)) + "\n"
			}
			if len(t.Vulnerabilities) > 0 {
				content += subHeadStyle.Render("Vulnerabilities:") + "\n"
				for _, v := range t.Vulnerabilities {
					content += listStyle.Render("• " + v) + "\n"
				}
			}
			if len(t.Credentials) > 0 {
				content += subHeadStyle.Render("Credentials:") + "\n"
				for _, c := range t.Credentials {
					content += listStyle.Render(fmt.Sprintf("• %s:%s", c.Username, c.Password)) + "\n"
				}
			}
			if len(t.Tokens) > 0 {
				content += subHeadStyle.Render("Tokens:") + "\n"
				for _, t := range t.Tokens {
					content += listStyle.Render("• " + t) + "\n"
				}
			}
			content += hintStyle.Render("[Press Enter to set as Active Target]")
		} else {
			content = hintStyle.Render("No target selected.")
		}
	case 2:
		if i, ok := m.moduleList.SelectedItem().(moduleItem); ok {
			desc := i.desc
			desc = strings.ReplaceAll(desc, "Use Case:", subHeadStyle.Render("Use Case:"))
			desc = strings.ReplaceAll(desc, "\nFunction:", "\n\n"+subHeadStyle.Render("Function:"))
			desc = strings.ReplaceAll(desc, "\nProblem Solved:", "\n\n"+subHeadStyle.Render("Problem Solved:"))
			desc = strings.ReplaceAll(desc, "\nContext:", "\n\n"+subHeadStyle.Render("Context:"))

			content = headlineStyle.Render(i.name) + "\n\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Render(desc) + "\n"
			if m.activeTarget == "" {
				content += errHintStyle.Render("[Cannot Execute: No Active Target Selected!]")
			} else {
				content += hintStyle.Render(fmt.Sprintf("[Press Enter to Execute against %s]", m.activeTarget))
			}
		} else {
			content = hintStyle.Render("No module selected.")
		}
	case 3:
		if m.activeTarget == "" {
			content = errHintStyle.Render("No target selected. Go to Targets tab to select one.")
		} else if len(m.recommendList.Items()) == 0 {
			content = hintStyle.Render(fmt.Sprintf("No recommendations loaded for %s.\n\n[Press 'r' to Fetch LLM Recommendations]", m.activeTarget))
		} else {
			if i, ok := m.recommendList.SelectedItem().(recItem); ok {
				desc := i.rec.Description
				desc = strings.ReplaceAll(desc, "Score:", subHeadStyle.Render("Score:"))
				desc = strings.ReplaceAll(desc, "Use Case:", subHeadStyle.Render("Use Case:"))
				desc = strings.ReplaceAll(desc, "\nFunction:", "\n\n"+subHeadStyle.Render("Function:"))
				desc = strings.ReplaceAll(desc, "\nProblem Solved:", "\n\n"+subHeadStyle.Render("Problem Solved:"))
				desc = strings.ReplaceAll(desc, "\nContext:", "\n\n"+subHeadStyle.Render("Context:"))

				content = headlineStyle.Render(i.rec.Name) + "\n\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Render(desc) + "\n"
				content += hintStyle.Render(fmt.Sprintf("[Press Enter to Execute against %s]\n\n[Press 'r' to Refresh Recommendations]", m.activeTarget))
			} else {
				content = hintStyle.Render("No recommendation selected.\n\n[Press 'r' to Refresh Recommendations]")
			}
		}
	}

	m.detailView.SetContent(wordwrap.String(content, m.detailView.Width))
}

func (m HITLModel) headerView() string {
	title := titleStyle.Render("Fire Starter C2")
	
	activeTgtStr := "None"
	if m.activeTarget != "" {
		activeTgtStr = m.activeTarget
	}
	targetInfo := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Render(fmt.Sprintf(" Target: %s ", activeTgtStr))

	spin := "  "
	if m.working {
		spin = m.spinner.View() + " "
	}
	status := spin + statusStyle.Render(m.statusMsg)
	
	tabs := []string{"Dashboard", "Targets", "Modules", "Recommendations"}
	var renderedTabs []string
	for i, t := range tabs {
		if i == m.activeTab {
			renderedTabs = append(renderedTabs, lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render("["+t+"]"))
		} else {
			renderedTabs = append(renderedTabs, lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(" "+t+" "))
		}
	}
	tabBar := strings.Join(renderedTabs, "  ")

	headerTop := lipgloss.JoinHorizontal(lipgloss.Top, title, targetInfo, "  ", status)
	headerBottom := tabBar
	return lipgloss.JoinVertical(lipgloss.Left, headerTop, headerBottom)
}

func (m HITLModel) dashboardView() string {
	targetsCount := len(m.kgTargets)
	var vulnCount, portCount, credCount int
	for _, t := range m.kgTargets {
		vulnCount += len(t.Vulnerabilities)
		portCount += len(t.OpenPorts)
		credCount += len(t.Credentials)
	}

	boxWidth := (m.width - 10) / 4
	if boxWidth < 10 {
		boxWidth = 10
	}

	headerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Bold(true).Underline(true).Width(boxWidth).Align(lipgloss.Left)

	h1 := headerStyle.Render("Targets")
	h2 := headerStyle.Render("Vulns")
	h3 := headerStyle.Render("Ports")
	h4 := headerStyle.Render("Creds")
	headerRow := lipgloss.JoinHorizontal(lipgloss.Top, h1, h2, h3, h4)

	valStyle := lipgloss.NewStyle().Bold(true).Width(boxWidth).Align(lipgloss.Left)
	v1 := valStyle.Copy().Foreground(lipgloss.Color("86")).Render(fmt.Sprintf("%d", targetsCount))
	v2 := valStyle.Copy().Foreground(lipgloss.Color("196")).Render(fmt.Sprintf("%d", vulnCount))
	v3 := valStyle.Copy().Foreground(lipgloss.Color("208")).Render(fmt.Sprintf("%d", portCount))
	v4 := valStyle.Copy().Foreground(lipgloss.Color("112")).Render(fmt.Sprintf("%d", credCount))
	dataRow := lipgloss.JoinHorizontal(lipgloss.Top, v1, v2, v3, v4)

	metricsRow := lipgloss.JoinVertical(lipgloss.Left, headerRow, dataRow)

	left := lipgloss.NewStyle().Width(m.width/2 - 2).Render(m.logsList.View())
	right := lipgloss.NewStyle().Width(m.width/2 - 2).Render(m.logsDetailView.View())
	logsArea := lipgloss.JoinHorizontal(lipgloss.Top, left, right)

	return lipgloss.JoinVertical(lipgloss.Left, metricsRow, "", logsArea)
}

func (m HITLModel) footerView() string {
	helpText := "tab: switch panes • up/down: navigate • enter: select/execute • ctrl+r: report • q/ctrl+c: quit"
	return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(helpText)
}

func (m HITLModel) View() string {
	if !m.ready {
		return "\n  Initializing C2..."
	}

	var content string

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1)

	switch m.activeTab {
	case 0:
		boxH := m.logsList.Height() + 7
		if boxH < 0 {
			boxH = 0
		}
		content = boxStyle.Width(m.width - 2).Height(boxH).Render(m.dashboardView())
	case 1:
		left := boxStyle.Width(m.width/2 - 2).Render(m.targetList.View())
		right := boxStyle.Width(m.width/2 - 2).Render(m.detailView.View())
		content = lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	case 2:
		left := boxStyle.Width(m.width/2 - 2).Render(m.moduleList.View())
		right := boxStyle.Width(m.width/2 - 2).Render(m.detailView.View())
		content = lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	case 3:
		left := boxStyle.Width(m.width/2 - 2).Render(m.recommendList.View())
		right := boxStyle.Width(m.width/2 - 2).Render(m.detailView.View())
		content = lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	}

	return lipgloss.JoinVertical(lipgloss.Left, m.headerView(), content, m.footerView())
}
