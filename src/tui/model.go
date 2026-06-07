package tui

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/wordwrap"
)

var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("205")).
			Bold(true).
			Padding(0, 1).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62"))

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))
)

// Messages
type LogMsg struct {
	Text string
}

type AgentFinishedMsg struct {
	Report string
}

type KGUpdateMsg struct {
	Data []byte
}



type KGTarget struct {
	Value           string
	Type            string
	Score           int
	OpenPorts       []int
	Tokens          []string
	Vulnerabilities []string
	Credentials     []struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	Expanded bool
}

type KGNode struct {
	Label       string
	Icon        string
	Color       lipgloss.Color
	Level       int
	IsTarget    bool
	TargetIndex int // Index into kgTargets
	DetailText  string // Text to display in the detail pane
}

type Model struct {
	logsViewport     viewport.Model
	kgTreeViewport   viewport.Model
	kgDetailViewport viewport.Model
	spinner          spinner.Model
	logs             []string
	kgTargets        []KGTarget
	kgNodes          []KGNode
	kgTreeCursor     int
	currentPhase     string
	ready            bool
	finished         bool
	finalReport      string
	width            int
	height           int

	activePane       int // 0 = logs, 1 = sidebar
}

func InitialModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return Model{
		spinner: s,
		logs:    make([]string, 0),
	}
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

func parseKG(data []byte, existingTargets []KGTarget) ([]KGTarget, string) {
	var kg struct {
		Targets map[string]struct {
			Value           string   `json:"value"`
			Type            string   `json:"type"`
			Score           int      `json:"score"`
			OpenPorts       []int    `json:"open_ports"`
			Tokens          []string `json:"tokens"`
			Vulnerabilities []string `json:"vulnerabilities"`
			Credentials     []struct {
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"credentials"`
		} `json:"targets"`
		CurrentPhase string `json:"current_phase"`
	}

	if err := json.Unmarshal(data, &kg); err != nil {
		return existingTargets, ""
	}

	expandedMap := make(map[string]bool)
	for _, t := range existingTargets {
		expandedMap[t.Value] = t.Expanded
	}

	var newTargets []KGTarget
	for _, t := range kg.Targets {
		newTargets = append(newTargets, KGTarget{
			Value:           t.Value,
			Type:            t.Type,
			Score:           t.Score,
			OpenPorts:       t.OpenPorts,
			Tokens:          t.Tokens,
			Vulnerabilities: t.Vulnerabilities,
			Credentials:     t.Credentials,
			Expanded:        expandedMap[t.Value],
		})
	}

	sort.Slice(newTargets, func(i, j int) bool {
		if newTargets[i].Score == newTargets[j].Score {
			return newTargets[i].Value < newTargets[j].Value
		}
		return newTargets[i].Score > newTargets[j].Score
	})

	return newTargets, kg.CurrentPhase
}

func buildKGNodes(targets []KGTarget) []KGNode {
	var nodes []KGNode
	for i, t := range targets {
		icon := "🌐"
		color := lipgloss.Color("33") // Blue
		if t.Type == "ip" {
			icon = "🖥️ "
			color = lipgloss.Color("46") // Green
		}
		
		hasChildren := len(t.OpenPorts) > 0 || len(t.Vulnerabilities) > 0 || len(t.Tokens) > 0 || len(t.Credentials) > 0
		exp := " "
		if hasChildren {
			exp = "▶"
			if t.Expanded {
				exp = "▼"
			}
		}
		
		nodes = append(nodes, KGNode{
			Label:       fmt.Sprintf("%s %s %s", exp, icon, t.Value),
			Color:       color,
			Level:       0,
			IsTarget:    true,
			TargetIndex: i,
			DetailText:  fmt.Sprintf("Type: %s\nScore: %d\nOpen Ports: %d\nVulnerabilities: %d\nTokens: %d\nCredentials: %d", t.Type, t.Score, len(t.OpenPorts), len(t.Vulnerabilities), len(t.Tokens), len(t.Credentials)),
		})

		if t.Expanded {
			for _, p := range t.OpenPorts {
				nodes = append(nodes, KGNode{
					Label:       fmt.Sprintf("🔌 Port %d", p),
					Color:       lipgloss.Color("99"), // Purple
					Level:       1,
					TargetIndex: i,
					DetailText:  fmt.Sprintf("Target: %s\nOpen Port: %d", t.Value, p),
				})
			}
			for _, v := range t.Vulnerabilities {
				nodes = append(nodes, KGNode{
					Label:       fmt.Sprintf("⚠️  %s", v),
					Color:       lipgloss.Color("196"), // Red
					Level:       1,
					TargetIndex: i,
					DetailText:  fmt.Sprintf("Target: %s\n\nVulnerability:\n%s", t.Value, v),
				})
			}
			for _, token := range t.Tokens {
				nodes = append(nodes, KGNode{
					Label:       "🔑 Token",
					Color:       lipgloss.Color("220"), // Yellow
					Level:       1,
					TargetIndex: i,
					DetailText:  fmt.Sprintf("Target: %s\n\nToken/Cookie:\n%s", t.Value, token),
				})
			}
			for _, cred := range t.Credentials {
				nodes = append(nodes, KGNode{
					Label:       fmt.Sprintf("👤 %s", cred.Username),
					Color:       lipgloss.Color("240"), // Gray
					Level:       1,
					TargetIndex: i,
					DetailText:  fmt.Sprintf("Target: %s\n\nUsername: %s\nPassword: %s", t.Value, cred.Username, cred.Password),
				})
			}
		}
	}
	return nodes
}

func (m *Model) updateKGViewports() {
	if !m.ready {
		return
	}

	var treeBuilder strings.Builder
	for i, n := range m.kgNodes {
		prefix := ""
		if n.Level > 0 {
			prefix = "  └─ "
		}
		
		cursor := "  "
		if i == m.kgTreeCursor {
			cursor = "> "
		}

		style := lipgloss.NewStyle().Foreground(n.Color)
		if i == m.kgTreeCursor && m.activePane == 1 {
			style = style.Bold(true).Background(lipgloss.Color("236"))
		}

		line := cursor + prefix + style.Render(n.Label)
		treeBuilder.WriteString(line + "\n")
	}

	if len(m.kgNodes) == 0 {
		treeBuilder.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("  No targets discovered yet.\n"))
	}

	m.kgTreeViewport.SetContent(treeBuilder.String())
	
	if m.kgTreeCursor < m.kgTreeViewport.YOffset {
		m.kgTreeViewport.SetYOffset(m.kgTreeCursor)
	} else if m.kgTreeCursor >= m.kgTreeViewport.YOffset+m.kgTreeViewport.Height {
		m.kgTreeViewport.SetYOffset(m.kgTreeCursor - m.kgTreeViewport.Height + 1)
	}

	detailContent := ""
	if len(m.kgNodes) > 0 && m.kgTreeCursor < len(m.kgNodes) {
		node := m.kgNodes[m.kgTreeCursor]
		header := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true).Render("Detail View")
		detailContent = header + "\n" + strings.Repeat("─", 20) + "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Render(node.DetailText)
	}
	m.kgDetailViewport.SetContent(wordwrap.String(detailContent, m.kgDetailViewport.Width))
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab":
			m.activePane = (m.activePane + 1) % 2
			m.updateKGViewports()
		case "up", "k":
			if m.activePane == 1 {
				if m.kgTreeCursor > 0 {
					m.kgTreeCursor--
					m.updateKGViewports()
				}
			} else if m.activePane == 0 {
				m.logsViewport.LineUp(1)
			}
		case "down", "j":
			if m.activePane == 1 {
				if m.kgTreeCursor < len(m.kgNodes)-1 {
					m.kgTreeCursor++
					m.updateKGViewports()
				}
			} else if m.activePane == 0 {
				m.logsViewport.LineDown(1)
			}
		case "enter", " ":
			if m.activePane == 1 {
				if len(m.kgNodes) > 0 && m.kgTreeCursor < len(m.kgNodes) {
					if m.kgNodes[m.kgTreeCursor].IsTarget {
						idx := m.kgNodes[m.kgTreeCursor].TargetIndex
						m.kgTargets[idx].Expanded = !m.kgTargets[idx].Expanded
						m.kgNodes = buildKGNodes(m.kgTargets)
						m.updateKGViewports()
					}
				}
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		headerHeight := lipgloss.Height(m.headerView())
		footerHeight := lipgloss.Height(m.footerView())
		verticalMarginHeight := headerHeight + footerHeight + 3

		logsWidth := ((msg.Width * 2) / 3) - 4
		kgWidth := msg.Width - ((msg.Width * 2) / 3) - 4

		if logsWidth < 0 { logsWidth = 0 }
		if kgWidth < 0 { kgWidth = 0 }

		kgHeight := max(0, msg.Height-verticalMarginHeight)
		kgTreeHeight := kgHeight / 2
		kgDetailHeight := kgHeight - kgTreeHeight - 1 // -1 for a divider if we want, or just let them abut

		if !m.ready {
			m.logsViewport = viewport.New(logsWidth, max(0, msg.Height-verticalMarginHeight))
			m.kgTreeViewport = viewport.New(kgWidth, kgTreeHeight)
			m.kgDetailViewport = viewport.New(kgWidth, kgDetailHeight)
			m.ready = true
		} else {
			m.logsViewport.Width = logsWidth
			m.logsViewport.Height = max(0, msg.Height-verticalMarginHeight)
			m.kgTreeViewport.Width = kgWidth
			m.kgTreeViewport.Height = kgTreeHeight
			m.kgDetailViewport.Width = kgWidth
			m.kgDetailViewport.Height = kgDetailHeight
		}

		m.logsViewport.SetContent(wordwrap.String(strings.Join(m.logs, "\n"), m.logsViewport.Width))
		m.updateKGViewports()

	case LogMsg:
		m.logs = append(m.logs, msg.Text)
		if m.ready {
			m.logsViewport.SetContent(wordwrap.String(strings.Join(m.logs, "\n"), m.logsViewport.Width))
			m.logsViewport.GotoBottom()
		}

	case KGUpdateMsg:
		m.kgTargets, m.currentPhase = parseKG(msg.Data, m.kgTargets)
		m.kgNodes = buildKGNodes(m.kgTargets)
		if m.kgTreeCursor >= len(m.kgNodes) {
			m.kgTreeCursor = max(0, len(m.kgNodes)-1)
		}
		m.updateKGViewports()

	case AgentFinishedMsg:
		m.finished = true
		m.finalReport = msg.Report



	case spinner.TickMsg:
		if !m.finished {
			var spinnerCmd tea.Cmd
			m.spinner, spinnerCmd = m.spinner.Update(msg)
			cmds = append(cmds, spinnerCmd)
		}
	}

	if m.ready {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "up", "down", "k", "j":
				// Skip passing navigation keys to viewports, we handle them manually
			default:
				if m.activePane == 0 {
					m.logsViewport, cmd = m.logsViewport.Update(msg)
					cmds = append(cmds, cmd)
				}
				if m.activePane == 1 {
					m.kgTreeViewport, cmd = m.kgTreeViewport.Update(msg)
					cmds = append(cmds, cmd)
					m.kgDetailViewport, cmd = m.kgDetailViewport.Update(msg)
					cmds = append(cmds, cmd)
				}
			}
		default:
			m.logsViewport, cmd = m.logsViewport.Update(msg)
			cmds = append(cmds, cmd)
			m.kgTreeViewport, cmd = m.kgTreeViewport.Update(msg)
			cmds = append(cmds, cmd)
			m.kgDetailViewport, cmd = m.kgDetailViewport.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

func (m Model) headerView() string {
	title := titleStyle.Render("Fire Starter")
	
	var headerStatus string
	if m.finished {
		headerStatus = statusStyle.Render("Agent finished.")
	} else {
		spin := m.spinner.View()
		headerStatus = spin + statusStyle.Render(" Agent is working...")
	}
	
	headerStatus = "  " + headerStatus + "  "

	availableWidth := m.width - lipgloss.Width(title) - lipgloss.Width(headerStatus) - 2
	line := strings.Repeat("─", max(0, availableWidth))
	
	return lipgloss.JoinHorizontal(lipgloss.Center, title, headerStatus, lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Render(line))
}

func (m Model) footerView() string {
	bgColor := lipgloss.Color("62") // Default neutral background
	switch m.currentPhase {
	case "pre-engagement":
		bgColor = lipgloss.Color("63") // Purple
	case "reconnaissance":
		bgColor = lipgloss.Color("33") // Blue
	case "scanning-enumeration":
		bgColor = lipgloss.Color("214") // Orange
	case "vulnerability-analysis":
		bgColor = lipgloss.Color("208") // Dark orange
	case "exploitation":
		bgColor = lipgloss.Color("196") // Red
	case "post-exploitation":
		bgColor = lipgloss.Color("129") // Deep Purple
	case "reporting":
		bgColor = lipgloss.Color("46") // Green
	}

	if m.finished {
		bgColor = lipgloss.Color("22") // Dark green when finished
	}

	phases := []string{"pre-engagement", "reconnaissance", "scanning-enumeration", "vulnerability-analysis", "exploitation", "post-exploitation", "reporting"}
	shortPhases := []string{"Pre", "Recon", "Scan", "Vuln", "Exploit", "Post", "Report"}
	
	var breadcrumbs []string
	for i, p := range phases {
		if p == m.currentPhase {
			breadcrumbs = append(breadcrumbs, lipgloss.NewStyle().Background(bgColor).Foreground(lipgloss.Color("255")).Bold(true).Render(shortPhases[i]))
		} else {
			breadcrumbs = append(breadcrumbs, lipgloss.NewStyle().Background(bgColor).Foreground(lipgloss.Color("250")).Render(shortPhases[i]))
		}
	}
	separator := lipgloss.NewStyle().Background(bgColor).Render("   ")
	bcView := strings.Join(breadcrumbs, separator)

	footerText := lipgloss.NewStyle().Background(bgColor).Render("  ") + bcView

	barStyle := lipgloss.NewStyle().
		Background(bgColor).
		Width(m.width)

	return barStyle.Render(footerText)
}

func (m Model) View() string {
	if !m.ready {
		return "\n  Initializing..."
	}

	logsContent := m.logsViewport.View()
	


	if m.finished && m.finalReport != "" {
		logsContent = m.logsViewport.View() + "\n\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Render("--- Final Report ---\n"+m.finalReport)
	}

	activeColor := lipgloss.Color("205")
	inactiveColor := lipgloss.Color("62")

	logsBorderColor := inactiveColor
	kgBorderColor := inactiveColor
	if m.activePane == 0 {
		logsBorderColor = activeColor
	} else {
		kgBorderColor = activeColor
	}

	// Logs Viewport
	logsScrollStr := fmt.Sprintf(" %3.0f%% ", m.logsViewport.ScrollPercent()*100)
	if m.logsViewport.TotalLineCount() <= m.logsViewport.Height {
		logsScrollStr = " 100% "
	}
	logsStatus := lipgloss.NewStyle().Width(m.logsViewport.Width).Align(lipgloss.Right).Foreground(lipgloss.Color("240")).Render(logsScrollStr)
	paddedLogs := lipgloss.NewStyle().Height(m.logsViewport.Height).Render(logsContent)
	logsContentWithStatus := lipgloss.JoinVertical(lipgloss.Left, paddedLogs, logsStatus)

	// KG Tree Viewport
	kgTreeScrollStr := fmt.Sprintf(" %3.0f%% ", m.kgTreeViewport.ScrollPercent()*100)
	if m.kgTreeViewport.TotalLineCount() <= m.kgTreeViewport.Height {
		kgTreeScrollStr = " 100% "
	}
	kgTreeStatus := lipgloss.NewStyle().Width(m.kgTreeViewport.Width).Align(lipgloss.Right).Foreground(lipgloss.Color("240")).Render(kgTreeScrollStr)
	paddedKgTree := lipgloss.NewStyle().Height(m.kgTreeViewport.Height).Render(m.kgTreeViewport.View())
	kgTreeWithStatus := lipgloss.JoinVertical(lipgloss.Left, paddedKgTree, kgTreeStatus)

	// KG Detail Viewport
	kgDetailScrollStr := fmt.Sprintf(" %3.0f%% ", m.kgDetailViewport.ScrollPercent()*100)
	if m.kgDetailViewport.TotalLineCount() <= m.kgDetailViewport.Height {
		kgDetailScrollStr = " 100% "
	}
	kgDetailStatus := lipgloss.NewStyle().Width(m.kgDetailViewport.Width).Align(lipgloss.Right).Foreground(lipgloss.Color("240")).Render(kgDetailScrollStr)
	paddedKgDetail := lipgloss.NewStyle().Height(m.kgDetailViewport.Height).Render(m.kgDetailViewport.View())
	kgDetailWithStatus := lipgloss.JoinVertical(lipgloss.Left, paddedKgDetail, kgDetailStatus)

	// Combine KG Top and Bottom
	divider := lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Render(strings.Repeat("─", m.kgTreeViewport.Width))
	kgCombined := lipgloss.JoinVertical(lipgloss.Left, kgTreeWithStatus, divider, kgDetailWithStatus)

	logsStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(logsBorderColor).
		Padding(0, 1)

	kgStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(kgBorderColor).
		Padding(0, 1)

	split := lipgloss.JoinHorizontal(lipgloss.Top, logsStyle.Render(logsContentWithStatus), kgStyle.Render(kgCombined))
	return lipgloss.JoinVertical(lipgloss.Left, m.headerView(), split, m.footerView())
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
