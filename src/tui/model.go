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
}

type Model struct {
	logsViewport    viewport.Model
	kgViewport      viewport.Model
	spinner         spinner.Model
	logs            []string
	kgTargets       []KGTarget
	dashboardCursor int
	inspectorMode   bool
	currentPhase    string
	ready           bool
	finished        bool
	finalReport     string
	width           int
	height          int

	activePane      int // 0 = logs, 1 = sidebar
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

func (m *Model) updateKGViewport() {
	if !m.ready {
		return
	}

	var contentBuilder strings.Builder

	if m.inspectorMode && m.dashboardCursor < len(m.kgTargets) {
		t := m.kgTargets[m.dashboardCursor]
		header := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true).Render("⬅ Press Esc to return")
		contentBuilder.WriteString(header + "\n\n")

		titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
		valueStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
		
		icon := "🌐"
		if t.Type == "ip" {
			icon = "🖥️ "
		}
		
		contentBuilder.WriteString(titleStyle.Render(fmt.Sprintf("%s Target: ", icon)) + valueStyle.Render(t.Value) + "\n")
		contentBuilder.WriteString(titleStyle.Render("Score: ") + valueStyle.Render(fmt.Sprintf("%d", t.Score)) + "\n")
		contentBuilder.WriteString(titleStyle.Render("Type: ") + valueStyle.Render(t.Type) + "\n\n")

		if len(t.OpenPorts) > 0 {
			contentBuilder.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("99")).Bold(true).Render("🔌 Open Ports") + "\n")
			for _, p := range t.OpenPorts {
				contentBuilder.WriteString(fmt.Sprintf("  - %d\n", p))
			}
			contentBuilder.WriteString("\n")
		}

		if len(t.Vulnerabilities) > 0 {
			contentBuilder.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true).Render("⚠️  Vulnerabilities") + "\n")
			for _, v := range t.Vulnerabilities {
				contentBuilder.WriteString(fmt.Sprintf("  - %s\n", v))
			}
			contentBuilder.WriteString("\n")
		}

		if len(t.Tokens) > 0 {
			contentBuilder.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true).Render("🔑 Tokens / Cookies") + "\n")
			for _, token := range t.Tokens {
				contentBuilder.WriteString(fmt.Sprintf("  - %s\n", token))
			}
			contentBuilder.WriteString("\n")
		}

		if len(t.Credentials) > 0 {
			contentBuilder.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Bold(true).Render("👤 Credentials") + "\n")
			for _, cred := range t.Credentials {
				contentBuilder.WriteString(fmt.Sprintf("  - %s:%s\n", cred.Username, cred.Password))
			}
			contentBuilder.WriteString("\n")
		}

	} else {
		// Dashboard Mode
		totalPorts, totalVulns, totalTokens, totalCreds := 0, 0, 0, 0
		for _, t := range m.kgTargets {
			totalPorts += len(t.OpenPorts)
			totalVulns += len(t.Vulnerabilities)
			totalTokens += len(t.Tokens)
			totalCreds += len(t.Credentials)
		}
		
		metricStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
		valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
		
		metrics := fmt.Sprintf("%s %s | %s %s | %s %s | %s %s",
			metricStyle.Render("Targets:"), valStyle.Render(fmt.Sprintf("%d", len(m.kgTargets))),
			metricStyle.Render("Vulns:"), valStyle.Render(fmt.Sprintf("%d", totalVulns)),
			metricStyle.Render("Creds:"), valStyle.Render(fmt.Sprintf("%d", totalCreds)),
			metricStyle.Render("Ports:"), valStyle.Render(fmt.Sprintf("%d", totalPorts)))
		
		contentBuilder.WriteString(metrics + "\n" + strings.Repeat("─", m.kgViewport.Width) + "\n\n")

		if len(m.kgTargets) == 0 {
			contentBuilder.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("  No targets discovered yet.\n"))
		}

		for i, t := range m.kgTargets {
			cursor := "  "
			if i == m.dashboardCursor {
				cursor = "> "
			}
			
			icon := "🌐"
			color := lipgloss.Color("33") // Blue
			if t.Type == "ip" {
				icon = "🖥️ "
				color = lipgloss.Color("46") // Green
			}

			style := lipgloss.NewStyle().Foreground(color)
			if i == m.dashboardCursor && m.activePane == 1 {
				style = style.Bold(true).Background(lipgloss.Color("236"))
			}

			bgStyle := lipgloss.NewStyle()
			if i == m.dashboardCursor && m.activePane == 1 {
				bgStyle = bgStyle.Background(lipgloss.Color("236"))
			}

			baseStyle := bgStyle.Copy().Foreground(lipgloss.Color("245"))

			portStr := fmt.Sprintf("%d", len(t.OpenPorts))
			if len(t.OpenPorts) > 0 {
				portStr = bgStyle.Copy().Foreground(lipgloss.Color("99")).Render(portStr)
			} else {
				portStr = baseStyle.Render(portStr)
			}

			vulnStr := fmt.Sprintf("%d", len(t.Vulnerabilities))
			if len(t.Vulnerabilities) > 0 {
				vulnStr = bgStyle.Copy().Foreground(lipgloss.Color("196")).Render(vulnStr)
			} else {
				vulnStr = baseStyle.Render(vulnStr)
			}

			credStr := fmt.Sprintf("%d", len(t.Credentials))
			if len(t.Credentials) > 0 {
				credStr = bgStyle.Copy().Foreground(lipgloss.Color("220")).Render(credStr)
			} else {
				credStr = baseStyle.Render(credStr)
			}

			summary := baseStyle.Render("    ↳ Ports: ") + portStr + baseStyle.Render(" | Vulns: ") + vulnStr + baseStyle.Render(" | Creds: ") + credStr
			
			cursorSpacing := "  "
			line1 := cursor + style.Render(fmt.Sprintf("%s %s (Score: %d)", icon, t.Value, t.Score))
			line2 := cursorSpacing + summary
			contentBuilder.WriteString(line1 + "\n" + line2 + "\n")
		}
	}

	m.kgViewport.SetContent(wordwrap.String(contentBuilder.String(), m.kgViewport.Width))
	
	// Handle scroll sync if needed
	if !m.inspectorMode && len(m.kgTargets) > 0 {
		cursorYTop := (m.dashboardCursor * 2) + 3 // header offset
		cursorYBottom := cursorYTop + 1
		if cursorYTop < m.kgViewport.YOffset {
			m.kgViewport.SetYOffset(cursorYTop)
		} else if cursorYBottom >= m.kgViewport.YOffset+m.kgViewport.Height {
			m.kgViewport.SetYOffset(cursorYBottom - m.kgViewport.Height + 1)
		}
	}
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
			m.updateKGViewport()
		case "up", "k":
			if m.activePane == 1 {
				if m.inspectorMode {
					m.kgViewport.LineUp(1)
				} else {
					if m.dashboardCursor > 0 {
						m.dashboardCursor--
						m.updateKGViewport()
					}
				}
			} else if m.activePane == 0 {
				m.logsViewport.LineUp(1)
			}
		case "down", "j":
			if m.activePane == 1 {
				if m.inspectorMode {
					m.kgViewport.LineDown(1)
				} else {
					if m.dashboardCursor < len(m.kgTargets)-1 {
						m.dashboardCursor++
						m.updateKGViewport()
					}
				}
			} else if m.activePane == 0 {
				m.logsViewport.LineDown(1)
			}
		case "enter", " ":
			if m.activePane == 1 && !m.inspectorMode {
				if len(m.kgTargets) > 0 {
					m.inspectorMode = true
					m.kgViewport.SetYOffset(0) // reset scroll
					m.updateKGViewport()
				}
			}
		case "esc", "backspace":
			if m.activePane == 1 && m.inspectorMode {
				m.inspectorMode = false
				m.updateKGViewport()
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		headerHeight := lipgloss.Height(m.headerView())
		phaseHeight := lipgloss.Height(m.phaseView())
		verticalMarginHeight := headerHeight + phaseHeight + 4

		logsWidth := ((msg.Width * 2) / 3) - 4
		kgWidth := msg.Width - ((msg.Width * 2) / 3) - 4

		if logsWidth < 0 { logsWidth = 0 }
		if kgWidth < 0 { kgWidth = 0 }

		kgHeight := max(0, msg.Height-verticalMarginHeight)

		if !m.ready {
			m.logsViewport = viewport.New(logsWidth, max(0, msg.Height-verticalMarginHeight))
			m.kgViewport = viewport.New(kgWidth, kgHeight - 2)
			m.ready = true
		} else {
			m.logsViewport.Width = logsWidth
			m.logsViewport.Height = max(0, msg.Height-verticalMarginHeight)
			m.kgViewport.Width = kgWidth
			m.kgViewport.Height = max(0, kgHeight - 2)
		}

		m.logsViewport.SetContent(wordwrap.String(strings.Join(m.logs, "\n"), m.logsViewport.Width))
		m.updateKGViewport()

	case LogMsg:
		m.logs = append(m.logs, msg.Text)
		if m.ready {
			m.logsViewport.SetContent(wordwrap.String(strings.Join(m.logs, "\n"), m.logsViewport.Width))
			m.logsViewport.GotoBottom()
		}

	case KGUpdateMsg:
		m.kgTargets, m.currentPhase = parseKG(msg.Data, m.kgTargets)
		if m.dashboardCursor >= len(m.kgTargets) {
			m.dashboardCursor = max(0, len(m.kgTargets)-1)
		}
		m.updateKGViewport()

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
					m.kgViewport, cmd = m.kgViewport.Update(msg)
					cmds = append(cmds, cmd)
				}
			}
		default:
			m.logsViewport, cmd = m.logsViewport.Update(msg)
			cmds = append(cmds, cmd)
			m.kgViewport, cmd = m.kgViewport.Update(msg)
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

func (m Model) phaseView() string {
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
	logsTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).Render(" Execution Log")
	logsScrollStr := fmt.Sprintf(" %3.0f%% ", m.logsViewport.ScrollPercent()*100)
	if m.logsViewport.TotalLineCount() <= m.logsViewport.Height {
		logsScrollStr = " 100% "
	}
	logsStatus := lipgloss.NewStyle().Width(m.logsViewport.Width).Align(lipgloss.Right).Foreground(lipgloss.Color("240")).Render(logsScrollStr)
	paddedLogs := lipgloss.NewStyle().Height(m.logsViewport.Height).Render(logsContent)
	logsContentWithStatus := lipgloss.JoinVertical(lipgloss.Left, logsTitle, paddedLogs, logsStatus)

	// KG Viewport
	titleStr := " Knowledge Graph Dashboard"
	if m.inspectorMode {
		titleStr = " Target Inspector"
	}
	kgTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).Render(titleStr)
	
	var kgScrollStr string
	if m.inspectorMode {
		kgScrollStr = fmt.Sprintf(" %3.0f%% ", m.kgViewport.ScrollPercent()*100)
		if m.kgViewport.TotalLineCount() <= m.kgViewport.Height {
			kgScrollStr = " 100% "
		}
	} else {
		if len(m.kgTargets) <= 1 {
			kgScrollStr = " 100% "
		} else {
			percent := float64(m.dashboardCursor) / float64(len(m.kgTargets)-1) * 100
			kgScrollStr = fmt.Sprintf(" %3.0f%% ", percent)
		}
	}
	kgStatus := lipgloss.NewStyle().Width(m.kgViewport.Width).Align(lipgloss.Right).Foreground(lipgloss.Color("240")).Render(kgScrollStr)
	
	paddedKg := lipgloss.NewStyle().Height(m.kgViewport.Height).Render(m.kgViewport.View())
	
	kgCombined := lipgloss.JoinVertical(lipgloss.Left, kgTitle, paddedKg, kgStatus)

	logsStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(logsBorderColor).
		Padding(0, 1)

	kgStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(kgBorderColor).
		Padding(0, 1)

	split := lipgloss.JoinHorizontal(lipgloss.Top, logsStyle.Render(logsContentWithStatus), kgStyle.Render(kgCombined))
	return lipgloss.JoinVertical(lipgloss.Left, m.headerView(), m.phaseView(), split)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
