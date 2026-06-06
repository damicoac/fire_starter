package tui

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
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

type PromptMsg struct {
	Choices    []string
	ResponseCh chan int
}

type Model struct {
	logsViewport viewport.Model
	kgViewport   viewport.Model
	spinner      spinner.Model
	logs         []string
	kgStateText  string
	currentPhase string
	ready        bool
	finished     bool
	finalReport  string
	width        int
	height       int
	prompting    bool
	choices      []string
	cursor       int
	responseCh   chan int
	activePane   int // 0 = logs, 1 = sidebar
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

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.prompting {
				// Send a sentinel value to unblock the agent if it's waiting
				m.responseCh <- -1
			}
			return m, tea.Quit
		case "tab":
			m.activePane = (m.activePane + 1) % 2
		case "up", "k":
			if m.prompting && m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.prompting && m.cursor < len(m.choices)-1 {
				m.cursor++
			}
		case "enter":
			if m.prompting {
				m.prompting = false
				m.responseCh <- m.cursor
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		headerHeight := lipgloss.Height(m.headerView())
		footerHeight := lipgloss.Height(m.footerView())
		verticalMarginHeight := headerHeight + footerHeight + 3 // 3 for top/bottom borders + status line

		logsWidth := ((msg.Width * 2) / 3) - 4
		kgWidth := msg.Width - ((msg.Width * 2) / 3) - 4

		if logsWidth < 0 { logsWidth = 0 }
		if kgWidth < 0 { kgWidth = 0 }

		if !m.ready {
			m.logsViewport = viewport.New(logsWidth, max(0, msg.Height-verticalMarginHeight))
			m.kgViewport = viewport.New(kgWidth, max(0, msg.Height-verticalMarginHeight))
			m.ready = true
		} else {
			m.logsViewport.Width = logsWidth
			m.logsViewport.Height = max(0, msg.Height-verticalMarginHeight)
			m.kgViewport.Width = kgWidth
			m.kgViewport.Height = max(0, msg.Height-verticalMarginHeight)
		}

		m.logsViewport.SetContent(wordwrap.String(strings.Join(m.logs, "\n"), m.logsViewport.Width))
		m.kgViewport.SetContent(wordwrap.String(m.kgStateText, m.kgViewport.Width))

	case LogMsg:
		m.logs = append(m.logs, msg.Text)
		if m.ready {
			m.logsViewport.SetContent(wordwrap.String(strings.Join(m.logs, "\n"), m.logsViewport.Width))
			m.logsViewport.GotoBottom()
		}

	case KGUpdateMsg:
		m.kgStateText, m.currentPhase = formatKG(msg.Data)
		if m.ready {
			m.kgViewport.SetContent(wordwrap.String(m.kgStateText, m.kgViewport.Width))
		}

	case AgentFinishedMsg:
		m.finished = true
		m.finalReport = msg.Report

	case PromptMsg:
		m.prompting = true
		m.choices = msg.Choices
		m.cursor = 0
		m.responseCh = msg.ResponseCh

	case spinner.TickMsg:
		if !m.finished {
			var spinnerCmd tea.Cmd
			m.spinner, spinnerCmd = m.spinner.Update(msg)
			cmds = append(cmds, spinnerCmd)
		}
	}

	if m.ready {
		isKey := false
		if _, ok := msg.(tea.KeyMsg); ok {
			isKey = true
		}

		if !isKey || (!m.prompting && m.activePane == 0) {
			m.logsViewport, cmd = m.logsViewport.Update(msg)
			cmds = append(cmds, cmd)
		}
		
		if !isKey || (!m.prompting && m.activePane == 1) {
			m.kgViewport, cmd = m.kgViewport.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

func formatKG(data []byte) (string, string) {
	var kg struct {
		DiscoveredIPs []struct {
			Value string
			Score int
		} `json:"discovered_ips"`
		DiscoveredURLs []struct {
			Value string
			Score int
		} `json:"discovered_urls"`
		OpenPorts        map[string][]int `json:"open_ports"`
		HarvestedTokens  []string         `json:"harvested_tokens"`
		Vulnerabilities  []string         `json:"vulnerabilities"`
		KnownCredentials []struct {
			Username string
			Password string
		} `json:"known_credentials"`
		CurrentPhase string `json:"current_phase"`
	}

	if err := json.Unmarshal(data, &kg); err != nil {
		return "Awaiting Knowledge Graph...", ""
	}

	var sb strings.Builder
	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render("Phase: ") + kg.CurrentPhase + "\n\n")

	headerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	cardStyle := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		Padding(0, 1).
		MarginBottom(1)

	// IPs
	if len(kg.DiscoveredIPs) > 0 {
		t := table.New().
			Border(lipgloss.HiddenBorder()).
			Headers("IP ADDRESS", "SCORE").
			StyleFunc(func(row, col int) lipgloss.Style {
				if row == 0 {
					return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Bold(true)
				}
				return lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
			})
		for _, ip := range kg.DiscoveredIPs {
			t.Row(ip.Value, fmt.Sprintf("%d", ip.Score))
		}
		card := lipgloss.JoinVertical(lipgloss.Left, headerStyle.Render("Discovered IPs"), t.Render())
		sb.WriteString(cardStyle.Render(card) + "\n")
	}

	// URLs
	if len(kg.DiscoveredURLs) > 0 {
		t := table.New().
			Border(lipgloss.HiddenBorder()).
			Headers("URL", "SCORE").
			StyleFunc(func(row, col int) lipgloss.Style {
				if row == 0 {
					return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Bold(true)
				}
				return lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
			})
		for _, url := range kg.DiscoveredURLs {
			t.Row(url.Value, fmt.Sprintf("%d", url.Score))
		}
		card := lipgloss.JoinVertical(lipgloss.Left, headerStyle.Render("Discovered URLs"), t.Render())
		sb.WriteString(cardStyle.Render(card) + "\n")
	}

	// Ports
	if len(kg.OpenPorts) > 0 {
		t := table.New().
			Border(lipgloss.HiddenBorder()).
			Headers("TARGET", "OPEN PORTS").
			StyleFunc(func(row, col int) lipgloss.Style {
				if row == 0 {
					return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Bold(true)
				}
				return lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
			})
		for ip, ports := range kg.OpenPorts {
			t.Row(ip, fmt.Sprintf("%v", ports))
		}
		card := lipgloss.JoinVertical(lipgloss.Left, headerStyle.Render("Open Ports"), t.Render())
		sb.WriteString(cardStyle.Render(card) + "\n")
	}

	// Vulns
	if len(kg.Vulnerabilities) > 0 {
		var content string
		for _, v := range kg.Vulnerabilities {
			content += " • " + v + "\n"
		}
		card := lipgloss.JoinVertical(lipgloss.Left, headerStyle.Render("Vulnerabilities"), lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render(content))
		sb.WriteString(cardStyle.Render(card) + "\n")
	}

	// Tokens
	if len(kg.HarvestedTokens) > 0 {
		var content string
		for _, t := range kg.HarvestedTokens {
			content += " 🔑 " + t + "\n"
		}
		card := lipgloss.JoinVertical(lipgloss.Left, headerStyle.Render("Harvested Tokens"), lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(content))
		sb.WriteString(cardStyle.Render(card) + "\n")
	}
	
	// Credentials
	if len(kg.KnownCredentials) > 0 {
		t := table.New().
			Border(lipgloss.HiddenBorder()).
			Headers("USERNAME", "PASSWORD").
			StyleFunc(func(row, col int) lipgloss.Style {
				if row == 0 {
					return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Bold(true)
				}
				return lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
			})
		for _, cred := range kg.KnownCredentials {
			t.Row(cred.Username, cred.Password)
		}
		card := lipgloss.JoinVertical(lipgloss.Left, headerStyle.Render("Known Credentials"), t.Render())
		sb.WriteString(cardStyle.Render(card) + "\n")
	}

	return sb.String(), kg.CurrentPhase
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
	
	if m.prompting {
		var b strings.Builder
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render("Select next action:"))
		b.WriteString("\n\n")
		for i, choice := range m.choices {
			cursor := "  " // no cursor
			style := lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
			if m.cursor == i {
				cursor = "> " // cursor!
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
			}
			b.WriteString(cursor + style.Render(choice) + "\n")
		}
		
		promptBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("205")).
			Padding(1, 2).
			Render(b.String())

		// Replace logs content with prompt box, vertically centered if possible
		logsContent = lipgloss.Place(
			m.logsViewport.Width,
			m.logsViewport.Height,
			lipgloss.Center,
			lipgloss.Center,
			promptBox,
		)
	}

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

	// Generate Scroll Percentages
	logsScrollStr := fmt.Sprintf(" %3.0f%% ", m.logsViewport.ScrollPercent()*100)
	if m.logsViewport.TotalLineCount() <= m.logsViewport.Height {
		logsScrollStr = " 100% "
	}
	logsStatus := lipgloss.NewStyle().Width(m.logsViewport.Width).Align(lipgloss.Right).Foreground(lipgloss.Color("240")).Render(logsScrollStr)

	kgScrollStr := fmt.Sprintf(" %3.0f%% ", m.kgViewport.ScrollPercent()*100)
	if m.kgViewport.TotalLineCount() <= m.kgViewport.Height {
		kgScrollStr = " 100% "
	}
	kgStatus := lipgloss.NewStyle().Width(m.kgViewport.Width).Align(lipgloss.Right).Foreground(lipgloss.Color("240")).Render(kgScrollStr)

	// Ensure content is at least the height of the viewport so the status line is pushed to the bottom
	paddedLogs := lipgloss.NewStyle().Height(m.logsViewport.Height).Render(logsContent)
	logsContentWithStatus := lipgloss.JoinVertical(lipgloss.Left, paddedLogs, logsStatus)

	paddedKg := lipgloss.NewStyle().Height(m.kgViewport.Height).Render(m.kgViewport.View())
	kgContentWithStatus := lipgloss.JoinVertical(lipgloss.Left, paddedKg, kgStatus)

	logsStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(logsBorderColor).
		Padding(0, 1)

	kgStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(kgBorderColor).
		Padding(0, 1)

	split := lipgloss.JoinHorizontal(lipgloss.Top, logsStyle.Render(logsContentWithStatus), kgStyle.Render(kgContentWithStatus))
	return lipgloss.JoinVertical(lipgloss.Left, m.headerView(), split, m.footerView())
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
