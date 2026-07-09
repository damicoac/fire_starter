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

	phaseColors = map[string]lipgloss.Color{
		"pre-engagement":         lipgloss.Color("245"),
		"reconnaissance":         lipgloss.Color("33"),
		"scanning-enumeration":   lipgloss.Color("214"),
		"vulnerability-analysis": lipgloss.Color("196"),
		"exploitation":           lipgloss.Color("129"),
		"post-exploitation":      lipgloss.Color("201"),
		"reporting":              lipgloss.Color("46"),
	}

	cardBaseStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("238")).
			Padding(0, 1)

	cardSelectedStyle = cardBaseStyle.
				BorderForeground(lipgloss.Color("205")).
				Background(lipgloss.Color("236"))

	cardTitleStyle    = lipgloss.NewStyle().Bold(true)
	sectionTitleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	mutedStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	footerStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("248")).Padding(0, 1)
	statusBarStyle    = lipgloss.NewStyle().
				Foreground(lipgloss.Color("255")).
				Background(lipgloss.Color("62")).
				Padding(0, 1)
	activeFilterStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("205")).Bold(true).Padding(0, 1)
	inactiveFilterStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("248")).Background(lipgloss.Color("237")).Padding(0, 1)
)

type LogMsg struct {
	Entry LogEntry
}

type AgentFinishedMsg struct {
	Report string
}

type KGUpdateMsg struct {
	Data []byte
}

type KGVulnerability struct {
	Finding string
	Status  string
}

type KGTarget struct {
	Value                string
	Type                 string
	Score                int
	CurrentPhase         string
	OpenPorts            []int
	Tokens               []string
	Vulnerabilities      []string
	VulnerabilityDetails []KGVulnerability
	Credentials          []struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
}

type Model struct {
	logsViewport       viewport.Model
	kgViewport         viewport.Model
	spinner            spinner.Model
	allLogs            []LogEntry
	visibleLogs        []string
	kgTargets          []KGTarget
	dashboardCursor    int
	inspectorMode      bool
	ready              bool
	finished           bool
	finalReport        string
	width              int
	height             int
	activePane         int
	activeLogFilter    LogCategory
	collapsedSummaries bool
}

func InitialModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return Model{
		spinner:            s,
		allLogs:            make([]LogEntry, 0),
		visibleLogs:        make([]string, 0),
		activeLogFilter:    LogCategoryGeneral,
		collapsedSummaries: true,
	}
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

func parseKG(data []byte, existingTargets []KGTarget) []KGTarget {
	var kg struct {
		Targets map[string]struct {
			Value           string   `json:"value"`
			Type            string   `json:"type"`
			Score           int      `json:"score"`
			CurrentPhase    string   `json:"current_phase"`
			OpenPorts       []int    `json:"open_ports"`
			Tokens          []string `json:"tokens"`
			Vulnerabilities []string `json:"vulnerabilities"`
			Credentials     []struct {
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"credentials"`
		} `json:"targets"`
		VulnerabilityRecords []struct {
			TargetDomain string `json:"TargetDomain"`
			Finding      string `json:"Finding"`
			Status       string `json:"Status"`
		} `json:"vulnerability_records"`
	}

	if err := json.Unmarshal(data, &kg); err != nil {
		return existingTargets
	}

	vulnerabilityDetailsByTarget := make(map[string][]KGVulnerability)
	for _, v := range kg.VulnerabilityRecords {
		if strings.TrimSpace(v.Finding) == "" || strings.TrimSpace(v.Status) == "" {
			continue
		}
		vulnerabilityDetailsByTarget[v.TargetDomain] = append(vulnerabilityDetailsByTarget[v.TargetDomain], KGVulnerability{Finding: v.Finding, Status: v.Status})
	}

	var newTargets []KGTarget
	for _, t := range kg.Targets {
		newTargets = append(newTargets, KGTarget{
			Value:                t.Value,
			Type:                 t.Type,
			Score:                t.Score,
			CurrentPhase:         t.CurrentPhase,
			OpenPorts:            t.OpenPorts,
			Tokens:               t.Tokens,
			Vulnerabilities:      t.Vulnerabilities,
			VulnerabilityDetails: vulnerabilityDetailsByTarget[t.Value],
			Credentials:          t.Credentials,
		})
	}

	sort.Slice(newTargets, func(i, j int) bool {
		if newTargets[i].Score == newTargets[j].Score {
			return newTargets[i].Value < newTargets[j].Value
		}
		return newTargets[i].Score > newTargets[j].Score
	})

	return newTargets
}

func (m *Model) rebuildLogsViewport(stickBottom bool) {
	if !m.ready {
		return
	}
	m.visibleLogs = filterLogs(m.allLogs, m.activeLogFilter, m.collapsedSummaries)
	m.logsViewport.SetContent(wordwrap.String(strings.Join(m.visibleLogs, "\n"), m.logsViewport.Width))
	if stickBottom {
		m.logsViewport.GotoBottom()
	}
}

func filterLogs(entries []LogEntry, filter LogCategory, collapsed bool) []string {
	filtered := make([]string, 0, len(entries))
	for _, entry := range entries {
		if filter != LogCategoryGeneral && entry.Category != filter {
			continue
		}
		text := entry.Text
		if collapsed && entry.Category == LogCategoryTools && strings.Contains(text, "TOOL_EXECUTION_SUMMARY") {
			lines := strings.Split(text, "\n")
			if len(lines) > 1 {
				text = lines[0]
			}
		}
		filtered = append(filtered, text)
	}
	if len(filtered) == 0 {
		filtered = append(filtered, mutedStyle.Render("No log entries for the current filter yet."))
	}
	return filtered
}

func phaseShortName(phase string) string {
	switch phase {
	case "pre-engagement":
		return "Pre"
	case "reconnaissance":
		return "Recon"
	case "scanning-enumeration":
		return "Scan"
	case "vulnerability-analysis":
		return "Vuln"
	case "exploitation":
		return "Exploit"
	case "post-exploitation":
		return "Post"
	case "reporting":
		return "Report"
	default:
		return phase
	}
}

func phaseBadge(phase string) string {
	color := lipgloss.Color("214")
	if c, ok := phaseColors[phase]; ok {
		color = c
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Background(color).Bold(true).Padding(0, 1).Render(phaseShortName(phase))
}

func countBadge(label string, count int, color lipgloss.Color) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Background(color).Padding(0, 1).Render(fmt.Sprintf("%s %d", label, count))
}

func joinNonEmpty(parts []string, sep string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			filtered = append(filtered, part)
		}
	}
	return strings.Join(filtered, sep)
}

func phaseBreakdown(targets []KGTarget) string {
	phases := []string{"pre-engagement", "reconnaissance", "scanning-enumeration", "vulnerability-analysis", "exploitation", "post-exploitation", "reporting"}
	parts := make([]string, 0, len(phases))
	counts := make(map[string]int)
	for _, target := range targets {
		counts[target.CurrentPhase]++
	}
	for _, phase := range phases {
		if counts[phase] == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %d", phaseBadge(phase), counts[phase]))
	}
	if len(parts) == 0 {
		return mutedStyle.Render("No active phases yet")
	}
	return strings.Join(parts, " ")
}

func (m *Model) updateKGViewport() {
	if !m.ready {
		return
	}

	var contentBuilder strings.Builder

	if m.inspectorMode && m.dashboardCursor < len(m.kgTargets) {
		t := m.kgTargets[m.dashboardCursor]
		header := sectionTitleStyle.Render("Press Esc to return")
		contentBuilder.WriteString(header + "\n\n")

		titleRow := lipgloss.JoinHorizontal(lipgloss.Left, cardTitleStyle.Foreground(lipgloss.Color("205")).Render(t.Value), " ", phaseBadge(t.CurrentPhase))
		metaRow := mutedStyle.Render(fmt.Sprintf("Type: %s   Score: %d", t.Type, t.Score))
		contentBuilder.WriteString(titleRow + "\n" + metaRow + "\n\n")

		if len(t.OpenPorts) > 0 {
			contentBuilder.WriteString(sectionTitleStyle.Foreground(lipgloss.Color("99")).Render("Open Ports") + "\n")
			for _, p := range t.OpenPorts {
				contentBuilder.WriteString(fmt.Sprintf("  • %d\n", p))
			}
			contentBuilder.WriteString("\n")
		}

		if len(t.VulnerabilityDetails) > 0 {
			contentBuilder.WriteString(sectionTitleStyle.Foreground(lipgloss.Color("196")).Render("Vulnerabilities") + "\n")
			for _, v := range t.VulnerabilityDetails {
				contentBuilder.WriteString(fmt.Sprintf("  • [%s] %s\n", v.Status, v.Finding))
			}
			contentBuilder.WriteString("\n")
		} else if len(t.Vulnerabilities) > 0 {
			contentBuilder.WriteString(sectionTitleStyle.Foreground(lipgloss.Color("196")).Render("Vulnerabilities") + "\n")
			for _, v := range t.Vulnerabilities {
				contentBuilder.WriteString(fmt.Sprintf("  • [candidate] %s\n", v))
			}
			contentBuilder.WriteString("\n")
		}

		if len(t.Tokens) > 0 {
			contentBuilder.WriteString(sectionTitleStyle.Foreground(lipgloss.Color("220")).Render("Tokens / Cookies") + "\n")
			for _, token := range t.Tokens {
				contentBuilder.WriteString(fmt.Sprintf("  • %s\n", token))
			}
			contentBuilder.WriteString("\n")
		}

		if len(t.Credentials) > 0 {
			contentBuilder.WriteString(sectionTitleStyle.Foreground(lipgloss.Color("250")).Render("Credentials") + "\n")
			for _, cred := range t.Credentials {
				contentBuilder.WriteString(fmt.Sprintf("  • %s:%s\n", cred.Username, cred.Password))
			}
			contentBuilder.WriteString("\n")
		}
	} else {
		totalPorts, totalVulns, totalTokens, totalCreds := 0, 0, 0, 0
		for _, t := range m.kgTargets {
			totalPorts += len(t.OpenPorts)
			totalVulns += len(t.Vulnerabilities)
			totalTokens += len(t.Tokens)
			totalCreds += len(t.Credentials)
		}

		summaryTop := joinNonEmpty([]string{
			countBadge("Targets", len(m.kgTargets), lipgloss.Color("62")),
			countBadge("Vulns", totalVulns, lipgloss.Color("196")),
			countBadge("Creds", totalCreds, lipgloss.Color("220")),
			countBadge("Tokens", totalTokens, lipgloss.Color("99")),
			countBadge("Ports", totalPorts, lipgloss.Color("33")),
		}, " ")
		contentBuilder.WriteString(summaryTop + "\n")
		contentBuilder.WriteString(phaseBreakdown(m.kgTargets) + "\n\n")

		if len(m.kgTargets) == 0 {
			contentBuilder.WriteString(mutedStyle.Render("No targets discovered yet."))
		}

		for i, t := range m.kgTargets {
			cardStyle := cardBaseStyle
			if i == m.dashboardCursor && m.activePane == 1 {
				cardStyle = cardSelectedStyle
			}

			icon := "Host"
			nameColor := lipgloss.Color("33")
			if t.Type == "ip" {
				icon = "IP"
				nameColor = lipgloss.Color("46")
			}

			headerLeft := lipgloss.NewStyle().Foreground(nameColor).Bold(true).Render(icon + "  " + t.Value)
			headerRight := mutedStyle.Render(fmt.Sprintf("score %d", t.Score))
			headerWidth := max(0, m.kgViewport.Width-8-lipgloss.Width(headerRight))
			header := lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Width(headerWidth).Render(headerLeft), headerRight)

			badges := joinNonEmpty([]string{
				phaseBadge(t.CurrentPhase),
				countBadge("Ports", len(t.OpenPorts), lipgloss.Color("33")),
				countBadge("Vulns", len(t.Vulnerabilities), lipgloss.Color("196")),
				countBadge("Creds", len(t.Credentials), lipgloss.Color("220")),
				countBadge("Tokens", len(t.Tokens), lipgloss.Color("99")),
			}, " ")

			previewItems := []string{}
			if len(t.VulnerabilityDetails) > 0 {
				previewItems = append(previewItems, fmt.Sprintf("[%s] %s", t.VulnerabilityDetails[0].Status, t.VulnerabilityDetails[0].Finding))
			} else if len(t.Vulnerabilities) > 0 {
				previewItems = append(previewItems, "[candidate] "+t.Vulnerabilities[0])
			}
			if len(t.Credentials) > 0 {
				previewItems = append(previewItems, fmt.Sprintf("%s:%s", t.Credentials[0].Username, t.Credentials[0].Password))
			}
			if len(t.Tokens) > 0 {
				previewItems = append(previewItems, t.Tokens[0])
			}
			preview := mutedStyle.Render("Select to inspect details")
			if len(previewItems) > 0 {
				preview = mutedStyle.Render(strings.Join(previewItems, "  •  "))
			}

			card := lipgloss.JoinVertical(lipgloss.Left, header, badges, preview)
			contentBuilder.WriteString(cardStyle.Width(max(0, m.kgViewport.Width-2)).Render(card) + "\n")
		}
	}

	m.kgViewport.SetContent(wordwrap.String(contentBuilder.String(), m.kgViewport.Width))

	if !m.inspectorMode && len(m.kgTargets) > 0 {
		cursorYTop := m.dashboardCursor * 5
		cursorYBottom := cursorYTop + 4
		if m.dashboardCursor == 0 {
			m.kgViewport.SetYOffset(0)
		} else if cursorYTop < m.kgViewport.YOffset {
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
		case "1":
			m.activeLogFilter = LogCategoryGeneral
			m.rebuildLogsViewport(false)
		case "2":
			m.activeLogFilter = LogCategoryTools
			m.rebuildLogsViewport(false)
		case "3":
			m.activeLogFilter = LogCategoryChat
			m.rebuildLogsViewport(false)
		case "4":
			m.activeLogFilter = LogCategoryErrors
			m.rebuildLogsViewport(false)
		case "g":
			m.collapsedSummaries = !m.collapsedSummaries
			m.rebuildLogsViewport(false)
		case "up", "k":
			if m.activePane == 1 {
				if m.inspectorMode {
					m.kgViewport.ScrollUp(1)
				} else if m.dashboardCursor > 0 {
					m.dashboardCursor--
					m.updateKGViewport()
				}
			} else {
				m.logsViewport.ScrollUp(1)
			}
		case "down", "j":
			if m.activePane == 1 {
				if m.inspectorMode {
					m.kgViewport.ScrollDown(1)
				} else if m.dashboardCursor < len(m.kgTargets)-1 {
					m.dashboardCursor++
					m.updateKGViewport()
				}
			} else {
				m.logsViewport.ScrollDown(1)
			}
		case "enter", " ":
			if m.activePane == 1 && !m.inspectorMode && len(m.kgTargets) > 0 {
				m.inspectorMode = true
				m.kgViewport.SetYOffset(0)
				m.updateKGViewport()
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
		footerHeight := lipgloss.Height(m.footerView())
		statusHeight := lipgloss.Height(m.statusBarView())
		verticalMarginHeight := headerHeight + footerHeight + statusHeight + 4

		logsWidth := ((msg.Width * 2) / 3) - 4
		kgWidth := msg.Width - ((msg.Width * 2) / 3) - 4

		if logsWidth < 0 {
			logsWidth = 0
		}
		if kgWidth < 0 {
			kgWidth = 0
		}

		kgHeight := max(0, msg.Height-verticalMarginHeight)

		if !m.ready {
			m.logsViewport = viewport.New(logsWidth, max(0, msg.Height-verticalMarginHeight))
			m.kgViewport = viewport.New(kgWidth, kgHeight)
			m.ready = true
		} else {
			m.logsViewport.Width = logsWidth
			m.logsViewport.Height = max(0, msg.Height-verticalMarginHeight)
			m.kgViewport.Width = kgWidth
			m.kgViewport.Height = max(0, kgHeight)
		}

		m.rebuildLogsViewport(true)
		m.updateKGViewport()

	case LogMsg:
		m.allLogs = append(m.allLogs, msg.Entry)
		m.rebuildLogsViewport(true)

	case KGUpdateMsg:
		m.kgTargets = parseKG(msg.Data, m.kgTargets)
		if m.dashboardCursor >= len(m.kgTargets) {
			m.dashboardCursor = max(0, len(m.kgTargets)-1)
		}
		m.updateKGViewport()

	case AgentFinishedMsg:
		m.finished = true
		m.finalReport = msg.Report
		if m.finalReport != "" {
			reportText := "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Render("--- Final Report ---\n"+m.finalReport)
			m.allLogs = append(m.allLogs, LogEntry{Category: LogCategoryGeneral, Text: reportText})
			m.rebuildLogsViewport(true)
		}

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
			case "up", "down", "k", "j", "1", "2", "3", "4", "g":
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

func (m Model) statusBarView() string {
	pane := "Logs"
	if m.activePane == 1 {
		pane = "Knowledge Graph"
	}
	mode := "Dashboard"
	if m.inspectorMode {
		mode = "Inspector"
	}
	filterLabel := "All"
	switch m.activeLogFilter {
	case LogCategoryTools:
		filterLabel = "Tools"
	case LogCategoryChat:
		filterLabel = "Chat"
	case LogCategoryErrors:
		filterLabel = "Errors"
	}
	content := fmt.Sprintf("Pane: %s   Mode: %s   Filter: %s   Targets: %d", pane, mode, filterLabel, len(m.kgTargets))
	return statusBarStyle.Width(max(lipgloss.Width(content), m.width)).Render(content)
}

func (m Model) footerView() string {
	filters := []struct {
		label    string
		category LogCategory
	}{
		{label: "1 All", category: LogCategoryGeneral},
		{label: "2 Tools", category: LogCategoryTools},
		{label: "3 Chat", category: LogCategoryChat},
		{label: "4 Errors", category: LogCategoryErrors},
	}

	filterViews := make([]string, 0, len(filters))
	for _, filter := range filters {
		style := inactiveFilterStyle
		if m.activeLogFilter == filter.category {
			style = activeFilterStyle
		}
		filterViews = append(filterViews, style.Render(filter.label))
	}

	groupingLabel := inactiveFilterStyle.Render("g Expanded")
	if m.collapsedSummaries {
		groupingLabel = activeFilterStyle.Render("g Grouped")
	}

	keys := footerStyle.Render("Tab switch pane  j/k move  Enter inspect  Esc back  q quit")
	controls := lipgloss.JoinHorizontal(lipgloss.Left, strings.Join(filterViews, " "), " ", groupingLabel)
	return lipgloss.JoinVertical(lipgloss.Left, controls, keys)
}

func (m Model) View() string {
	if !m.ready {
		return "\n  Initializing..."
	}

	logsContent := m.logsViewport.View()
	activeColor := lipgloss.Color("205")
	inactiveColor := lipgloss.Color("62")

	logsBorderColor := inactiveColor
	kgBorderColor := inactiveColor
	if m.activePane == 0 {
		logsBorderColor = activeColor
	} else {
		kgBorderColor = activeColor
	}

	logsTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).Render(" Execution Log")
	logsScrollStr := fmt.Sprintf(" %3.0f%% ", m.logsViewport.ScrollPercent()*100)
	if m.logsViewport.TotalLineCount() <= m.logsViewport.Height {
		logsScrollStr = " 100% "
	}
	logsStatus := lipgloss.NewStyle().Width(m.logsViewport.Width).Align(lipgloss.Right).Foreground(lipgloss.Color("240")).Render(logsScrollStr)
	paddedLogs := lipgloss.NewStyle().Height(m.logsViewport.Height).Render(logsContent)
	logsContentWithStatus := lipgloss.JoinVertical(lipgloss.Left, logsTitle, paddedLogs, logsStatus)

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

	logsStyle := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(logsBorderColor).Padding(0, 1)
	kgStyle := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(kgBorderColor).Padding(0, 1)

	split := lipgloss.JoinHorizontal(lipgloss.Top, logsStyle.Render(logsContentWithStatus), kgStyle.Render(kgCombined))
	return lipgloss.JoinVertical(lipgloss.Left, m.headerView(), m.statusBarView(), split, m.footerView())
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
