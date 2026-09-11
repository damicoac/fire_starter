package tui

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"fire_starter/src/matrix"

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
	Finding  string
	Status   string
	Severity string
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
	DiscoveredURLs       []string
	Credentials          []struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	SiteMap *matrix.SiteMap `json:"site_map,omitempty"`
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
	activeTab          int
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
			DiscoveredURLs  []string `json:"discovered_urls"`
			Credentials     []struct {
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"credentials"`
			SiteMap *matrix.SiteMap `json:"site_map"`
		} `json:"targets"`
		VulnerabilityRecords []struct {
			TargetDomain string `json:"TargetDomain"`
			Finding      string `json:"Finding"`
			Status       string `json:"Status"`
			Severity     string `json:"Severity"`
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
		vulnerabilityDetailsByTarget[v.TargetDomain] = append(vulnerabilityDetailsByTarget[v.TargetDomain], KGVulnerability{Finding: v.Finding, Status: v.Status, Severity: v.Severity})
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
			DiscoveredURLs:       t.DiscoveredURLs,
			Credentials:          t.Credentials,
			SiteMap:              t.SiteMap,
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
	switch m.activeTab {
	case 1:
		m.logsViewport.SetContent(buildSiteMapView(m.kgTargets, m.logsViewport.Width))
	case 2:
		m.logsViewport.SetContent(buildTargetCardsView(m.kgTargets, m.dashboardCursor, m.activePane == 0, m.logsViewport.Width))
	default:
		raw := filterLogs(m.allLogs, m.activeLogFilter, m.collapsedSummaries)
		if len(raw) == 0 {
			m.visibleLogs = []string{mutedStyle.Render("No log entries for the current filter yet.")}
		} else {
			m.visibleLogs = make([]string, len(raw))
			for i, line := range raw {
				m.visibleLogs[i] = wordwrap.String(line, m.logsViewport.Width)
			}
		}
		m.logsViewport.SetContent(strings.Join(m.visibleLogs, "\n"))
		if stickBottom {
			m.logsViewport.GotoBottom()
		}
	}
}

func formatLogText(entry LogEntry, collapsed bool) string {
	text := entry.Text
	if collapsed && entry.Category == LogCategoryTools && strings.Contains(text, "TOOL_EXECUTION_SUMMARY") {
		lines := strings.Split(text, "\n")
		if len(lines) > 1 {
			text = lines[0]
		}
	}
	return text
}

func filterLogs(entries []LogEntry, filter LogCategory, collapsed bool) []string {
	filtered := make([]string, 0, len(entries))
	for _, entry := range entries {
		if filter != LogCategoryGeneral && entry.Category != filter {
			continue
		}
		filtered = append(filtered, formatLogText(entry, collapsed))
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

func buildSiteMapView(targets []KGTarget, width int) string {
	if len(targets) == 0 {
		return mutedStyle.Render("No site map data discovered yet.")
	}

	var sb strings.Builder
	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	header := titleStyle.Render("🌐 Target Site Map & Topology")
	sb.WriteString(header + "\n\n")

	totalURLs := 0
	totalNodes := 0
	siteMaps := make([]*matrix.SiteMap, len(targets))

	for i, t := range targets {
		totalURLs += len(t.DiscoveredURLs)
		sm := t.SiteMap
		if sm == nil {
			sm = matrix.NewSiteMap(t.Value)
			for _, u := range t.DiscoveredURLs {
				_ = sm.AddURL(u, "", 0, "", nil)
			}
		}
		siteMaps[i] = sm
		totalNodes += sm.NodeCount()
	}

	summary := mutedStyle.Render(fmt.Sprintf("Targets: %d   Discovered Endpoints: %d   Tree Nodes: %d", len(targets), totalURLs, totalNodes))
	sb.WriteString(summary + "\n\n")

	for i, t := range targets {
		sm := siteMaps[i]
		targetHeader := lipgloss.NewStyle().Foreground(lipgloss.Color("33")).Bold(true).Render("▼ 🌐 " + t.Value)
		scoreBadge := mutedStyle.Render(fmt.Sprintf(" (score %d)", t.Score))
		sb.WriteString(targetHeader + scoreBadge + " " + phaseBadge(t.CurrentPhase) + "\n")

		children := sm.Root.SortedChildren()
		if len(children) == 0 {
			sb.WriteString(mutedStyle.Render("  └── 📁 / (root surface only)\n\n"))
			continue
		}

		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Render("  ├── 📁 / (root surface)\n"))
		for idx, child := range children {
			isLast := (idx == len(children)-1)
			renderSiteNode(&sb, child, "  ", isLast, width)
		}
		sb.WriteString("\n")
	}

	return clipViewLines(sb.String(), width)
}

func renderSiteNode(sb *strings.Builder, node *matrix.SiteNode, prefix string, isLast bool, width int) {
	connector := "├── "
	if isLast {
		connector = "└── "
	}

	children := node.SortedChildren()
	hasChildren := len(children) > 0

	icon := "📄 "
	nodeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	if hasChildren {
		icon = "📁 "
		nodeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	}

	lineText := prefix + connector + icon + nodeStyle.Render(node.Path)

	if node.Method != "" {
		methodStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
		lineText += " " + methodStyle.Render("["+node.Method+"]")
	}
	if node.StatusCode > 0 {
		statusColor := lipgloss.Color("46")
		if node.StatusCode >= 400 {
			statusColor = lipgloss.Color("196")
		} else if node.StatusCode >= 300 {
			statusColor = lipgloss.Color("220")
		}
		statusStyle := lipgloss.NewStyle().Foreground(statusColor)
		lineText += " " + statusStyle.Render(fmt.Sprintf("[%d]", node.StatusCode))
	}
	if len(node.Parameters) > 0 {
		paramStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
		lineText += " " + paramStyle.Render("?"+strings.Join(node.Parameters, ","))
	}

	sb.WriteString(lineText + "\n")

	childPrefix := prefix + "│   "
	if isLast {
		childPrefix = prefix + "    "
	}

	for i, child := range children {
		childIsLast := (i == len(children)-1)
		renderSiteNode(sb, child, childPrefix, childIsLast, width)
	}
}

func clipViewLines(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if lipgloss.Width(line) > maxWidth {
			lines[i] = lipgloss.NewStyle().MaxWidth(maxWidth).Render(line)
		}
	}
	return strings.Join(lines, "\n")
}

func buildTargetCardsView(targets []KGTarget, cursor int, isPaneActive bool, width int) string {
	if len(targets) == 0 {
		return mutedStyle.Render("No targets discovered yet.")
	}

	var contentBuilder strings.Builder
	totalPorts, totalVulns, totalTokens, totalCreds := 0, 0, 0, 0
	for _, t := range targets {
		totalPorts += len(t.OpenPorts)
		totalVulns += len(t.Vulnerabilities)
		totalTokens += len(t.Tokens)
		totalCreds += len(t.Credentials)
	}

	summaryTop := joinNonEmpty([]string{
		countBadge("Targets", len(targets), lipgloss.Color("62")),
		countBadge("Vulns", totalVulns, lipgloss.Color("196")),
		countBadge("Creds", totalCreds, lipgloss.Color("220")),
		countBadge("Tokens", totalTokens, lipgloss.Color("99")),
		countBadge("Ports", totalPorts, lipgloss.Color("33")),
	}, " ")
	contentBuilder.WriteString(summaryTop + "\n")
	contentBuilder.WriteString(phaseBreakdown(targets) + "\n\n")

	for i, t := range targets {
		cardStyle := cardBaseStyle
		if i == cursor && isPaneActive {
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
		headerWidth := max(0, width-8-lipgloss.Width(headerRight))
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
			previewItems = append(previewItems, fmt.Sprintf("[%s/%s] %s", t.VulnerabilityDetails[0].Status, t.VulnerabilityDetails[0].Severity, t.VulnerabilityDetails[0].Finding))
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
		contentBuilder.WriteString(cardStyle.Width(max(0, width-2)).Render(card) + "\n")
	}

	return wordwrap.String(contentBuilder.String(), width)
}

func buildInspectorView(t KGTarget, width int) string {
	var contentBuilder strings.Builder

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
			contentBuilder.WriteString(fmt.Sprintf("  • [%s/%s] %s\n", v.Status, v.Severity, v.Finding))
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

	return wordwrap.String(contentBuilder.String(), width)
}

func (m *Model) updateKGViewport() {
	if !m.ready {
		return
	}

	if m.activeTab == 2 {
		if len(m.kgTargets) > 0 && m.dashboardCursor < len(m.kgTargets) {
			t := m.kgTargets[m.dashboardCursor]
			m.kgViewport.SetContent(buildInspectorView(t, m.kgViewport.Width))
		} else {
			m.kgViewport.SetContent(mutedStyle.Render("No target selected."))
		}
		return
	}

	m.kgViewport.SetContent(buildTargetCardsView(m.kgTargets, m.dashboardCursor, m.activePane == 1, m.kgViewport.Width))
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
		case "tab", "shift+tab":
			m.activePane = 1 - m.activePane
			m.rebuildLogsViewport(false)
			m.updateKGViewport()
		case "left", "h":
			m.activePane = 0
			m.rebuildLogsViewport(false)
			m.updateKGViewport()
		case "right", "l":
			m.activePane = 1
			m.rebuildLogsViewport(false)
			m.updateKGViewport()
		case "1", "f1":
			m.activeTab = 0
			m.rebuildLogsViewport(false)
			m.updateKGViewport()
		case "2", "f2":
			m.activeTab = 1
			m.rebuildLogsViewport(false)
			m.updateKGViewport()
		case "3", "f3":
			m.activeTab = 2
			m.rebuildLogsViewport(false)
			m.updateKGViewport()
		case "g":
			m.collapsedSummaries = !m.collapsedSummaries
			m.rebuildLogsViewport(false)
		case "f":
			switch m.activeLogFilter {
			case LogCategoryGeneral:
				m.activeLogFilter = LogCategoryTools
			case LogCategoryTools:
				m.activeLogFilter = LogCategoryChat
			case LogCategoryChat:
				m.activeLogFilter = LogCategoryErrors
			default:
				m.activeLogFilter = LogCategoryGeneral
			}
			m.rebuildLogsViewport(false)
		case "up", "k":
			if m.activePane == 0 {
				if m.activeTab == 2 {
					if m.dashboardCursor > 0 {
						m.dashboardCursor--
						m.rebuildLogsViewport(false)
						m.updateKGViewport()
					}
				} else {
					m.logsViewport.ScrollUp(1)
				}
			} else {
				if m.activeTab != 2 {
					if m.dashboardCursor > 0 {
						m.dashboardCursor--
						m.rebuildLogsViewport(false)
						m.updateKGViewport()
					}
				} else {
					m.kgViewport.ScrollUp(1)
				}
			}
		case "down", "j":
			if m.activePane == 0 {
				if m.activeTab == 2 {
					if m.dashboardCursor < len(m.kgTargets)-1 {
						m.dashboardCursor++
						m.rebuildLogsViewport(false)
						m.updateKGViewport()
					}
				} else {
					m.logsViewport.ScrollDown(1)
				}
			} else {
				if m.activeTab != 2 {
					if m.dashboardCursor < len(m.kgTargets)-1 {
						m.dashboardCursor++
						m.rebuildLogsViewport(false)
						m.updateKGViewport()
					}
				} else {
					m.kgViewport.ScrollDown(1)
				}
			}
		case "enter", " ":
			if m.activeTab == 2 && m.activePane == 0 {
				m.activePane = 1
				m.rebuildLogsViewport(false)
				m.updateKGViewport()
			}
		case "esc", "backspace":
			if m.activePane == 1 {
				m.activePane = 0
				m.rebuildLogsViewport(false)
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
		const maxLogs = 2000
		if len(m.allLogs) >= maxLogs {
			copy(m.allLogs, m.allLogs[1:])
			m.allLogs[len(m.allLogs)-1] = msg.Entry
		} else {
			m.allLogs = append(m.allLogs, msg.Entry)
		}

		if m.activeTab != 0 {
			// Do not re-render site map or target cards on incoming log entries
			return m, nil
		}
		if m.activeLogFilter != LogCategoryGeneral && msg.Entry.Category != m.activeLogFilter {
			// Do not re-render if the new log doesn't match active filter
			return m, nil
		}
		if !m.ready {
			return m, nil
		}

		// Incremental append: wrap only the new entry rather than re-wrapping all historical logs
		if len(m.visibleLogs) == 1 && m.visibleLogs[0] == mutedStyle.Render("No log entries for the current filter yet.") {
			m.visibleLogs = nil
		}
		formatted := formatLogText(msg.Entry, m.collapsedSummaries)
		wrapped := wordwrap.String(formatted, m.logsViewport.Width)
		if len(m.visibleLogs) >= maxLogs {
			copy(m.visibleLogs, m.visibleLogs[1:])
			m.visibleLogs[len(m.visibleLogs)-1] = wrapped
		} else {
			m.visibleLogs = append(m.visibleLogs, wrapped)
		}
		m.logsViewport.SetContent(strings.Join(m.visibleLogs, "\n"))
		m.logsViewport.GotoBottom()

	case KGUpdateMsg:
		m.kgTargets = parseKG(msg.Data, m.kgTargets)
		if m.dashboardCursor >= len(m.kgTargets) {
			m.dashboardCursor = max(0, len(m.kgTargets)-1)
		}
		if m.activeTab != 0 {
			m.rebuildLogsViewport(false)
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
			case "up", "down", "k", "j", "1", "2", "3", "g", "tab", "shift+tab", "f1", "f2", "f3", "left", "right", "h", "l", "enter", " ", "esc", "backspace":
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
	tabName := "1 Execution Logs"
	switch m.activeTab {
	case 1:
		tabName = "2 Site Map"
	case 2:
		tabName = "3 Knowledge Base & Findings"
	}
	paneName := "Left Pane"
	if m.activePane == 1 {
		paneName = "Right Pane"
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
	content := fmt.Sprintf("View: %s   Focus: %s   Filter: %s   Targets: %d", tabName, paneName, filterLabel, len(m.kgTargets))
	return statusBarStyle.Width(max(lipgloss.Width(content), m.width)).Render(content)
}

func (m Model) footerView() string {
	tabs := []string{"1 Execution Logs", "2 Site Map", "3 Knowledge Base & Findings"}
	var tabViews []string
	for i, t := range tabs {
		style := inactiveFilterStyle
		if m.activeTab == i {
			style = activeFilterStyle
		}
		tabViews = append(tabViews, style.Render(t))
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
	filterTag := activeFilterStyle.Render("f Filter: " + filterLabel)

	groupingLabel := inactiveFilterStyle.Render("g Expanded")
	if m.collapsedSummaries {
		groupingLabel = activeFilterStyle.Render("g Grouped")
	}

	keys := footerStyle.Render("1-3 switch view  Tab/←→ switch focus  j/k move  f filter  g collapse  q quit")
	controls := lipgloss.JoinHorizontal(lipgloss.Left, strings.Join(tabViews, " "), " | ", filterTag, " ", groupingLabel)
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

	logsTitleStr := " Execution Log"
	if m.activeTab == 1 {
		logsTitleStr = " 🌐 Target Site Map"
	} else if m.activeTab == 2 {
		logsTitleStr = " Target Domains & Hosts"
	}
	logsTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).Render(logsTitleStr)

	logsScrollStr := fmt.Sprintf(" %3.0f%% ", m.logsViewport.ScrollPercent()*100)
	if m.logsViewport.TotalLineCount() <= m.logsViewport.Height {
		logsScrollStr = " 100% "
	}
	logsStatus := lipgloss.NewStyle().Width(m.logsViewport.Width).Align(lipgloss.Right).Foreground(lipgloss.Color("240")).Render(logsScrollStr)
	paddedLogs := lipgloss.NewStyle().Height(m.logsViewport.Height).Render(logsContent)
	logsContentWithStatus := lipgloss.JoinVertical(lipgloss.Left, logsTitle, paddedLogs, logsStatus)

	titleStr := " Knowledge Base Overview"
	if m.activeTab == 2 {
		titleStr = " Target Inspector & Evidence"
	}
	kgTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).Render(titleStr)

	var kgScrollStr string
	if m.activeTab == 2 || m.inspectorMode {
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
