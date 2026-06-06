package tui

import (
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ProgramWriter acts as an io.Writer that forwards written bytes
// as LogMsg to a running Bubble Tea program.
type ProgramWriter struct {
	Program *tea.Program
}

func NewProgramWriter(p *tea.Program) *ProgramWriter {
	return &ProgramWriter{
		Program: p,
	}
}

func (w *ProgramWriter) Write(p []byte) (n int, err error) {
	if w.Program != nil {
		text := strings.TrimRight(string(p), "\r\n")
		if strings.Contains(text, "KNOWLEDGE_GRAPH_UPDATE") {
			return len(p), nil // Suppress this log, we'll use the sidebar instead
		}
		formatted := formatLogLine(text)
		w.Program.Send(LogMsg{Text: formatted})
	}
	return len(p), nil
}

var (
	timeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	loopBadge   = lipgloss.NewStyle().Background(lipgloss.Color("205")).Foreground(lipgloss.Color("0")).Bold(true).Padding(0, 1)
	toolBadge   = lipgloss.NewStyle().Background(lipgloss.Color("86")).Foreground(lipgloss.Color("0")).Bold(true).Padding(0, 1)
	chatBadge   = lipgloss.NewStyle().Background(lipgloss.Color("111")).Foreground(lipgloss.Color("0")).Bold(true).Padding(0, 1)
	errorBadge  = lipgloss.NewStyle().Background(lipgloss.Color("196")).Foreground(lipgloss.Color("255")).Bold(true).Padding(0, 1)
	updateBadge = lipgloss.NewStyle().Background(lipgloss.Color("42")).Foreground(lipgloss.Color("0")).Bold(true).Padding(0, 1)

	quoteStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("111")).
			Border(lipgloss.NormalBorder(), false, false, false, true).
			BorderForeground(lipgloss.Color("111")).
			PaddingLeft(1)

	summaryStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("250")).
			Border(lipgloss.NormalBorder(), false, false, false, true).
			BorderForeground(lipgloss.Color("42")).
			PaddingLeft(1)
)

func formatLogLine(line string) string {
	ts := timeStyle.Render(time.Now().Format("15:04:05"))

	if strings.Contains(line, "RED_TEAM_LOOP") {
		badge := loopBadge.Render("RED_TEAM_LOOP")
		rest := strings.Replace(line, "RED_TEAM_LOOP", badge, 1)
		return ts + " [*] " + rest
	}
	if strings.Contains(line, "TOOL_SELECTED") {
		badge := toolBadge.Render("TOOL_SELECTED")
		rest := strings.Replace(line, "TOOL_SELECTED", badge, 1)
		return ts + " [+] " + rest
	}
	if strings.Contains(line, "KNOWLEDGE_GRAPH_UPDATE") {
		badge := updateBadge.Render("KNOWLEDGE_GRAPH_UPDATE")
		rest := strings.Replace(line, "KNOWLEDGE_GRAPH_UPDATE", badge, 1)
		return ts + " [~] " + rest
	}
	if strings.Contains(line, "LLM_CHAT_MESSAGE") {
		badge := chatBadge.Render("LLM_CHAT_MESSAGE")
		rest := strings.Replace(line, "LLM_CHAT_MESSAGE", badge, 1)
		
		idx := strings.Index(line, `text="`)
		if idx != -1 {
			quoted := line[idx+5:]
			unquoted, err := strconv.Unquote(quoted)
			if err == nil {
				return ts + " [-] " + badge + "\n" + quoteStyle.Render(strings.TrimSpace(unquoted))
			}
		}
		return ts + " [-] " + rest
	}
	if strings.Contains(line, "TOOL_ERROR") {
		badge := errorBadge.Render("TOOL_ERROR")
		rest := strings.Replace(line, "TOOL_ERROR", badge, 1)
		return ts + " [!] " + rest
	}
	if strings.Contains(line, "TOOL_EXECUTION_SUMMARY") {
		badge := toolBadge.Render("TOOL_EXECUTION_SUMMARY")
		
		toolPrefix := "tool="
		summaryPrefix := `summary="`

		tIdx := strings.Index(line, toolPrefix)
		sIdx := strings.Index(line, summaryPrefix)
		
		if tIdx != -1 && sIdx != -1 {
			toolName := strings.TrimSpace(line[tIdx+len(toolPrefix) : sIdx])
			quotedSummary := line[sIdx+len(`summary=`):]
			
			unquoted, err := strconv.Unquote(quotedSummary)
			if err == nil {
				// Replace literal "\n" sequences with actual newlines
				unquoted = strings.ReplaceAll(unquoted, `\n`, "\n")
				header := ts + " [+] " + badge + lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Render(" (" + toolName + ")")
				body := summaryStyle.Render(strings.TrimSpace(unquoted))
				return header + "\n" + body
			}
		}
		rest := strings.Replace(line, "TOOL_EXECUTION_SUMMARY", badge, 1)
		return ts + " [+] " + rest
	}
	return ts + " [*] " + line
}
