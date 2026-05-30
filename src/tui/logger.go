package tui

import (
	"strconv"
	"strings"

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
	loopStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	toolStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("86"))
	updateStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	chatStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("111")).Italic(true)
	errorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)

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

	toolBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("86")).
			Foreground(lipgloss.Color("86")).
			Padding(0, 1)
)

func formatLogLine(line string) string {
	if strings.Contains(line, "RED_TEAM_LOOP") {
		return loopStyle.Render(line)
	}
	if strings.Contains(line, "TOOL_SELECTED") {
		toolPrefix := "tool="
		idx := strings.Index(line, toolPrefix)
		if idx != -1 {
			start := idx + len(toolPrefix)
			end := strings.Index(line[start:], " ")
			var toolName string
			if end == -1 {
				toolName = line[start:]
			} else {
				toolName = line[start : start+end]
			}
			return toolBoxStyle.Render("Running Tool: " + toolName)
		}
		return toolStyle.Render(line)
	}
	if strings.Contains(line, "KNOWLEDGE_GRAPH_UPDATE") {
		return updateStyle.Render(line)
	}
	if strings.Contains(line, "LLM_CHAT_MESSAGE") {
		idx := strings.Index(line, `text="`)
		if idx != -1 {
			quoted := line[idx+5:]
			unquoted, err := strconv.Unquote(quoted)
			if err == nil {
				return quoteStyle.Render(strings.TrimSpace(unquoted))
			}
		}
		return chatStyle.Render(line)
	}
	if strings.Contains(line, "TOOL_ERROR") {
		return errorStyle.Render(line)
	}
	if strings.Contains(line, "TOOL_EXECUTION_SUMMARY") {
		toolPrefix := "tool="
		summaryPrefix := `summary="`

		tIdx := strings.Index(line, toolPrefix)
		sIdx := strings.Index(line, summaryPrefix)
		
		if tIdx != -1 && sIdx != -1 {
			toolName := strings.TrimSpace(line[tIdx+len(toolPrefix) : sIdx])
			quotedSummary := line[sIdx+len(`summary=`):]
			
			unquoted, err := strconv.Unquote(quotedSummary)
			if err == nil {
				// Replace literal "\n" sequences with actual newlines in case the LLM returned raw "\n" strings
				unquoted = strings.ReplaceAll(unquoted, `\n`, "\n")
				header := lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Render("Summary (" + toolName + "):")
				body := summaryStyle.Render(strings.TrimSpace(unquoted))
				return header + "\n" + body
			}
		}
	}
	return line
}
