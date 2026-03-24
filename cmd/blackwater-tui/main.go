// File overview:
// CLI entrypoint for the terminal UI. It exists to bootstrap Bubble Tea with a fully wired model so analysts can run the workflow interactively without writing glue code.

package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
