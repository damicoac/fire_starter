package main

import (
	"context"
	"flag"
	"fmt"
	stdlog "log"

	"os"

	"fire_starter/src/agent"
	"fire_starter/src/matrix"
	"fire_starter/src/tui"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/log"
)

func main() {
	cfg := agent.DefaultConfig()

	configPath := flag.String("config", "", "Path to JSON config file")
	target := flag.String("target", "", "Target IP or URL to test")
	provider := flag.String("provider", "", "LLM provider (openai, anthropic, gemini, local)")
	modelName := flag.String("model", "", "Model ID to use")
	baseURL := flag.String("base-url", "", "Custom base URL for the provider")
	maxIters := flag.Int("max-iters", 0, "Maximum execution loop iterations")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	
	// Create a custom flag variable that defaults to the config's value (true).
	efficiency := flag.Bool("efficiency", true, "Enable efficiency mode to skip low value targets (default true, use -efficiency=false to disable)")

	flag.Parse()

	loadedCfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed loading config: %v", err)
	}
	cfg = loadedCfg

	if *target != "" {
		cfg.Target = *target
	}
	if *provider != "" {
		cfg.Provider = *provider
	}
	if *modelName != "" {
		cfg.Model = *modelName
	}
	if *baseURL != "" {
		cfg.BaseURL = *baseURL
	}
	if *maxIters > 0 && *configPath == "" {
		cfg.MaxIters = *maxIters
	}
	if *verbose {
		cfg.Verbose = true
	}
	
	// Override the config value with the flag's value. 
	// If the user specifies -efficiency=false, this overrides the default true.
	// If the config file had "efficiency_mode": false, we only override it if the user explicitly provided the flag,
	// but flag.Bool doesn't easily let us check if it was provided vs defaulted.
	// However, we can check if the flag was explicitly set:
	flagSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "efficiency" {
			flagSet = true
		}
	})
	
	if flagSet {
		cfg.EfficiencyMode = *efficiency
	}

	if cfg.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	if cfg.Target == "" {
		log.Fatal("Usage: fire_starter -target <ip_or_url> or set target in -config")
	}

	m := tui.InitialModel()
	p := tea.NewProgram(m, tea.WithAltScreen())

	log.SetOutput(tui.NewProgramWriter(p))
	stdlog.SetOutput(tui.NewProgramWriter(p))

	go func() {
		log.Infof("Starting Fire Starter Agent. Target: %s, Provider: %s, Model: %s", cfg.Target, cfg.Provider, cfg.Model)

		onKGUpdate := func(kg *matrix.KnowledgeGraph) {
			b, err := kg.ToJSON("")
			if err == nil {
				p.Send(tui.KGUpdateMsg{Data: b})
			}
		}

		result, err := agent.RunAgent(context.Background(), cfg.Target, cfg, onKGUpdate)
		if err != nil {
			log.Errorf("Analysis failed: %v", err)
			p.Send(tui.AgentFinishedMsg{Report: fmt.Sprintf("Error: %v", err)})
			return
		}
		p.Send(tui.AgentFinishedMsg{Report: result})
	}()

	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}
