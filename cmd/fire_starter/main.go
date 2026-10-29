package main

import (
	"context"
	"flag"
	"fmt"
	stdlog "log"
	"os"

	"fire_starter/src/agent"
	"fire_starter/src/matrix"
	"fire_starter/src/mcp"
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
	efficiency := flag.Bool("efficiency", true, "Enable efficiency mode to skip low value targets (default true, use -efficiency=false to disable)")
	mcpMode := flag.Bool("mcp", false, "Run in Model Context Protocol (MCP) server mode via STDIO")
	insecureTLS := flag.Bool("insecure-tls", false, "Skip TLS certificate verification (for self-signed lab endpoints only)")
	oobHost := flag.String("oob-host", "", "Public host[:port] of this scanner reachable by targets for out-of-band (OOB) callbacks; required for remote blind OOB testing")

	flag.Parse()

	if *mcpMode {
		kg := matrix.NewKnowledgeGraph()
		defer kg.Close()
		defer matrix.CloseDB()

		// Persistence in MCP mode: initialize SQLite so vulnerability and
		// target-state records are actually written instead of silently
		// no-op'ing. A failure is logged but must not abort the server.
		if _, err := matrix.InitDB("fire_starter.db"); err != nil {
			log.Warnf("Failed to init SQLite database: %v", err)
		}

		decisions, err := matrix.LoadDecisions("src/matrix/decisions.json")
		if err != nil {
			log.Fatalf("Failed to load decisions: %v", err)
		}
		executor, err := matrix.NewRealExecutor(decisions)
		if err != nil {
			log.Fatalf("Failed to initialize executor: %v", err)
		}

		// Scope guard for MCP tool execution. Without a config file there is
		// no declared engagement scope, so we fail closed and only accept
		// loopback targets; with -config the allowed set is ip_whitelist
		// plus every IP the configured target resolves to.
		allow := agent.LoopbackScopeAllow()
		if *configPath != "" {
			mcpCfg, err := agent.LoadConfig(*configPath)
			if err != nil {
				log.Fatalf("Failed loading config: %v", err)
			}
			allow = agent.ConfigScopeAllow(mcpCfg)
		}

		server := mcp.NewMCPServer(kg, executor, allow)
		if err := server.ServeSTDIO(os.Stdin, os.Stdout); err != nil {
			log.Fatalf("MCP Server error: %v", err)
		}
		return
	}
	defer matrix.CloseDB()

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
	if *maxIters > 0 {
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

	// TLS skip-verify precedence: the config file's tls_skip_verify applies
	// by default, but an explicitly passed -insecure-tls flag overrides it
	// (checked via flag.Visit, since flag.Bool defaults to false).
	insecureTLSSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "insecure-tls" {
			insecureTLSSet = true
		}
	})
	if insecureTLSSet {
		cfg.TLSSkipVerify = *insecureTLS
	}

	// OOB host precedence: the config file's oob_public_host applies by
	// default, but an explicitly passed -oob-host flag overrides it
	// (checked via flag.Visit).
	oobHostSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "oob-host" {
			oobHostSet = true
		}
	})
	if oobHostSet {
		cfg.OOBPublicHost = *oobHost
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
			b, err := kg.ToJSONWithoutTestCases("")
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
