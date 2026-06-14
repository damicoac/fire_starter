package agent

import (
	"encoding/json"
	"fmt"
	"os"
)

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Config struct {
	Target            string       `json:"target"`
	Provider          string       `json:"provider"`
	Model             string       `json:"model"`
	BaseURL           string       `json:"base_url"`
	MaxIters          int          `json:"max_iters"`
	Verbose           bool         `json:"verbose"`
	EfficiencyMode    bool         `json:"efficiency_mode"`
	IPWhitelist       []string     `json:"ip_whitelist"`
	RulesOfEngagement string       `json:"rules_of_engagement"`
	Credentials       []Credential `json:"credentials"`
}

func DefaultConfig() Config {
	return Config{
		Provider:       "openai",
		Model:          "gpt-4o",
		MaxIters:       50,
		EfficiencyMode: true,
		IPWhitelist:    make([]string, 0),
		Credentials:    make([]Credential, 0),
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config file: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bytes, &raw); err != nil {
		return cfg, fmt.Errorf("parse config file: %w", err)
	}

	if err := json.Unmarshal(bytes, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config file: %w", err)
	}

	if _, hasMaxIters := raw["max_iters"]; !hasMaxIters {
		if legacyMaxIters, hasLegacyMaxIters := raw["max_iterations"]; hasLegacyMaxIters {
			var v int
			if err := json.Unmarshal(legacyMaxIters, &v); err == nil {
				cfg.MaxIters = v
			}
		}
	}

	if cfg.MaxIters <= 0 {
		cfg.MaxIters = 50
	}
	if cfg.IPWhitelist == nil {
		cfg.IPWhitelist = make([]string, 0)
	}
	if cfg.Credentials == nil {
		cfg.Credentials = make([]Credential, 0)
	}
	if cfg.Provider == "" {
		cfg.Provider = "openai"
	}
	if cfg.Model == "" {
		cfg.Model = "gpt-4o"
	}

	return cfg, nil
}
