package core

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type ExecutableModule interface {
	Execute(ctx context.Context) (any, error)
	GetUnderlying() any
}

type ModuleWrapper struct {
	Module      any
	ExecuteFunc func(ctx context.Context) (any, error)
}

func (m ModuleWrapper) Execute(ctx context.Context) (any, error) {
	return m.ExecuteFunc(ctx)
}

func (m ModuleWrapper) GetUnderlying() any {
	return m.Module
}

type ModuleFactory func(payload map[string]any, onLog func(string)) (ExecutableModule, error)

var (
	moduleRegistry = make(map[string]ModuleFactory)
	registryMu     sync.RWMutex
)

func RegisterModule(technique string, factory ModuleFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	moduleRegistry[strings.ToLower(strings.TrimSpace(technique))] = factory
}

func GetModuleFactory(technique string) (ModuleFactory, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	factory, ok := moduleRegistry[strings.ToLower(strings.TrimSpace(technique))]
	return factory, ok
}

// Payload helpers available to all modules during factory initialization
func PayloadString(payload map[string]any, key, fallback string) string {
	v, ok := payload[key]
	if !ok || v == nil {
		return fallback
	}
	if s, ok := v.(string); ok {
		s = strings.TrimSpace(s)
		if s == "" {
			return fallback
		}
		return s
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	if s == "" {
		return fallback
	}
	return s
}

func PayloadInt(payload map[string]any, key string, fallback int) int {
	v, ok := payload[key]
	if !ok || v == nil {
		return fallback
	}
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	case string:
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return fallback
}
