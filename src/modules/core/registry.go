package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
)

type ExecutableModule interface {
	Execute(ctx context.Context) (any, error)
	GetUnderlying() any
}

// SessionAware indicates a module that accepts authenticated session cookies
type SessionAware interface {
	SetCookies(cookies string)
}

// PoCProvider indicates a module that collects Proof of Concept reproduction steps
type PoCProvider interface {
	GetPoCs() []ProofOfConcept
}

// ThreadConfigurable allows runtime adjustment of worker concurrency
type ThreadConfigurable interface {
	SetThreads(count int)
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
	key := strings.ToLower(strings.TrimSpace(technique))
	registryMu.Lock()
	defer registryMu.Unlock()
	if existing, ok := moduleRegistry[key]; ok && existing != nil {
		// Duplicate technique keys silently replace the first registration,
		// hiding programming errors; fail loudly instead.
		panic(fmt.Sprintf("module technique %q registered more than once", key))
	}
	moduleRegistry[key] = factory
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
	case int64:
		return int(val)
	case int32:
		return int(val)
	case uint:
		return int(val)
	case json.Number:
		if i, err := val.Int64(); err == nil {
			return int(i)
		}
	case float64:
		// Clamp out-of-range values instead of letting the conversion wrap.
		if val < math.MinInt32 {
			return math.MinInt32
		}
		if val > math.MaxInt32 {
			return math.MaxInt32
		}
		return int(val)
	case string:
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return fallback
}
