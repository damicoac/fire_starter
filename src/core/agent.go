package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// AgentState defines the operational state of an Agent.
type AgentState string

const (
	StateCreated AgentState = "created"
	StateRunning AgentState = "running"
	StateStopped AgentState = "stopped"
	StateFailed  AgentState = "failed"
)

// AgentConfig holds configuration settings for an Agent instance.
type AgentConfig struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Role          string         `json:"role"`
	Target        string         `json:"target"`
	MaxIterations int            `json:"max_iterations,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// Agent represents an autonomous or event-driven agent in Fire Starter v2.
type Agent struct {
	mu        sync.RWMutex
	id        string
	config    AgentConfig
	bus       *EventBus
	state     AgentState
	iteration int
	subs      []*Subscription
	handlers  map[string][]Handler
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewAgent creates and initializes a new Agent.
func NewAgent(config AgentConfig, bus *EventBus) (*Agent, error) {
	if bus == nil {
		return nil, errors.New("event bus cannot be nil")
	}
	if config.ID == "" {
		config.ID = fmt.Sprintf("agent_%d", time.Now().UnixNano())
	}
	if config.Name == "" {
		config.Name = config.ID
	}

	return &Agent{
		id:       config.ID,
		config:   config,
		bus:      bus,
		state:    StateCreated,
		handlers: make(map[string][]Handler),
	}, nil
}

// ID returns the unique agent identifier.
func (a *Agent) ID() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.id
}

// Name returns the display name of the agent.
func (a *Agent) Name() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config.Name
}

// Role returns the agent role.
func (a *Agent) Role() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config.Role
}

// Target returns the assigned target for the agent.
func (a *Agent) Target() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config.Target
}

// Config returns a copy of the agent configuration.
func (a *Agent) Config() AgentConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config
}

// State returns the current lifecycle state of the agent.
func (a *Agent) State() AgentState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state
}

// Iteration returns the current loop/task iteration count.
func (a *Agent) Iteration() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.iteration
}

// IncrementIteration increments and returns the new iteration count.
func (a *Agent) IncrementIteration() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.iteration++
	return a.iteration
}

// On registers a handler callback for a specific event type on this agent.
func (a *Agent) On(eventType string, handler Handler) error {
	if handler == nil {
		return errors.New("handler cannot be nil")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.handlers[eventType] = append(a.handlers[eventType], handler)

	// If agent is already running, subscribe immediately to the bus
	if a.state == StateRunning {
		sub, err := a.bus.Subscribe(eventType, func(ctx context.Context, evt Event) error {
			return handler(ctx, evt)
		})
		if err != nil {
			return fmt.Errorf("failed to subscribe to bus: %w", err)
		}
		a.subs = append(a.subs, sub)
	}

	return nil
}

// Emit publishes an event to the EventBus with the agent as the source.
func (a *Agent) Emit(ctx context.Context, eventType string, payload any) error {
	a.mu.RLock()
	source := a.id
	target := a.config.Target
	a.mu.RUnlock()

	event := Event{
		Type:      eventType,
		Source:    source,
		Target:    target,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	return a.bus.Publish(ctx, event)
}

// EmitTargetEvent publishes an event specifying an explicit target.
func (a *Agent) EmitTargetEvent(ctx context.Context, eventType string, target string, payload any) error {
	a.mu.RLock()
	source := a.id
	a.mu.RUnlock()

	event := Event{
		Type:      eventType,
		Source:    source,
		Target:    target,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	return a.bus.Publish(ctx, event)
}

// ProcessEvent directly invokes all matching local handlers on the agent.
func (a *Agent) ProcessEvent(ctx context.Context, event Event) error {
	a.mu.RLock()
	exactHandlers := append([]Handler(nil), a.handlers[event.Type]...)
	wildcardHandlers := append([]Handler(nil), a.handlers[EventTypeWildcard]...)
	a.mu.RUnlock()

	var firstErr error
	for _, h := range exactHandlers {
		if err := h(ctx, event); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if event.Type != EventTypeWildcard {
		for _, h := range wildcardHandlers {
			if err := h(ctx, event); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}

	return firstErr
}

// Start begins agent operations, subscribing all registered event handlers to the bus.
func (a *Agent) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.state == StateRunning {
		a.mu.Unlock()
		return errors.New("agent is already running")
	}

	a.state = StateRunning
	subCtx, cancel := context.WithCancel(ctx)
	a.ctx = subCtx
	a.cancel = cancel

	// Subscribe all registered local handlers to the bus
	for eventType, handlerList := range a.handlers {
		for _, h := range handlerList {
			handlerRef := h
			sub, err := a.bus.Subscribe(eventType, func(c context.Context, evt Event) error {
				return handlerRef(c, evt)
			})
			if err != nil {
				a.state = StateFailed
				a.mu.Unlock()
				return fmt.Errorf("failed to subscribe handler for %s: %w", eventType, err)
			}
			a.subs = append(a.subs, sub)
		}
	}

	a.mu.Unlock()

	// Notify agent state change
	_ = a.Emit(ctx, EventTypeAgentStateChanged, map[string]any{
		"agent_id": a.id,
		"state":    StateRunning,
	})

	return nil
}

// Stop halts agent execution and unsubscribes all handlers from the EventBus.
func (a *Agent) Stop() error {
	a.mu.Lock()
	if a.state == StateStopped {
		a.mu.Unlock()
		return nil
	}

	a.state = StateStopped
	if a.cancel != nil {
		a.cancel()
	}

	subsToClean := a.subs
	a.subs = nil
	a.mu.Unlock()

	for _, sub := range subsToClean {
		_ = a.bus.Unsubscribe(sub)
	}

	_ = a.Emit(context.Background(), EventTypeAgentStateChanged, map[string]any{
		"agent_id": a.id,
		"state":    StateStopped,
	})

	return nil
}
