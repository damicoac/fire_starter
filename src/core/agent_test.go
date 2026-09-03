package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAgent_LifecycleAndEvents(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	cfg := AgentConfig{
		ID:     "agent_recon_1",
		Name:   "Recon Agent",
		Role:   "reconnaissance",
		Target: "http://target.local",
	}

	agent, err := NewAgent(cfg, bus)
	if err != nil {
		t.Fatalf("unexpected error creating agent: %v", err)
	}

	if agent.ID() != "agent_recon_1" || agent.Name() != "Recon Agent" || agent.Role() != "reconnaissance" || agent.Target() != "http://target.local" {
		t.Errorf("agent properties mismatch: %+v", agent.Config())
	}

	retCfg := agent.Config()
	if retCfg.ID != cfg.ID || retCfg.Target != cfg.Target {
		t.Errorf("expected config match, got %+v", retCfg)
	}

	if agent.State() != StateCreated {
		t.Errorf("expected initial state %s, got %s", StateCreated, agent.State())
	}

	var stateChanges []Event
	var mu sync.Mutex

	_, _ = bus.Subscribe(EventTypeAgentStateChanged, func(ctx context.Context, event Event) error {
		mu.Lock()
		defer mu.Unlock()
		stateChanges = append(stateChanges, event)
		return nil
	})

	var receivedTargetEvents []Event
	err = agent.On("target.discovered", func(ctx context.Context, event Event) error {
		mu.Lock()
		defer mu.Unlock()
		receivedTargetEvents = append(receivedTargetEvents, event)
		return nil
	})
	if err != nil {
		t.Fatalf("failed to register On handler: %v", err)
	}

	// Start agent
	err = agent.Start(context.Background())
	if err != nil {
		t.Fatalf("failed to start agent: %v", err)
	}
	if agent.State() != StateRunning {
		t.Errorf("expected state %s, got %s", StateRunning, agent.State())
	}

	// Double start should fail
	if err := agent.Start(context.Background()); err == nil {
		t.Error("expected error on starting already running agent")
	}

	// Emit from agent
	err = agent.Emit(context.Background(), "target.discovered", map[string]string{"subdomain": "sub.target.local"})
	if err != nil {
		t.Fatalf("unexpected error emitting from agent: %v", err)
	}

	mu.Lock()
	if len(receivedTargetEvents) != 1 {
		t.Errorf("expected 1 target.discovered event handled by agent, got %d", len(receivedTargetEvents))
	}
	mu.Unlock()

	// EmitTargetEvent
	err = agent.EmitTargetEvent(context.Background(), "port.scanned", "http://target.local:8080", map[string]int{"port": 8080})
	if err != nil {
		t.Fatalf("unexpected error emitting target event: %v", err)
	}

	// Test iteration counting
	if agent.Iteration() != 0 {
		t.Errorf("expected 0 iterations initially, got %d", agent.Iteration())
	}
	if agent.IncrementIteration() != 1 {
		t.Errorf("expected iteration 1 after increment")
	}

	// Stop agent
	err = agent.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping agent: %v", err)
	}
	if agent.State() != StateStopped {
		t.Errorf("expected state %s, got %s", StateStopped, agent.State())
	}

	// Double stop should be idempotent
	if err := agent.Stop(); err != nil {
		t.Errorf("stop should be idempotent, got %v", err)
	}

	mu.Lock()
	if len(stateChanges) < 2 {
		t.Errorf("expected state change events for running and stopped, got %d", len(stateChanges))
	}
	mu.Unlock()
}

func TestAgent_OnHandlerWhenAlreadyRunning(t *testing.T) {
	bus := NewEventBus()

	agent, _ := NewAgent(AgentConfig{Name: "DynamicAgent"}, bus)
	_ = agent.Start(context.Background())

	var handled int32
	err := agent.On("dynamic.event", func(ctx context.Context, event Event) error {
		atomic.AddInt32(&handled, 1)
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error adding On handler to running agent: %v", err)
	}

	_ = agent.Emit(context.Background(), "dynamic.event", "payload")
	if atomic.LoadInt32(&handled) != 1 {
		t.Errorf("expected dynamic handler to process event, got %d", handled)
	}

	// Test error when bus is closed and On is called on running agent
	_ = bus.Close()
	err = agent.On("another.event", func(ctx context.Context, event Event) error { return nil })
	if err == nil {
		t.Error("expected error adding On handler when bus is closed")
	}
	_ = agent.Stop()
}

func TestAgent_StartFailsOnClosedBus(t *testing.T) {
	bus := NewEventBus()
	agent, _ := NewAgent(AgentConfig{}, bus)

	_ = agent.On("test.event", func(ctx context.Context, event Event) error { return nil })
	_ = bus.Close()

	err := agent.Start(context.Background())
	if err == nil {
		t.Error("expected error starting agent on closed bus")
	}
	if agent.State() != StateFailed {
		t.Errorf("expected state %s, got %s", StateFailed, agent.State())
	}
}

func TestAgent_ProcessEvent(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	agent, _ := NewAgent(AgentConfig{}, bus)

	var exactCount int32
	var wildcardCount int32

	_ = agent.On("explicit.event", func(ctx context.Context, event Event) error {
		atomic.AddInt32(&exactCount, 1)
		return nil
	})

	_ = agent.On(EventTypeWildcard, func(ctx context.Context, event Event) error {
		atomic.AddInt32(&wildcardCount, 1)
		return nil
	})

	_ = agent.ProcessEvent(context.Background(), Event{Type: "explicit.event"})

	if atomic.LoadInt32(&exactCount) != 1 {
		t.Errorf("expected exact handler call, got %d", exactCount)
	}
	if atomic.LoadInt32(&wildcardCount) != 1 {
		t.Errorf("expected wildcard handler call, got %d", wildcardCount)
	}
}

func TestAgent_ValidationErrors(t *testing.T) {
	_, err := NewAgent(AgentConfig{}, nil)
	if err == nil {
		t.Error("expected error creating agent with nil bus")
	}

	bus := NewEventBus()
	defer bus.Close()

	agent, _ := NewAgent(AgentConfig{}, bus)
	err = agent.On("event", nil)
	if err == nil {
		t.Error("expected error registering nil handler")
	}

	// Test default ID auto-generation
	defaultAgent, _ := NewAgent(AgentConfig{}, bus)
	if defaultAgent.ID() == "" {
		t.Error("expected auto-generated agent ID")
	}
	if defaultAgent.Name() != defaultAgent.ID() {
		t.Errorf("expected default name to match auto-generated ID")
	}
}

func TestAgent_HandlerErrorPropagates(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	agent, _ := NewAgent(AgentConfig{}, bus)
	expectedErr := errors.New("agent handler error")

	_ = agent.On("err.event", func(ctx context.Context, event Event) error {
		return expectedErr
	})

	err := agent.ProcessEvent(context.Background(), Event{Type: "err.event"})
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}
