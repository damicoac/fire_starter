package agents_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"fire_starter/src/agents"
	"fire_starter/src/core"
	"fire_starter/src/matrix"
)

func TestMultiAgentSystem_EndToEndFlow(t *testing.T) {
	bus := core.NewEventBus()
	kg := matrix.NewKnowledgeGraph()
	defer kg.Close()

	commander := agents.NewCommanderAgent("commander-1", kg)
	recon := agents.NewReconAgent("recon-1", kg)
	exploit := agents.NewExploitAgent("exploit-1", kg)
	verifier := agents.NewVerifierAgent("verifier-1", kg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := commander.Start(ctx, bus); err != nil {
		t.Fatalf("failed to start commander: %v", err)
	}
	if err := recon.Start(ctx, bus); err != nil {
		t.Fatalf("failed to start recon: %v", err)
	}
	if err := exploit.Start(ctx, bus); err != nil {
		t.Fatalf("failed to start exploit: %v", err)
	}
	if err := verifier.Start(ctx, bus); err != nil {
		t.Fatalf("failed to start verifier: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)

	_, err := bus.Subscribe(core.EventTypeVulnerabilityFound, func(cctx context.Context, evt core.Event) error {
		defer wg.Done()
		payloadMap, ok := evt.Payload.(map[string]interface{})
		if !ok {
			t.Errorf("expected map payload")
			return nil
		}
		if payloadMap["verified"] != true {
			t.Errorf("expected vulnerability to be verified")
		}
		if payloadMap["vuln_type"] != "SQLInjection" {
			t.Errorf("expected SQLInjection, got %v", payloadMap["vuln_type"])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to subscribe to verified vulnerability event: %v", err)
	}

	// Trigger target discovery event
	err = bus.Publish(ctx, core.Event{
		ID:        "evt-target-1",
		Type:      core.EventTypeTargetDiscovered,
		Source:    "user",
		Timestamp: time.Now(),
		Payload:   map[string]interface{}{"target": "http://127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("failed to publish target event: %v", err)
	}

	// Wait for event completion channel signal or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Successfully received verified event
	case <-ctx.Done():
		t.Fatal("timed out waiting for verified vulnerability event")
	}
}
