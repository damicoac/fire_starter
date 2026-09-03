package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEventBus_SubscribeAndPublishSync(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	var received []Event
	var mu sync.Mutex

	sub, err := bus.Subscribe("target.discovered", func(ctx context.Context, event Event) error {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, event)
		return nil
	})
	if err != nil {
		t.Fatalf("expected no error on Subscribe, got %v", err)
	}
	if sub == nil || sub.ID == "" {
		t.Fatalf("expected valid subscription handle")
	}

	evt := Event{
		Type:    "target.discovered",
		Source:  "scanner",
		Target:  "http://example.com",
		Payload: map[string]string{"ip": "192.168.1.1"},
	}

	err = bus.Publish(context.Background(), evt)
	if err != nil {
		t.Fatalf("expected no error on Publish, got %v", err)
	}

	mu.Lock()
	if len(received) != 1 {
		t.Fatalf("expected 1 event, got %d", len(received))
	}
	if received[0].Target != "http://example.com" {
		t.Errorf("expected target http://example.com, got %s", received[0].Target)
	}
	if received[0].ID == "" {
		t.Errorf("expected auto-generated event ID")
	}
	if received[0].Timestamp.IsZero() {
		t.Errorf("expected auto-generated timestamp")
	}
	mu.Unlock()
}

func TestEventBus_WildcardSubscription(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	var count int32

	_, err := bus.Subscribe(EventTypeWildcard, func(ctx context.Context, event Event) error {
		atomic.AddInt32(&count, 1)
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_ = bus.Publish(context.Background(), Event{Type: "tool.requested"})
	_ = bus.Publish(context.Background(), Event{Type: "vulnerability.found"})

	if atomic.LoadInt32(&count) != 2 {
		t.Errorf("expected wildcard handler to receive 2 events, got %d", count)
	}
}

func TestEventBus_SubscribeAsync(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	done := make(chan Event, 1)

	sub, err := bus.SubscribeAsync("tool.executed", func(ctx context.Context, event Event) error {
		done <- event
		return nil
	}, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sub == nil {
		t.Fatalf("expected valid subscription handle")
	}

	err = bus.Publish(context.Background(), Event{Type: "tool.executed", Target: "target1"})
	if err != nil {
		t.Fatalf("unexpected error publishing: %v", err)
	}

	select {
	case evt := <-done:
		if evt.Target != "target1" {
			t.Errorf("expected target1, got %s", evt.Target)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for async event delivery")
	}

	// Test default buffer size when bufferSize <= 0
	sub2, err := bus.SubscribeAsync("default.buffer", func(ctx context.Context, event Event) error { return nil }, 0)
	if err != nil || sub2 == nil {
		t.Fatalf("expected sub2 to succeed with default buffer size")
	}
}

func TestEventBus_Unsubscribe(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	var count int32
	handler := func(ctx context.Context, event Event) error {
		atomic.AddInt32(&count, 1)
		return nil
	}

	sub, err := bus.Subscribe("test.event", handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_ = bus.Publish(context.Background(), Event{Type: "test.event"})
	if atomic.LoadInt32(&count) != 1 {
		t.Errorf("expected 1 event before unsubscribe, got %d", count)
	}

	err = bus.Unsubscribe(sub)
	if err != nil {
		t.Fatalf("unexpected error unsubscribing: %v", err)
	}

	_ = bus.Publish(context.Background(), Event{Type: "test.event"})
	if atomic.LoadInt32(&count) != 1 {
		t.Errorf("expected count to remain 1 after unsubscribe, got %d", count)
	}
}

func TestEventBus_Middleware(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	var trace []string
	var mu sync.Mutex

	bus.Use(func(next Handler) Handler {
		return func(ctx context.Context, event Event) error {
			mu.Lock()
			trace = append(trace, "middleware_before")
			mu.Unlock()
			err := next(ctx, event)
			mu.Lock()
			trace = append(trace, "middleware_after")
			mu.Unlock()
			return err
		}
	})

	_, _ = bus.Subscribe("custom.event", func(ctx context.Context, event Event) error {
		mu.Lock()
		trace = append(trace, "handler")
		mu.Unlock()
		return nil
	})

	_ = bus.Publish(context.Background(), Event{Type: "custom.event"})

	mu.Lock()
	if len(trace) != 3 || trace[0] != "middleware_before" || trace[1] != "handler" || trace[2] != "middleware_after" {
		t.Errorf("unexpected middleware execution order: %v", trace)
	}
	mu.Unlock()
}

func TestEventBus_History(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	_ = bus.Publish(context.Background(), Event{Type: "e1"})
	_ = bus.Publish(context.Background(), Event{Type: "e2"})
	_ = bus.Publish(context.Background(), Event{Type: "e3"})

	bus.SetHistoryCapacity(2)

	h := bus.History()
	if len(h) != 2 {
		t.Fatalf("expected history size 2, got %d", len(h))
	}
	if h[0].Type != "e2" || h[1].Type != "e3" {
		t.Errorf("unexpected history items: %v", h)
	}

	bus.ClearHistory()
	if len(bus.History()) != 0 {
		t.Errorf("expected empty history after ClearHistory")
	}
}

func TestEventBus_AsyncPublishTimeout(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	// Create async subscriber with buffer size 1 that blocks
	sub, _ := bus.SubscribeAsync("full.channel", func(ctx context.Context, event Event) error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}, 1)

	// Fill buffer
	_ = bus.Publish(context.Background(), Event{Type: "full.channel"})
	_ = bus.Publish(context.Background(), Event{Type: "full.channel"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := bus.Publish(ctx, Event{Type: "full.channel"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}

	_ = bus.Unsubscribe(sub)
}

func TestEventBus_ErrorsAndEdgeCases(t *testing.T) {
	bus := NewEventBus()

	_, err := bus.Subscribe("ev", nil)
	if err == nil {
		t.Error("expected error subscribing with nil handler")
	}

	_, err = bus.SubscribeAsync("ev", nil, 10)
	if err == nil {
		t.Error("expected error subscribing async with nil handler")
	}

	err = bus.Unsubscribe(nil)
	if err == nil {
		t.Error("expected error unsubscribing nil subscription")
	}

	fakeSub := &Subscription{ID: "fake_id", EventType: "ev"}
	err = bus.Unsubscribe(fakeSub)
	if err == nil {
		t.Error("expected error unsubscribing non-existent subscription")
	}

	// Unsubscribe from type with wrong ID
	sub, _ := bus.Subscribe("ev2", func(ctx context.Context, event Event) error { return nil })
	err = bus.Unsubscribe(&Subscription{ID: "wrong_id", EventType: "ev2"})
	if err == nil {
		t.Error("expected error unsubscribing wrong sub ID")
	}
	_ = bus.Unsubscribe(sub)

	// Handler returning error
	targetErr := errors.New("handler failed")
	_, _ = bus.Subscribe("err.event", func(ctx context.Context, event Event) error {
		return targetErr
	})

	err = bus.Publish(context.Background(), Event{Type: "err.event"})
	if !errors.Is(err, targetErr) {
		t.Errorf("expected handler error %v, got %v", targetErr, err)
	}

	// Close bus and test operation after close
	_ = bus.Close()
	_ = bus.Close() // Idempotent close

	_, err = bus.Subscribe("ev", func(ctx context.Context, event Event) error { return nil })
	if err == nil {
		t.Error("expected error subscribing to closed bus")
	}

	err = bus.Publish(context.Background(), Event{Type: "ev"})
	if err == nil {
		t.Error("expected error publishing to closed bus")
	}
}
