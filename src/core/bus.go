package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// Common event type constants for Fire Starter v2.
const (
	EventTypeWildcard              = "*"
	EventTypeTargetDiscovered      = "target.discovered"
	EventTypeTargetUpdated         = "target.updated"
	EventTypeToolRequested         = "tool.requested"
	EventTypeToolExecuted          = "tool.executed"
	EventTypeToolFailed            = "tool.failed"
	EventTypeIntelligenceExtracted = "intelligence.extracted"
	EventTypeVulnerabilityFound    = "vulnerability.found"
	EventTypeEndpointFound         = "endpoint.found"
	EventTypeTaskDelegated         = "task.delegated"
	EventTypeCandidateFinding      = "finding.candidate"
	EventTypePhaseChanged          = "phase.changed"
	EventTypeKGUpdated             = "kg.updated"
	EventTypeAgentStateChanged     = "agent.state_changed"
)

// Event represents a system event emitted within Fire Starter v2.
type Event struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Source    string            `json:"source"`
	Target    string            `json:"target,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Payload   any               `json:"payload,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Handler is a function that processes an event.
type Handler func(ctx context.Context, event Event) error

// MiddlewareFunc wraps a Handler for cross-cutting concerns (logging, metrics, tracing).
type MiddlewareFunc func(next Handler) Handler

// Subscription represents an active subscription to the EventBus.
type Subscription struct {
	ID        string
	EventType string
	handler   Handler
	async     bool
	eventChan chan Event
	ctx       context.Context
	cancel    context.CancelFunc
}

// EventBus manages event subscriptions and publishing across Fire Starter components.
type EventBus struct {
	mu            sync.RWMutex
	subscriptions map[string]map[string]*Subscription // eventType -> subscriptionID -> Subscription
	middlewares   []MiddlewareFunc
	history       []Event
	historyCap    int
	closed        bool
	subCounter    uint64
}

// NewEventBus creates a new initialized EventBus.
func NewEventBus() *EventBus {
	return &EventBus{
		subscriptions: make(map[string]map[string]*Subscription),
		historyCap:    1000,
	}
}

// Use adds middleware to the EventBus execution pipeline.
func (b *EventBus) Use(middlewares ...MiddlewareFunc) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.middlewares = append(b.middlewares, middlewares...)
}

// SetHistoryCapacity adjusts the maximum number of recorded events in history.
func (b *EventBus) SetHistoryCapacity(cap int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.historyCap = cap
	if len(b.history) > cap {
		b.history = b.history[len(b.history)-cap:]
	}
}

// History returns a copy of recorded events.
func (b *EventBus) History() []Event {
	b.mu.RLock()
	defer b.mu.RUnlock()
	cp := make([]Event, len(b.history))
	copy(cp, b.history)
	return cp
}

// ClearHistory clears the recorded event history.
func (b *EventBus) ClearHistory() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.history = nil
}

// Subscribe registers a synchronous handler for a specific event type (or EventTypeWildcard).
func (b *EventBus) Subscribe(eventType string, handler Handler) (*Subscription, error) {
	if handler == nil {
		return nil, errors.New("handler cannot be nil")
	}
	return b.subscribeInternal(eventType, handler, false, 0)
}

// SubscribeAsync registers an asynchronous handler for a specific event type with a buffered channel.
func (b *EventBus) SubscribeAsync(eventType string, handler Handler, bufferSize int) (*Subscription, error) {
	if handler == nil {
		return nil, errors.New("handler cannot be nil")
	}
	if bufferSize <= 0 {
		bufferSize = 64
	}
	return b.subscribeInternal(eventType, handler, true, bufferSize)
}

func (b *EventBus) subscribeInternal(eventType string, handler Handler, async bool, bufferSize int) (*Subscription, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, errors.New("event bus is closed")
	}

	b.subCounter++
	subID := fmt.Sprintf("sub_%d_%d", time.Now().UnixNano(), b.subCounter)

	sub := &Subscription{
		ID:        subID,
		EventType: eventType,
		handler:   handler,
		async:     async,
	}

	if async {
		ctx, cancel := context.WithCancel(context.Background())
		sub.ctx = ctx
		sub.cancel = cancel
		sub.eventChan = make(chan Event, bufferSize)

		go b.runAsyncWorker(sub)
	}

	if _, exists := b.subscriptions[eventType]; !exists {
		b.subscriptions[eventType] = make(map[string]*Subscription)
	}
	b.subscriptions[eventType][subID] = sub

	return sub, nil
}

func (b *EventBus) runAsyncWorker(sub *Subscription) {
	for {
		select {
		case <-sub.ctx.Done():
			return
		case event, ok := <-sub.eventChan:
			if !ok {
				return
			}
			pipeline := b.buildPipeline(sub.handler)
			if err := pipeline(sub.ctx, event); err != nil {
				// Use the standard log package or pass in a logger. For now, log.Printf
				log.Printf("EventBus: pipeline error for event %s: %v", event.Type, err)
			}
		}
	}
}

// Unsubscribe removes a subscription from the EventBus.
func (b *EventBus) Unsubscribe(sub *Subscription) error {
	if sub == nil {
		return errors.New("subscription cannot be nil")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	subsForType, exists := b.subscriptions[sub.EventType]
	if !exists {
		return fmt.Errorf("subscription %s not found", sub.ID)
	}

	targetSub, found := subsForType[sub.ID]
	if !found {
		return fmt.Errorf("subscription %s not found", sub.ID)
	}

	if targetSub.async && targetSub.cancel != nil {
		targetSub.cancel()
	}

	delete(subsForType, sub.ID)
	if len(subsForType) == 0 {
		delete(b.subscriptions, sub.EventType)
	}

	return nil
}

// Publish dispatches an event to all matching subscribers synchronously and asynchronously.
func (b *EventBus) Publish(ctx context.Context, event Event) error {
	if ctx == nil {
		ctx = context.Background()
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return errors.New("event bus is closed")
	}

	if event.ID == "" {
		event.ID = fmt.Sprintf("evt_%d", time.Now().UnixNano())
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	if b.historyCap > 0 {
		b.history = append(b.history, event)
		if len(b.history) > b.historyCap {
			b.history = b.history[1:]
		}
	}

	// Gather matching subscribers (exact match + wildcard match)
	var targets []*Subscription
	if exact, ok := b.subscriptions[event.Type]; ok {
		for _, sub := range exact {
			targets = append(targets, sub)
		}
	}
	if event.Type != EventTypeWildcard {
		if wildcard, ok := b.subscriptions[EventTypeWildcard]; ok {
			for _, sub := range wildcard {
				targets = append(targets, sub)
			}
		}
	}

	middlewares := make([]MiddlewareFunc, len(b.middlewares))
	copy(middlewares, b.middlewares)

	b.mu.Unlock()

	var firstErr error
	for _, sub := range targets {
		if sub.async {
			select {
			case sub.eventChan <- event:
			case <-ctx.Done():
				if firstErr == nil {
					firstErr = ctx.Err()
				}
			}
		} else {
			pipeline := b.chainMiddlewares(sub.handler, middlewares)
			if err := pipeline(ctx, event); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}

	return firstErr
}

// Close shuts down the event bus and cancels all async subscription workers.
func (b *EventBus) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	for _, subs := range b.subscriptions {
		for _, sub := range subs {
			if sub.async {
				if sub.cancel != nil {
					sub.cancel()
				}
				close(sub.eventChan)
			}
		}
	}

	b.subscriptions = make(map[string]map[string]*Subscription)
	return nil
}

func (b *EventBus) buildPipeline(handler Handler) Handler {
	b.mu.RLock()
	middlewares := make([]MiddlewareFunc, len(b.middlewares))
	copy(middlewares, b.middlewares)
	b.mu.RUnlock()

	return b.chainMiddlewares(handler, middlewares)
}

func (b *EventBus) chainMiddlewares(handler Handler, middlewares []MiddlewareFunc) Handler {
	current := handler
	for i := len(middlewares) - 1; i >= 0; i-- {
		current = middlewares[i](current)
	}
	return current
}
