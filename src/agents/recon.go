package agents

import (
	"context"
	"fmt"
	"sync"
	"time"

	"fire_starter/src/core"
	"fire_starter/src/matrix"
)

type ReconAgent struct {
	id     string
	role   string
	bus    *core.EventBus
	kg     *matrix.KnowledgeGraph
	cancel context.CancelFunc
	subs   []*core.Subscription
	mu     sync.RWMutex
}

func NewReconAgent(id string, kg *matrix.KnowledgeGraph) *ReconAgent {
	return &ReconAgent{
		id:   id,
		role: "recon",
		kg:   kg,
	}
}

func (r *ReconAgent) ID() string {
	return r.id
}

func (r *ReconAgent) Role() string {
	return r.role
}

func (r *ReconAgent) Start(ctx context.Context, bus *core.EventBus) error {
	r.mu.Lock()
	r.bus = bus
	r.mu.Unlock()

	sub, err := bus.SubscribeAsync(core.EventTypeTaskDelegated, func(cctx context.Context, evt core.Event) error {
		r.handleTask(cctx, evt)
		return nil
	}, 10)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.subs = append(r.subs, sub)
	r.mu.Unlock()

	return nil
}

func (r *ReconAgent) Stop() error {
	r.mu.Lock()
	bus := r.bus
	subs := r.subs
	r.subs = nil
	if r.cancel != nil {
		r.cancel()
	}
	r.mu.Unlock()

	if bus != nil {
		for _, s := range subs {
			_ = bus.Unsubscribe(s)
		}
	}
	return nil
}

func (r *ReconAgent) handleTask(ctx context.Context, evt core.Event) {
	payloadMap, ok := evt.Payload.(map[string]interface{})
	if !ok {
		return
	}
	role, _ := payloadMap["role"].(string)
	if role != "recon" {
		return
	}
	target, _ := payloadMap["target"].(string)
	if target == "" {
		return
	}

	if r.bus != nil {
		_ = r.bus.Publish(context.Background(), core.Event{
			ID:        fmt.Sprintf("evt-ep-%d", time.Now().UnixNano()),
			Type:      core.EventTypeEndpointFound,
			Source:    r.id,
			Timestamp: time.Now(),
			Payload: map[string]interface{}{
				"target":   target,
				"endpoint": fmt.Sprintf("%s/api/v1", target),
			},
		})
	}
}
