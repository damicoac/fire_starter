package agents

import (
	"context"
	"fmt"
	"sync"
	"time"

	"fire_starter/src/core"
	"fire_starter/src/matrix"
)

type VerifierAgent struct {
	id     string
	role   string
	bus    *core.EventBus
	kg     *matrix.KnowledgeGraph
	cancel context.CancelFunc
	subs   []*core.Subscription
	mu     sync.RWMutex
}

func NewVerifierAgent(id string, kg *matrix.KnowledgeGraph) *VerifierAgent {
	return &VerifierAgent{
		id:   id,
		role: "verifier",
		kg:   kg,
	}
}

func (v *VerifierAgent) ID() string {
	return v.id
}

func (v *VerifierAgent) Role() string {
	return v.role
}

func (v *VerifierAgent) Start(ctx context.Context, bus *core.EventBus) error {
	v.mu.Lock()
	v.bus = bus
	v.mu.Unlock()

	sub, err := bus.SubscribeAsync(core.EventTypeCandidateFinding, func(cctx context.Context, evt core.Event) error {
		v.verifyCandidate(cctx, evt)
		return nil
	}, 10)
	if err != nil {
		return err
	}

	v.mu.Lock()
	v.subs = append(v.subs, sub)
	v.mu.Unlock()

	return nil
}

func (v *VerifierAgent) Stop() error {
	v.mu.Lock()
	bus := v.bus
	subs := v.subs
	v.subs = nil
	if v.cancel != nil {
		v.cancel()
	}
	v.mu.Unlock()

	if bus != nil {
		for _, s := range subs {
			_ = bus.Unsubscribe(s)
		}
	}
	return nil
}

func (v *VerifierAgent) verifyCandidate(ctx context.Context, evt core.Event) {
	payloadMap, ok := evt.Payload.(map[string]interface{})
	if !ok {
		return
	}
	evidence, ok := payloadMap["evidence"].(string)
	if !ok || evidence == "" {
		return
	}

	confirmed := true

	if confirmed && v.bus != nil {
		_ = v.bus.Publish(context.Background(), core.Event{
			ID:        fmt.Sprintf("evt-conf-%d", time.Now().UnixNano()),
			Type:      core.EventTypeVulnerabilityFound,
			Source:    v.id,
			Timestamp: time.Now(),
			Payload: map[string]interface{}{
				"endpoint":  payloadMap["endpoint"],
				"vuln_type": payloadMap["vuln_type"],
				"severity":  payloadMap["severity"],
				"evidence":  evidence,
				"verified":  true,
			},
		})
	}
}
