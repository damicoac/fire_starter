package agents

import (
	"context"
	"fmt"
	"sync"
	"time"

	"fire_starter/src/core"
	"fire_starter/src/matrix"
)

type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"
	TaskRunning   TaskStatus = "running"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
)

type SubTask struct {
	ID          string                 `json:"id"`
	Role        string                 `json:"role"`
	Action      string                 `json:"action"`
	Target      string                 `json:"target"`
	Params      map[string]interface{} `json:"params"`
	Status      TaskStatus             `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	CompletedAt time.Time              `json:"completed_at,omitempty"`
	Result      string                 `json:"result,omitempty"`
}

type CommanderAgent struct {
	id     string
	role   string
	bus    *core.EventBus
	kg     *matrix.KnowledgeGraph
	tasks  map[string]*SubTask
	subs   []*core.Subscription
	mu     sync.RWMutex
	cancel context.CancelFunc
}

func NewCommanderAgent(id string, kg *matrix.KnowledgeGraph) *CommanderAgent {
	return &CommanderAgent{
		id:    id,
		role:  "commander",
		kg:    kg,
		tasks: make(map[string]*SubTask),
	}
}

func (c *CommanderAgent) ID() string {
	return c.id
}

func (c *CommanderAgent) Role() string {
	return c.role
}

func (c *CommanderAgent) Start(ctx context.Context, bus *core.EventBus) error {
	c.mu.Lock()
	c.bus = bus
	c.mu.Unlock()

	sub1, err := bus.SubscribeAsync(core.EventTypeTargetDiscovered, func(cctx context.Context, evt core.Event) error {
		c.handleTargetDiscovered(cctx, evt)
		return nil
	}, 10)
	if err != nil {
		return err
	}

	sub2, err := bus.SubscribeAsync(core.EventTypeEndpointFound, func(cctx context.Context, evt core.Event) error {
		c.handleEndpointFound(cctx, evt)
		return nil
	}, 10)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.subs = append(c.subs, sub1, sub2)
	c.mu.Unlock()

	return nil
}

func (c *CommanderAgent) Stop() error {
	c.mu.Lock()
	bus := c.bus
	subs := c.subs
	c.subs = nil
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()

	if bus != nil {
		for _, s := range subs {
			_ = bus.Unsubscribe(s)
		}
	}
	return nil
}

func (c *CommanderAgent) DelegateTask(role string, action string, target string, params map[string]interface{}) *SubTask {
	c.mu.Lock()
	taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	task := &SubTask{
		ID:        taskID,
		Role:      role,
		Action:    action,
		Target:    target,
		Params:    params,
		Status:    TaskPending,
		CreatedAt: time.Now(),
	}
	c.tasks[taskID] = task
	bus := c.bus
	commanderID := c.id
	c.mu.Unlock()

	if bus != nil {
		_ = bus.Publish(context.Background(), core.Event{
			ID:        fmt.Sprintf("evt-del-%s", taskID),
			Type:      core.EventTypeTaskDelegated,
			Source:    commanderID,
			Timestamp: time.Now(),
			Payload: map[string]interface{}{
				"task_id": taskID,
				"role":    role,
				"action":  action,
				"target":  target,
				"params":  params,
			},
		})
	}

	return task
}

func (c *CommanderAgent) handleTargetDiscovered(ctx context.Context, evt core.Event) {
	payloadMap, ok := evt.Payload.(map[string]interface{})
	if !ok {
		return
	}
	target, _ := payloadMap["target"].(string)
	if target == "" {
		return
	}
	c.DelegateTask("recon", "enumerate", target, map[string]interface{}{"depth": "full"})
}

func (c *CommanderAgent) handleEndpointFound(ctx context.Context, evt core.Event) {
	payloadMap, ok := evt.Payload.(map[string]interface{})
	if !ok {
		return
	}
	endpoint, _ := payloadMap["endpoint"].(string)
	if endpoint == "" {
		return
	}
	c.DelegateTask("exploit", "assess_vulnerabilities", endpoint, map[string]interface{}{"endpoint": endpoint})
}

func (c *CommanderAgent) TaskCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.tasks)
}
