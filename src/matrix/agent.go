package matrix

import (
	"math/rand"
	"time"
)

// Agent defines the interface for an MCP client proposing actions.
type Agent interface {
	ProposeDecisions(history []ExecutionResult, available []Decision, count int, kg *KnowledgeGraph) []Decision
}

// MockAgent provides a simulated implementation for early runloop testing.
type MockAgent struct {
	rng *rand.Rand
}

func NewMockAgent() *MockAgent {
	return &MockAgent{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ProposeDecisions creates a randomized list of count decisions to simulate an LLM's proposals.
func (m *MockAgent) ProposeDecisions(history []ExecutionResult, available []Decision, count int, kg *KnowledgeGraph) []Decision {
	if len(available) == 0 {
		return nil
	}

	shuffled := make([]Decision, len(available))
	copy(shuffled, available)

	m.rng.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	if count > len(shuffled) {
		count = len(shuffled)
	}

	return shuffled[:count]
}
