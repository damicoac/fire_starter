package matrix

import "fmt"

// Executor defines the interface for a tool runner that executes a chosen technique and retrieves results
type Executor interface {
	Execute(decision Decision) (string, error)
}

// MockExecutor simulates external executions for testing the runloop
type MockExecutor struct{}

func NewMockExecutor() *MockExecutor {
	return &MockExecutor{}
}

func (m *MockExecutor) Execute(decision Decision) (string, error) {
	return fmt.Sprintf("Successfully executed mock action %s. Uncovered active vulnerability vector and advanced to next exploit phase.", decision.Technique), nil
}
