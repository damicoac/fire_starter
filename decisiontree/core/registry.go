// File overview:
// Global node/tool registry management. It provides centralized discovery and initialization so features can self-register without manual wiring in every caller.

package core

import "sync"

var (
	registryMu    sync.RWMutex
	registeredSet []ToolDefinition
)

func RegisterTool(tool ToolDefinition) error {
	if err := validateTool(tool); err != nil {
		return err
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	registeredSet = append(registeredSet, tool)
	return nil
}

func RegisterNode(name string, condition ToolCondition, run ToolFunc) error {
	return RegisterTool(ToolDefinition{
		Name:      name,
		Condition: condition,
		Run:       run,
	})
}

func MustRegisterTool(tool ToolDefinition) {
	err := RegisterTool(tool)
	if err != nil {
		panic(err)
	}
}

func MustRegisterNode(name string, condition ToolCondition, run ToolFunc) {
	err := RegisterNode(name, condition, run)
	if err != nil {
		panic(err)
	}
}

func RegisteredTools() []ToolDefinition {
	registryMu.RLock()
	defer registryMu.RUnlock()

	tools := make([]ToolDefinition, len(registeredSet))
	copy(tools, registeredSet)
	return tools
}

func SnapshotRegisteredTools() []ToolDefinition {
	return RegisteredTools()
}

func ReplaceRegisteredTools(tools []ToolDefinition) {
	registryMu.Lock()
	defer registryMu.Unlock()

	registeredSet = append([]ToolDefinition(nil), tools...)
}
