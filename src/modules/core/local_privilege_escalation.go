package core

import (
	"context"
	"fmt"
)

type LocalPrivilegeEscalation struct {
	*BaseModule
	Target string
}

func NewLocalPrivilegeEscalation(target string) *LocalPrivilegeEscalation {
	return &LocalPrivilegeEscalation{
		BaseModule: NewBaseModule(),
		Target:     target,
	}
}

func (m *LocalPrivilegeEscalation) Execute(ctx context.Context) ([]string, error) {
	return []string{
		"to be implemented",
	}, nil
}

func init() {
	RegisterModule("local_privilege_escalation", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "ip", "127.0.0.1")
		onLog(fmt.Sprintf("Starting LocalPrivilegeEscalation on: %s", target))

		tester := NewLocalPrivilegeEscalation(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
