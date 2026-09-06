package core

import (
	"context"
	"fmt"
)

type SSHPivot struct {
	*BaseModule
	Target   string
	Username string
	Password string
}

func NewSSHPivot(target, username, password string) *SSHPivot {
	return &SSHPivot{
		BaseModule: NewBaseModule(),
		Target:     target,
		Username:   username,
		Password:   password,
	}
}

type SSHPivotResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func (m *SSHPivot) Execute(ctx context.Context) ([]SSHPivotResult, error) {
	if m.Username == "" || m.Password == "" {
		return []SSHPivotResult{
			{
				Target: m.Target,
				Status: "error",
				Detail: "Username and password are required for SSH pivot.",
			},
		}, nil
	}
	return []SSHPivotResult{
		{
			Target: m.Target,
			Status: "unsupported_environment",
			Detail: "SSH pivot lateral movement is not configured for this target environment.",
		},
	}, nil
}

func init() {
	RegisterModule("ssh_pivot", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "ip", "127.0.0.1")
		username := PayloadString(payload, "username", "")
		password := PayloadString(payload, "password", "")

		onLog(fmt.Sprintf("Starting SSHPivot on: %s with user %s", target, username))

		tester := NewSSHPivot(target, username, password)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
