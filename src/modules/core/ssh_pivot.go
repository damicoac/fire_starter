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

func (m *SSHPivot) Execute(ctx context.Context) ([]string, error) {
	if m.Username == "" || m.Password == "" {
		return nil, fmt.Errorf("username and password are required for SSH pivot")
	}
	return []string{
		"to be implemented",
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
