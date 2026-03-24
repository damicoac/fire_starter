package decisiontree

import (
	"context"
	"errors"
)

type StageObserver interface {
	OnStageCompleted(ctx context.Context, input ThirdPartyInput, result *ToolResult) error
}

// Run executes the full loop until resolver indicates no further processing.
func (t *Tree) Run(ctx context.Context, initial ThirdPartyInput, resolve NextInputResolver) error {
	return t.RunWithObserver(ctx, initial, resolve, nil)
}

func (t *Tree) RunWithObserver(ctx context.Context, initial ThirdPartyInput, resolve NextInputResolver, observer StageObserver) error {
	if resolve == nil {
		return errors.New("next input resolver is required")
	}

	current := initial
	for {
		tool, err := t.SelectTool(current)
		if err != nil {
			t.logger.Error("tool selection failed", "stage", current.Stage, "err", err)
			return err
		}

		t.logger.Info("tool selected", "tool", tool.Name, "stage", current.Stage)
		result, err := tool.Run(ctx, current)
		if err != nil {
			t.logger.Error("tool execution failed", "tool", tool.Name, "stage", current.Stage, "err", err)
			return err
		}

		if observer != nil {
			err = observer.OnStageCompleted(ctx, current, &result)
			if err != nil {
				t.logger.Error("stage observer failed", "tool", result.ToolName, "stage", current.Stage, "err", err)
				return err
			}
		}

		t.logger.Info("tool completed", "tool", result.ToolName)
		next, continueFlow, err := resolve(ctx, result)
		if err != nil {
			t.logger.Error("resolver failed", "tool", result.ToolName, "err", err)
			return err
		}
		if !continueFlow {
			t.logger.Info("decision flow complete", "last_tool", result.ToolName)
			return nil
		}

		current = next
	}
}
