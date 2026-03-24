package core

func ExecutionSummary(executions []ToolExecution) map[string]any {
	summary := map[string]any{
		"total":      len(executions),
		"successful": 0,
		"failed":     0,
		"errors":     []string{},
	}

	errors := make([]string, 0)
	successful := 0
	for _, execution := range executions {
		if execution.Success {
			successful++
			continue
		}
		if execution.Error != "" {
			errors = append(errors, execution.Tool+"::"+execution.Function+": "+execution.Error)
		}
	}

	summary["successful"] = successful
	summary["failed"] = len(executions) - successful
	summary["errors"] = errors
	return summary
}
