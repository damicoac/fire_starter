// File overview:
// Tool call trace structure used in stage outputs. It preserves execution intent/evidence so downstream reporting and prompts can explain why actions were taken.

package core

type ToolCall struct {
	Tool     string
	Function string
	Purpose  string
}
