package matrix

import "time"

type Decision struct {
	UseCase              string `json:"use_case"`
	Technique            string `json:"technique"`
	Function             string `json:"function"`
	ProblemTheToolSolves string `json:"problem_the_tool_solves"`
	Identifier           string `json:"identifier"`
}

type DecisionData struct {
	Decisions []Decision `json:"decisions"`
}

type ExecutionResult struct {
	DecisionSelected Decision
	ResultData       string
	Timestamp        time.Time
}
