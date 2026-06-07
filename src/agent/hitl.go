package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"charm.land/fantasy"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/log"

	"fire_starter/src/matrix"
	"fire_starter/src/tui"
)

func BuildHITLModel(ctx context.Context, target string, cfg Config) (*tea.Program, error) {
	llmModel, err := initializeModel(ctx, cfg)
	if err != nil {
		return nil, err
	}

	decisionsFile := "src/matrix/decisions.json"
	bytes, err := matrix.ReadDecisionsFile(decisionsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read decisions.json: %w", err)
	}

	var data matrix.DecisionData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("error parsing decisions JSON: %w", err)
	}

	executor, err := matrix.NewRealExecutor(data.Decisions)
	if err != nil {
		return nil, fmt.Errorf("failed to init executor: %w", err)
	}

	kg := matrix.NewKnowledgeGraph()

	// Initial target load
	ips := extractIPsFromTarget(target)
	if net.ParseIP(target) != nil {
		kg.AddIP(target)
	} else {
		kg.AddURL(target)
	}
	for _, ip := range ips {
		kg.AddIP(ip)
	}

	var p *tea.Program

	kg.OnUpdate = func(graph *matrix.KnowledgeGraph) {
		if p != nil {
			b, err := graph.ToJSON()
			if err == nil {
				p.Send(tui.KGUpdateMsg{Data: b})
			}
		}
	}

	executeFn := func(moduleName, target string) tea.Msg {
		payload := make(map[string]any)
		
		var toolDef *matrix.ToolDefinition
		for _, t := range executor.Tools() {
			if t.Name == moduleName {
				toolDef = &t
				break
			}
		}

		if toolDef != nil {
			if props, ok := toolDef.InputSchema["properties"].(map[string]any); ok {
				if _, ok := props["url"]; ok {
					payload["url"] = target
				}
				if _, ok := props["ip"]; ok {
					payload["ip"] = target
				}
				if _, ok := props["target"]; ok {
					payload["target"] = target
				}
				// Default to target if none matched
				if len(payload) == 0 {
					payload["target"] = target
				}
			} else {
				payload["target"] = target
			}
		} else {
			payload["target"] = target
		}

		resultData, execErr := executor.ExecuteByToolName(moduleName, payload, func(s string) {
			log.Debug(s)
		})

		if execErr != nil {
			return tui.ExecutionResultMsg{Err: execErr}
		}

		var intelStr string
		summary, extractErr := kg.ExtractIntelligence(ctx, llmModel, moduleName, target, payload, resultData)
		if extractErr != nil {
			intelStr = fmt.Sprintf("Intelligence extraction failed: %v", extractErr)
			log.Warn(intelStr)
		} else {
			intelStr = fmt.Sprintf("Intelligence Extracted: %s", summary)
			log.Info(intelStr)
		}

		return tui.ExecutionResultMsg{Result: resultData, Intelligence: intelStr}
	}

	recommendFn := func(target string) tea.Msg {
		kgJSON, _ := kg.ToJSON()
		var toolDescs []string
		for _, t := range executor.Tools() {
			toolDescs = append(toolDescs, fmt.Sprintf("- %s: %s", t.Name, t.Description))
		}

		prompt := fmt.Sprintf(`You are an intelligent security testing agent. Based on the following Knowledge Graph state, recommend up to 5 security testing modules from the available tools to run next against the target '%s'.

Knowledge Graph:
%s

Available Tools:
%s

You MUST call the 'submit_recommendations' tool with your top 5 recommendations. Provide a reason for each.`, target, string(kgJSON), strings.Join(toolDescs, "\n"))

		activeTools := []fantasy.Tool{
			fantasy.FunctionTool{
				Name:        "submit_recommendations",
				Description: "Submit recommended tools to run next.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"recommendations": map[string]any{
							"type": "array",
							"items": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"tool_name": map[string]any{"type": "string"},
									"reason":    map[string]any{"type": "string"},
								},
								"required": []string{"tool_name", "reason"},
							},
						},
					},
					"required": []string{"recommendations"},
				},
			},
		}

		resp, err := llmModel.Generate(ctx, fantasy.Call{
			Prompt: []fantasy.Message{
				fantasy.NewUserMessage(prompt),
			},
			Tools: activeTools,
		})

		var recs []tui.Recommendation
		if err == nil {
			for _, tc := range resp.Content.ToolCalls() {
				if tc.ToolName == "submit_recommendations" {
					var args map[string]any
					if err := json.Unmarshal([]byte(tc.Input), &args); err == nil {
						if recList, ok := args["recommendations"].([]any); ok {
							for _, r := range recList {
								if rMap, ok := r.(map[string]any); ok {
									name, _ := rMap["tool_name"].(string)
									reason, _ := rMap["reason"].(string)
									if name != "" {
										recs = append(recs, tui.Recommendation{
											Name:        name,
											Description: fmt.Sprintf("Use Case: %s", reason),
										})
									}
								}
							}
						}
					}
				}
			}
		}

		if len(recs) == 0 {
			snapshot := kg.Snapshot()
			scored := make([]scoredTool, 0)
			for _, t := range executor.Tools() {
				st := scoreTool(t, snapshot.CurrentPhase, snapshot, false)
				scored = append(scored, st)
			}

			sort.SliceStable(scored, func(i, j int) bool {
				if scored[i].Score == scored[j].Score {
					return scored[i].Definition.Identifier < scored[j].Definition.Identifier
				}
				return scored[i].Score > scored[j].Score
			})

			numChoices := len(scored)
			if numChoices > 5 {
				numChoices = 5
			}
			for i := 0; i < numChoices; i++ {
				c := scored[i]
				recs = append(recs, tui.Recommendation{
					Name:        c.Definition.Name,
					Description: fmt.Sprintf("Score: %d\n\n%s", c.Score, c.Definition.Description),
				})
			}
		}

		return tui.RecommendationsMsg{Recommendations: recs}
	}

	reportFn := func() tea.Msg {
		kgJSON, _ := kg.ToJSON()
		prompt := fmt.Sprintf(`You are an intelligent security testing agent. Based on the following Knowledge Graph state, generate a comprehensive security assessment report. Summarize the findings and provide actionable recommendations.

Knowledge Graph:
%s`, string(kgJSON))
		
		resp, err := llmModel.Generate(ctx, fantasy.Call{
			Prompt: []fantasy.Message{
				fantasy.NewUserMessage(prompt),
			},
		})

		if err != nil {
			return tui.ExecutionResultMsg{Err: fmt.Errorf("report generation failed: %v", err)}
		}

		var reportStr string
		for _, c := range resp.Content {
			if txt, ok := c.(fantasy.TextContent); ok {
				reportStr += txt.Text
			}
		}

		reportStr += "\n\n## Appendix: Knowledge Graph Dump\n\n```json\n" + string(kgJSON) + "\n```\n"

		reportPath := "fire_starter_report.md"
		if err := os.WriteFile(reportPath, []byte(reportStr), 0644); err != nil {
			return tui.ExecutionResultMsg{Err: fmt.Errorf("failed to save report: %v", err)}
		}

		return tui.ExecutionResultMsg{Result: fmt.Sprintf("Report successfully saved to: %s", reportPath)}
	}

	m := tui.InitialHITLModel(executeFn, recommendFn, reportFn)
	p = tea.NewProgram(m, tea.WithAltScreen())

	// Send initial data
	go func() {
		// Modules
		var modules []tui.HITLModule
		for _, t := range executor.Tools() {
			modules = append(modules, tui.HITLModule{Name: t.Name, Description: t.Description})
		}
		p.Send(tui.ModulesLoadedMsg{Modules: modules})

		// KG
		b, _ := kg.ToJSON()
		p.Send(tui.KGUpdateMsg{Data: b})
	}()

	return p, nil
}
