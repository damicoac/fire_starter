package agent

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"charm.land/fantasy"
	"github.com/charmbracelet/log"

	"fire_starter/src/matrix"
)

func buildConfirmedVulnerabilitiesSummary(vulns []matrix.VulnInfo) string {
	var confirmedFindings []matrix.VulnInfo
	for _, v := range vulns {
		if strings.ToLower(strings.TrimSpace(v.Status)) == matrix.VulnerabilityStatusConfirmed {
			confirmedFindings = append(confirmedFindings, v)
		}
	}

	var sb strings.Builder
	if len(confirmedFindings) > 0 {
		sb.WriteString("Confirmed vulnerabilities detected during this engagement:\n\n")
		for _, v := range confirmedFindings {
			sb.WriteString(fmt.Sprintf("- Target Domain: %s\n  Finding: %s\n  Status: %s\n  Severity: %s\n  Date/Time: %s\n\n", v.TargetDomain, v.Finding, v.Status, v.Severity, v.DateTime.Format(time.RFC3339)))
		}
	} else {
		sb.WriteString("No confirmed vulnerabilities were detected during the assessment.\n\n")
	}
	return sb.String()
}

func buildVulnerabilityReportInput(vulns []matrix.VulnInfo) (string, []matrix.VulnInfo) {
	var confirmedFindings []matrix.VulnInfo
	var informationalFindings []matrix.VulnInfo
	for _, v := range vulns {
		switch strings.ToLower(strings.TrimSpace(v.Status)) {
		case matrix.VulnerabilityStatusConfirmed:
			confirmedFindings = append(confirmedFindings, v)
		case matrix.VulnerabilityStatusInformational:
			informationalFindings = append(informationalFindings, v)
		}
	}

	var sb strings.Builder
	if len(confirmedFindings) > 0 {
		sb.WriteString("Confirmed vulnerabilities detected during this engagement:\n\n")
		for _, v := range confirmedFindings {
			sb.WriteString(fmt.Sprintf("- Target Domain: %s\n  Finding: %s\n  Status: %s\n  Severity: %s\n  Date/Time: %s\n\n", v.TargetDomain, v.Finding, v.Status, v.Severity, v.DateTime.Format(time.RFC3339)))
		}
	} else {
		sb.WriteString("No confirmed vulnerabilities were detected during the assessment.\n\n")
	}
	if len(informationalFindings) > 0 {
		sb.WriteString("Informational findings to append to the final report:\n\n")
		for _, v := range informationalFindings {
			sb.WriteString(fmt.Sprintf("- Target Domain: %s\n  Finding: %s\n  Status: %s\n  Severity: %s\n  Date/Time: %s\n\n", v.TargetDomain, v.Finding, v.Status, v.Severity, v.DateTime.Format(time.RFC3339)))
		}
	} else {
		sb.WriteString("No informational findings were recorded during the assessment.\n")
	}
	return sb.String(), informationalFindings
}

func appendInformationalFindings(reportStr string, informationalFindings []matrix.VulnInfo) string {
	var informationalSection strings.Builder
	informationalSection.WriteString("\n\n## Informational Findings\n\n")
	if len(informationalFindings) == 0 {
		informationalSection.WriteString("No informational findings were recorded.\n")
	} else {
		for _, v := range informationalFindings {
			informationalSection.WriteString(fmt.Sprintf("- **%s** [%s]: %s\n", v.TargetDomain, v.Severity, v.Finding))
		}
	}
	return reportStr + informationalSection.String()
}

// saveTargetReport marks a target as transitioned into the reporting phase in
// the knowledge-graph context.
func saveTargetReport(ctx context.Context, target string, cfg Config, kg *matrix.KnowledgeGraph, model fantasy.LanguageModel) {
	log.Infof("Assessment completed for target: %s. Transitioned to reporting phase.", target)
	if kg != nil {
		kg.SetContextValue(fmt.Sprintf("target_reporting_%s", target), true)
	}
}

// collectReportVulnerabilities loads the final vulnerability list for the
// report. Query failures degrade to a placeholder summary line.
func collectReportVulnerabilities() (string, []matrix.VulnInfo, []matrix.VulnInfo) {
	vulns, err := matrix.GetVulnerabilities()
	if err != nil {
		log.Warnf("Failed to query vulnerabilities: %v", err)
		return "Error retrieving vulnerabilities from database.", nil, nil
	}
	vulnsListStr, informationalFindings := buildVulnerabilityReportInput(vulns)
	return vulnsListStr, informationalFindings, vulns
}

// generateNarrativeReport asks the LLM for the executive narrative and returns
// the concatenated text, or "" when generation failed.
func generateNarrativeReport(ctx context.Context, model fantasy.LanguageModel, vulnsListStr string) string {
	if model == nil {
		return ""
	}
	log.Infof("Generating final executive report via LLM...")
	reportPrompt := fmt.Sprintf("You are an expert security consultant. The red team engagement has concluded. Review the following confirmed vulnerabilities and informational findings. Write a comprehensive final executive summary and technical report. Your report should be formatted in markdown. Do NOT include any reproduction steps, commands, or code in the final report; focus on summarizing the scope, targets, and findings. Do not promote candidate or disproven findings into vulnerabilities.\n\n%s", vulnsListStr)
	resp, err := model.Generate(ctx, fantasy.Call{
		Prompt: []fantasy.Message{
			{Role: "system", Content: []fantasy.MessagePart{fantasy.TextPart{Text: "You write final executive security reports."}}},
			fantasy.NewUserMessage(reportPrompt),
		},
	})
	if err != nil {
		log.Errorf("Failed to generate final report via LLM: %v", err)
		return ""
	}
	var reportStr string
	for _, c := range resp.Content {
		if tc, ok := c.(fantasy.TextContent); ok {
			reportStr += tc.Text
		}
	}
	return reportStr
}

// generateFinalReport produces the final executive report, appends the
// informational findings section and a redacted knowledge-graph dump, and
// writes it to fire_starter_report.md with owner-only permissions (0600) so
// engagement details stay private.
func generateFinalReport(ctx context.Context, env *agentEnv) string {
	vulnsListStr, informationalFindings, vulns := collectReportVulnerabilities()

	reportStr := generateNarrativeReport(ctx, env.model, vulnsListStr)

	if reportStr == "" {
		confirmedSummary := buildConfirmedVulnerabilitiesSummary(vulns)
		reportStr = "# Final Report\n\n**Engagement Completed (Failed to generate narrative report).**\n\n" + confirmedSummary
	}

	reportStr = appendInformationalFindings(reportStr, informationalFindings)

	if rawGraph, err := env.kg.ToRedactedJSON(""); err == nil {
		reportStr += "\n\n## Knowledge Graph Dump\n\n```json\n" + string(rawGraph) + "\n```\n"
	}

	reportPath := "fire_starter_report.md"
	var finalReport string
	if err := os.WriteFile(reportPath, []byte(reportStr), 0600); err != nil {
		log.Errorf("Failed to save report: %v", err)
		finalReport = fmt.Sprintf("Error saving report to %s: %v", reportPath, err)
	} else {
		log.Infof("Saved report to: %s", reportPath)
		finalReport = fmt.Sprintf("Report successfully saved to: %s", reportPath)
	}

	return finalReport
}
