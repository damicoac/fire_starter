// File overview:
// Public package facade that re-exports core, feature, and OpenAI integration types/functions. It exists to provide one stable import surface for consumers while allowing internal package organization to evolve.

package decisiontree

import (
	"context"

	"github.com/charmbracelet/log"

	"blackwater/decisiontree/core"
	"blackwater/decisiontree/database"
	openaiintegration "blackwater/decisiontree/integrations/openai"

	_ "blackwater/decisiontree/features/active_testing"
	_ "blackwater/decisiontree/features/api_testing"
	_ "blackwater/decisiontree/features/application_mapping"
	_ "blackwater/decisiontree/features/target"
)

var (
	ErrNoMatchingTool = core.ErrNoMatchingTool
	ErrUnknownTool    = core.ErrUnknownTool
)

type ThirdPartyInput = core.ThirdPartyInput
type ToolResult = core.ToolResult
type ToolFunc = core.ToolFunc
type ToolCondition = core.ToolCondition
type ToolDefinition = core.ToolDefinition
type NextInputResolver = core.NextInputResolver
type ToolDescriptor = core.ToolDescriptor
type ToolCall = core.ToolCall
type Tree = core.Tree
type StageObserver = core.StageObserver
type LLMToolPlanner = core.LLMToolPlanner
type NextToolDecision = core.NextToolDecision
type LLMDecisionModel = core.LLMDecisionModel
type JSONLLMToolPlanner = core.JSONLLMToolPlanner
type ReinforcementLearner = database.ReinforcementLearner
type TransitionStats = database.TransitionStats
type SQLiteReinforcementLearner = database.SQLiteReinforcementLearner
type AuditLogger = database.AuditLogger
type AuditEvent = database.AuditEvent
type SQLiteAuditLogger = database.SQLiteAuditLogger
type StageGuidanceGenerator = openaiintegration.StageGuidanceGenerator
type OpenAIResponsesClient = openaiintegration.OpenAIResponsesClient
type OpenAIStageObserver = openaiintegration.OpenAIStageObserver

func NewTree(logger *log.Logger, tools []ToolDefinition) (*Tree, error) {
	return core.NewTree(logger, tools)
}

func NewTreeFromRegistry(logger *log.Logger) (*Tree, error) {
	return core.NewTreeFromRegistry(logger)
}

func NewTreeWithAuditLogger(logger *log.Logger, tools []ToolDefinition, auditLogger AuditLogger) (*Tree, error) {
	return core.NewTreeWithAuditLogger(logger, tools, auditLogger)
}

func RegisterTool(tool ToolDefinition) error {
	return core.RegisterTool(tool)
}

func RegisterNode(name string, condition ToolCondition, run ToolFunc) error {
	return core.RegisterNode(name, condition, run)
}

func MustRegisterTool(tool ToolDefinition) {
	core.MustRegisterTool(tool)
}

func MustRegisterNode(name string, condition ToolCondition, run ToolFunc) {
	core.MustRegisterNode(name, condition, run)
}

func RegisteredTools() []ToolDefinition {
	return core.RegisteredTools()
}

func DefaultNextInputResolver(ctx context.Context, result ToolResult) (ThirdPartyInput, bool, error) {
	return core.DefaultNextInputResolver(ctx, result)
}

func NewJSONLLMToolPlanner(model LLMDecisionModel) (*JSONLLMToolPlanner, error) {
	return core.NewJSONLLMToolPlanner(model)
}

func NewSQLiteReinforcementLearner(databasePath string) (*SQLiteReinforcementLearner, error) {
	return database.NewSQLiteReinforcementLearner(databasePath)
}

func NewSQLiteAuditLogger(databasePath string) (*SQLiteAuditLogger, error) {
	return database.NewSQLiteAuditLogger(databasePath)
}

func NewOpenAIResponsesClient(apiKey string, model string) (*OpenAIResponsesClient, error) {
	return openaiintegration.NewOpenAIResponsesClient(apiKey, model)
}

func NewOpenAIResponsesClientFromEnv(model string) (*OpenAIResponsesClient, error) {
	return openaiintegration.NewOpenAIResponsesClientFromEnv(model)
}

func NewOpenAIStageObserver(generator StageGuidanceGenerator) (*OpenAIStageObserver, error) {
	return openaiintegration.NewOpenAIStageObserver(generator)
}

func BuildStagePrompt(input ThirdPartyInput, result ToolResult) (string, string, error) {
	return openaiintegration.BuildStagePrompt(input, result)
}

func BuildLLMDecisionPrompt(result ToolResult, tools []ToolDescriptor) (string, error) {
	return core.BuildLLMDecisionPrompt(result, tools)
}

func CopyPayload(payload map[string]any) map[string]any {
	return core.CopyPayload(payload)
}

func snapshotRegisteredTools() []ToolDefinition {
	return core.SnapshotRegisteredTools()
}

func replaceRegisteredTools(tools []ToolDefinition) {
	core.ReplaceRegisteredTools(tools)
}

func getBool(payload map[string]any, key string) bool {
	return core.GetBool(payload, key)
}

const (
	stageTargetReceived         = "target.received"
	stageTargetClassify         = "target.classify"
	stageAPITestingRecon        = "api-testing.recon"
	stageAPITestingAccess       = "api-testing.access-control"
	stageAPITestingRateLimit    = "api-testing.rate-limit"
	stageAPITestingInjection    = "api-testing.injection"
	stageAPITestingGraphQL      = "api-testing.graphql"
	stageAPITestingFuzzing      = "api-testing.fuzzing"
	stageAPITestingComplete     = "api-testing.complete"
	stageApplicationMappingExplore       = "application-mapping.explore"
	stageApplicationMappingEntryPoints   = "application-mapping.entry-points"
	stageApplicationMappingMetadata      = "application-mapping.metadata-review"
	stageApplicationMappingAttackSurface = "application-mapping.attack-surface"
	stageApplicationMappingComplete      = "application-mapping.complete"
	stageActiveTestingAccessControl = "active-testing.access-control"
	stageActiveTestingBusinessLogic = "active-testing.business-logic"
	stageActiveTestingInputProbing  = "active-testing.input-probing"
	stageActiveTestingXSS           = "active-testing.xss"
	stageActiveTestingInjection     = "active-testing.injection"
	stageActiveTestingErrorHandling = "active-testing.error-handling"
	stageActiveTestingConfigChecks  = "active-testing.configuration-checks"
	stageActiveTestingComplete      = "active-testing.complete"
)
