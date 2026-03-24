// File overview:
// API-testing stage node/constants for the decision tree. This file encodes one bounded step so API security checks remain modular, reorderable, and easy to validate.

package apitesting

const (
	stageAPITestingRecon     = "api-testing.recon"
	stageAPITestingAccess    = "api-testing.access-control"
	stageAPITestingRateLimit = "api-testing.rate-limit"
	stageAPITestingInjection = "api-testing.injection"
	stageAPITestingGraphQL   = "api-testing.graphql"
	stageAPITestingFuzzing   = "api-testing.fuzzing"
	stageAPITestingComplete  = "api-testing.complete"
)

const (
	StageRecon    = stageAPITestingRecon
	StageComplete = stageAPITestingComplete
)
