// File overview:
// Active-testing stage node/constants for the decision tree. It structures exploit validation into small verifiable steps to reduce false positives and preserve traceability.

package activetesting

const (
	stageActiveTestingAccessControl = "active-testing.access-control"
	stageActiveTestingBusinessLogic = "active-testing.business-logic"
	stageActiveTestingInputProbing  = "active-testing.input-probing"
	stageActiveTestingXSS           = "active-testing.xss"
	stageActiveTestingInjection     = "active-testing.injection"
	stageActiveTestingErrorHandling = "active-testing.error-handling"
	stageActiveTestingConfigChecks  = "active-testing.configuration-checks"
	stageActiveTestingComplete      = "active-testing.complete"
)
