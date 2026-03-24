// File overview:
// Application-mapping stage node/constants for the decision tree. It exists to progressively build attack-surface knowledge before active exploitation checks begin.

package applicationmapping

const (
	stageApplicationMappingExplore       = "application-mapping.explore"
	stageApplicationMappingEntryPoints   = "application-mapping.entry-points"
	stageApplicationMappingMetadata      = "application-mapping.metadata-review"
	stageApplicationMappingAttackSurface = "application-mapping.attack-surface"
	stageApplicationMappingComplete      = "application-mapping.complete"
)
