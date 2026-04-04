package matrix

import (
	"context"
	"math/rand"
	"time"

	"blackwater/src/database"
)

// IntelligentAgent uses Reinforcement Learning and the KnowledgeGraph to propose intelligent decisions.
type IntelligentAgent struct {
	learner database.ReinforcementLearner
	rng     *rand.Rand
}

func NewIntelligentAgent(learner database.ReinforcementLearner) *IntelligentAgent {
	return &IntelligentAgent{
		learner: learner,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ProposeDecisions uses RL ranking and generates dynamic payloads based on the knowledge graph.
func (a *IntelligentAgent) ProposeDecisions(history []ExecutionResult, available []Decision, count int, kg *KnowledgeGraph) []Decision {
	if len(available) == 0 {
		return nil
	}

	previousStage := "application-mapping.explore"
	if len(history) > 0 {
		lastDecision := history[len(history)-1].DecisionSelected
		previousStage = MapTechniqueToStage(lastDecision.Technique)
	}

	// Create a mapping from stage to available decisions
	stageToDecisions := make(map[string][]Decision)
	for _, dec := range available {
		stage := MapTechniqueToStage(dec.Technique)
		stageToDecisions[stage] = append(stageToDecisions[stage], dec)
	}

	candidates := make([]string, 0, len(stageToDecisions))
	for stage := range stageToDecisions {
		candidates = append(candidates, stage)
	}

	// 1. Ask RL Learner to rank the next stages
	rankedStages, err := a.learner.RankNextStages(context.Background(), previousStage, candidates)
	if err != nil || len(rankedStages) == 0 {
		rankedStages = candidates
		a.rng.Shuffle(len(rankedStages), func(i, j int) {
			rankedStages[i], rankedStages[j] = rankedStages[j], rankedStages[i]
		})
	}

	var proposed []Decision
	for _, stage := range rankedStages {
		decisionsForStage := stageToDecisions[stage]
		for _, dec := range decisionsForStage {
			// Deep copy the decision to avoid mutating the original
			newDec := Decision{
				UseCase:              dec.UseCase,
				Technique:            dec.Technique,
				Function:             dec.Function,
				ProblemTheToolSolves: dec.ProblemTheToolSolves,
				Identifier:           dec.Identifier,
				Payload:              make(map[string]any),
			}

			// 2. Enable Dynamic Payload Generation based on KnowledgeGraph
			kg.mu.RLock()
			if len(kg.DiscoveredIPs) > 0 {
				newDec.Payload["ip"] = kg.DiscoveredIPs[a.rng.Intn(len(kg.DiscoveredIPs))]
			}
			if len(kg.DiscoveredURLs) > 0 {
				newDec.Payload["url"] = kg.DiscoveredURLs[a.rng.Intn(len(kg.DiscoveredURLs))]
			}
			if len(kg.HarvestedTokens) > 0 {
				newDec.Payload["cookies"] = kg.HarvestedTokens[a.rng.Intn(len(kg.HarvestedTokens))]
			}
			kg.mu.RUnlock()

			proposed = append(proposed, newDec)
			if len(proposed) >= count {
				return proposed
			}
		}
	}

	return proposed
}
