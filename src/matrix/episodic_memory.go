package matrix

import (
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// MemoryEntry represents a single stored log, HTTP request/response, or reasoning trace
type MemoryEntry struct {
	ID        string            `json:"id"`
	Content   string            `json:"content"`
	Source    string            `json:"source"`
	Timestamp time.Time         `json:"timestamp"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// MemoryQueryResult represents a similarity search result with relevancy score
type MemoryQueryResult struct {
	Entry MemoryEntry `json:"entry"`
	Score float64     `json:"score"`
}

// EpisodicMemory Store manages episodic memory indexing and keyword/Jaccard vector retrieval
type EpisodicMemory struct {
	mu      sync.RWMutex
	entries []MemoryEntry
}

// NewEpisodicMemory initializes a new EpisodicMemory store
func NewEpisodicMemory() *EpisodicMemory {
	return &EpisodicMemory{
		entries: make([]MemoryEntry, 0),
	}
}

const maxEpisodicMemoryEntries = 500

// Store adds a new entry to the memory repository
func (em *EpisodicMemory) Store(entry MemoryEntry) {
	em.mu.Lock()
	defer em.mu.Unlock()
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	if len(em.entries) >= maxEpisodicMemoryEntries {
		em.entries[0] = MemoryEntry{}
		em.entries = em.entries[1:]
	}
	em.entries = append(em.entries, entry)
}

// Query performs Jaccard and term-frequency similarity retrieval over stored memory entries
func (em *EpisodicMemory) Query(queryStr string, topK int) []MemoryQueryResult {
	em.mu.RLock()
	defer em.mu.RUnlock()

	if topK <= 0 {
		topK = 5
	}

	queryTokens := tokenize(queryStr)
	if len(queryTokens) == 0 {
		return nil
	}

	var results []MemoryQueryResult
	for _, entry := range em.entries {
		entryTokens := tokenize(entry.Content)
		score := calculateSimilarity(queryTokens, entryTokens)
		if score > 0.0 {
			results = append(results, MemoryQueryResult{
				Entry: entry,
				Score: score,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	if len(results) > topK {
		return results[:topK]
	}
	return results
}

// Count returns the total stored entries
func (em *EpisodicMemory) Count() int {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return len(em.entries)
}

func tokenize(text string) map[string]int {
	words := strings.Fields(strings.ToLower(text))
	freq := make(map[string]int)
	for _, w := range words {
		// Clean punctuation
		cleaned := strings.Trim(w, ".,!?:;\"'()[]{}")
		if len(cleaned) > 1 {
			freq[cleaned]++
		}
	}
	return freq
}

func calculateSimilarity(qTokens, eTokens map[string]int) float64 {
	if len(qTokens) == 0 || len(eTokens) == 0 {
		return 0.0
	}

	var intersection float64
	var qMag, eMag float64

	for t, count := range qTokens {
		qMag += float64(count * count)
		if eCount, exists := eTokens[t]; exists {
			intersection += float64(count * eCount)
		}
	}

	for _, count := range eTokens {
		eMag += float64(count * count)
	}

	if qMag == 0 || eMag == 0 {
		return 0.0
	}

	return intersection / (math.Sqrt(qMag) * math.Sqrt(eMag))
}
