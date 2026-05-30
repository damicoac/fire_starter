package matrix

import (
	"testing"
)

func TestKnowledgeGraph_Scoring(t *testing.T) {
	kg := NewKnowledgeGraph()

	// Test IP Scoring
	kg.AddIP("192.168.1.1")
	if len(kg.DiscoveredIPs) != 1 || kg.DiscoveredIPs[0].Score != 1 {
		t.Errorf("Expected IP score 1, got %d", kg.DiscoveredIPs[0].Score)
	}

	kg.AddIP("192.168.1.1")
	if kg.DiscoveredIPs[0].Score != 2 {
		t.Errorf("Expected IP score 2 after second add, got %d", kg.DiscoveredIPs[0].Score)
	}

	// Test Port Scoring
	kg.AddPort("192.168.1.1", 80)
	if kg.DiscoveredIPs[0].Score != 12 { // 2 + 10
		t.Errorf("Expected IP score 12 after adding port, got %d", kg.DiscoveredIPs[0].Score)
	}

	// Test URL Scoring
	kg.AddURL("http://example.com")
	if len(kg.DiscoveredURLs) != 1 || kg.DiscoveredURLs[0].Score != 1 {
		t.Errorf("Expected URL score 1, got %d", kg.DiscoveredURLs[0].Score)
	}

	kg.AddURL("http://example.com?id=1")
	if len(kg.DiscoveredURLs) != 2 || kg.DiscoveredURLs[1].Score != 6 { // 1 + 5
		t.Errorf("Expected URL score 6 for param URL, got %d", kg.DiscoveredURLs[1].Score)
	}
}
