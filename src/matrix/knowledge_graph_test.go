package matrix

import (
	"testing"
)

func TestKnowledgeGraph_Scoring(t *testing.T) {
	kg := NewKnowledgeGraph()

	// Test IP Scoring
	kg.AddIP("192.168.1.1")
	target := kg.Targets["192.168.1.1"]
	if target == nil || target.Score != 1 {
		t.Errorf("Expected IP score 1, got %v", target)
	}

	kg.AddIP("192.168.1.1")
	if target.Score != 2 {
		t.Errorf("Expected IP score 2 after second add, got %d", target.Score)
	}

	// Test Port Scoring
	kg.AddPort("192.168.1.1", 80)
	if target.Score != 12 { // 2 + 10
		t.Errorf("Expected IP score 12 after adding port, got %d", target.Score)
	}

	// Test URL Scoring
	kg.AddURL("http://example.com")
	targetUrl := kg.Targets["example.com"]
	if targetUrl == nil || targetUrl.Score != 1 {
		t.Errorf("Expected URL score 1, got %v", targetUrl)
	}

	kg.AddURL("http://example.com?id=1")
	if kg.Targets["example.com?id=1"] != nil {
		t.Errorf("Expected parameterized URL to be folded into base target")
	}
	if targetUrl.Score != 7 { // 1 (from http://example.com) + 6 (from http://example.com?id=1)
		t.Errorf("Expected URL score 7 for param URL folded into base target, got %d", targetUrl.Score)
	}

	// Test www normalization
	kg.AddURL("http://www.example.com")
	if kg.Targets["www.example.com"] != nil {
		t.Errorf("Expected URL to be normalized and merged")
	}
	kg.AddURL("https://www.example.com")
	if kg.Targets["www.example.com"] != nil {
		t.Errorf("Expected https://www.example.com to be merged as well")
	}
	kg.AddURL("www.test.com")
	targetTest := kg.Targets["test.com"]
	if targetTest == nil || targetTest.Value != "test.com" {
		t.Errorf("Expected www.test.com to be normalized to test.com")
	}
}
