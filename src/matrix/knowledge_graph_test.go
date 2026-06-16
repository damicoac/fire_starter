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
	kg.AddURL("http://example.com", "")
	targetUrl := kg.Targets["example.com"]
	if targetUrl == nil || targetUrl.Score != 1 {
		t.Errorf("Expected URL score 1, got %v", targetUrl)
	}

	kg.AddURL("http://example.com?id=1", "")
	if kg.Targets["example.com?id=1"] != nil {
		t.Errorf("Expected parameterized URL to be folded into base target")
	}
	if targetUrl.Score != 7 { // 1 (from http://example.com) + 6 (from http://example.com?id=1)
		t.Errorf("Expected URL score 7 for param URL folded into base target, got %d", targetUrl.Score)
	}

	// Test www normalization
	kg.AddURL("http://www.example.com", "")
	if kg.Targets["www.example.com"] != nil {
		t.Errorf("Expected URL to be normalized and merged")
	}
	kg.AddURL("https://www.example.com", "")
	if kg.Targets["www.example.com"] != nil {
		t.Errorf("Expected https://www.example.com to be merged as well")
	}
	kg.AddURL("www.test.com", "")
	targetTest := kg.Targets["test.com"]
	if targetTest == nil || targetTest.Value != "test.com" {
		t.Errorf("Expected www.test.com to be normalized to test.com")
	}
}

func TestKnowledgeGraph_GetTokensForTarget(t *testing.T) {
	kg := NewKnowledgeGraph()

	// Add targets and tokens
	kg.AddToken("example.com", "cookie_example")
	kg.AddToken("sub.example.com", "cookie_sub")
	kg.AddToken("other.com", "cookie_other")
	kg.AddToken("192.168.1.1", "cookie_ip1")
	kg.AddToken("192.168.1.2", "cookie_ip2")

	// Helper to check if slice contains element
	contains := func(slice []string, val string) bool {
		for _, s := range slice {
			if s == val {
				return true
			}
		}
		return false
	}

	// Test 1: exact match
	tokens := kg.GetTokensForTarget("example.com/api/v1")
	if !contains(tokens, "cookie_example") {
		t.Errorf("Expected tokens to contain cookie_example, got %v", tokens)
	}
	if contains(tokens, "cookie_other") {
		t.Errorf("Expected tokens NOT to contain cookie_other, got %v", tokens)
	}

	// Test 2: subdomain retrieval (should get both example.com and sub.example.com tokens)
	tokensSub := kg.GetTokensForTarget("sub.example.com/test")
	if !contains(tokensSub, "cookie_sub") || !contains(tokensSub, "cookie_example") {
		t.Errorf("Expected sub.example.com tokens to contain both cookie_sub and cookie_example, got %v", tokensSub)
	}
	if contains(tokensSub, "cookie_other") {
		t.Errorf("Expected sub.example.com tokens NOT to contain cookie_other, got %v", tokensSub)
	}

	// Test 3: parent domain retrieval (should get sub.example.com tokens as well because they share domain scope)
	tokensParent := kg.GetTokensForTarget("example.com")
	if !contains(tokensParent, "cookie_example") || !contains(tokensParent, "cookie_sub") {
		t.Errorf("Expected example.com tokens to contain both cookie_example and cookie_sub, got %v", tokensParent)
	}

	// Test 4: unrelated domain isolation
	tokensOther := kg.GetTokensForTarget("other.com")
	if !contains(tokensOther, "cookie_other") {
		t.Errorf("Expected other.com tokens to contain cookie_other, got %v", tokensOther)
	}
	if contains(tokensOther, "cookie_example") || contains(tokensOther, "cookie_sub") {
		t.Errorf("Expected other.com tokens NOT to contain example cookies, got %v", tokensOther)
	}

	// Test 5: IP isolation
	tokensIP1 := kg.GetTokensForTarget("192.168.1.1")
	if !contains(tokensIP1, "cookie_ip1") {
		t.Errorf("Expected 192.168.1.1 tokens to contain cookie_ip1, got %v", tokensIP1)
	}
	if contains(tokensIP1, "cookie_ip2") {
		t.Errorf("Expected 192.168.1.1 tokens NOT to contain cookie_ip2, got %v", tokensIP1)
	}
}

