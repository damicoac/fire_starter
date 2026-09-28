package core

import (
	"testing"
)

func TestGetDefaultWordlist(t *testing.T) {
	wordlist := getDefaultWordlist()
	if len(wordlist) == 0 {
		t.Fatal("expected default wordlist to be populated, got empty")
	}

	foundWWW := false
	for _, word := range wordlist {
		if word == "www" {
			foundWWW = true
			break
		}
	}
	if !foundWWW {
		t.Error("expected 'www' to be in default wordlist")
	}
}

