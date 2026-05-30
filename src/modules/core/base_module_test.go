package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDiscoverVectors(t *testing.T) {
	b := &BaseModule{}
	u, _ := url.Parse("http://example.com?q=test&id=1")
	vectors, _ := b.DiscoverVectors(u, nil, "", nil)
	if len(vectors) != 2 {
		t.Errorf("Expected 2 query vectors, got %d", len(vectors))
	}

	foundQ := false
	foundId := false
	for _, v := range vectors {
		if v.Type == VectorQueryParam && v.Key == "q" && v.Value == "test" {
			foundQ = true
		}
		if v.Type == VectorQueryParam && v.Key == "id" && v.Value == "1" {
			foundId = true
		}
	}
	if !foundQ {
		t.Error("Expected to find query vector 'q=test'")
	}
	if !foundId {
		t.Error("Expected to find query vector 'id=1'")
	}

	// Test Form Body
	u2, _ := url.Parse("http://example.com")
	body := strings.NewReader("user=admin&pass=secret")
	vectors2, newBody := b.DiscoverVectors(u2, body, "application/x-www-form-urlencoded", nil)
	if len(vectors2) != 2 {
		t.Errorf("Expected 2 form body vectors, got %d", len(vectors2))
	}

	// Verify non-destructive read
	bodyBytes, _ := io.ReadAll(newBody)
	if string(bodyBytes) != "user=admin&pass=secret" {
		t.Errorf("Expected body to be 'user=admin&pass=secret', got '%s'", string(bodyBytes))
	}

	foundUser := false
	foundPass := false
	for _, v := range vectors2 {
		if v.Type == VectorFormBody && v.Key == "user" && v.Value == "admin" {
			foundUser = true
		}
		if v.Type == VectorFormBody && v.Key == "pass" && v.Value == "secret" {
			foundPass = true
		}
	}
	if !foundUser {
		t.Error("Expected to find form body vector 'user=admin'")
	}
	if !foundPass {
		t.Error("Expected to find form body vector 'pass=secret'")
	}
}

func TestDiscoverHeaderAndPathVectors(t *testing.T) {
	b := &BaseModule{}
	u, _ := url.Parse("http://example.com/api/v1/users/123")
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0")
	headers.Set("Cookie", "session=xyz123; theme=dark")

	vectors, _ := b.DiscoverVectors(u, nil, "", headers)

	foundUA := false
	foundCookieSession := false
	foundCookieTheme := false
	foundPath1 := false // v1
	foundPath2 := false // users
	foundPath3 := false // 123

	for _, v := range vectors {
		if v.Type == VectorHeader && v.Key == "User-Agent" && v.Value == "Mozilla/5.0" {
			foundUA = true
		}
		if v.Type == VectorHeader && v.Key == "Cookie:session" && v.Value == "xyz123" {
			foundCookieSession = true
		}
		if v.Type == VectorHeader && v.Key == "Cookie:theme" && v.Value == "dark" {
			foundCookieTheme = true
		}
		if v.Type == VectorPathSegment && v.Key == "path[1]" && v.Value == "v1" {
			foundPath1 = true
		}
		if v.Type == VectorPathSegment && v.Key == "path[2]" && v.Value == "users" {
			foundPath2 = true
		}
		if v.Type == VectorPathSegment && v.Key == "path[3]" && v.Value == "123" {
			foundPath3 = true
		}
	}

	if !foundUA {
		t.Error("Expected to find User-Agent header vector")
	}
	if !foundCookieSession {
		t.Error("Expected to find Cookie:session vector")
	}
	if !foundCookieTheme {
		t.Error("Expected to find Cookie:theme vector")
	}
	if !foundPath1 {
		t.Error("Expected to find path[1] vector (v1)")
	}
	if !foundPath2 {
		t.Error("Expected to find path[2] vector (users)")
	}
	if !foundPath3 {
		t.Error("Expected to find path[3] vector (123)")
	}
}

func TestDiscoverReflection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q string
		if r.Method == "POST" {
			_ = r.ParseForm()
			q = r.Form.Get("q")
		} else {
			q = r.URL.Query().Get("q")
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><h1>Hello %s</h1><input value='%s'><script>var x = '%s';</script></body></html>", q, q, q)
	}))
	defer ts.Close()

	b := &BaseModule{Client: ts.Client()}
	u, _ := url.Parse(ts.URL + "?q=test")

	// Test Query Param
	vector := InputVector{Type: VectorQueryParam, Key: "q", Value: "test"}
	reflections := b.DiscoverReflection(context.Background(), u, vector)
	if len(reflections) != 3 {
		t.Errorf("Expected 3 reflections for query param, got %d", len(reflections))
	}

	// Test Form Body
	vector2 := InputVector{Type: VectorFormBody, Key: "q", Value: "test"}
	reflections2 := b.DiscoverReflection(context.Background(), u, vector2)
	if len(reflections2) != 3 {
		t.Errorf("Expected 3 reflections for form body, got %d", len(reflections2))
	}

	expectedTypes := map[ReflectionType]bool{
		ContextHTML:      false,
		ContextAttribute: false,
		ContextScript:    false,
	}

	for _, r := range reflections {
		expectedTypes[r.Type] = true
	}

	for k, v := range expectedTypes {
		if !v {
			t.Errorf("Expected to find reflection of type %s", k)
		}
	}
}

func TestDiscoverJSONVectors(t *testing.T) {
	b := &BaseModule{}
	u, _ := url.Parse("http://example.com/api/user")
	jsonBody := `{"user": {"id": 123, "name": "test"}, "active": true, "tags": ["admin", "beta"]}`
	body := strings.NewReader(jsonBody)

	vectors, _ := b.DiscoverVectors(u, body, "application/json", nil)

	// We expect 4 JSON vectors:
	// 1. user.id
	// 2. user.name
	// 3. active
	// 4. tags.0 (maybe? or just tags)
	// Based on the provided Step 2:
	// case []any: if len(v) > 0 { vectors = append(vectors, b.discoverJSONVectors(v[0], append(path, "0"))...) }
	// So it only takes the first element for arrays in the provided implementation.
	// 1. user.id
	// 2. user.name
	// 3. active
	// 4. tags.0

	jsonVectors := []InputVector{}
	for _, v := range vectors {
		if v.Type == VectorJSONBody {
			jsonVectors = append(jsonVectors, v)
		}
	}

	if len(jsonVectors) != 4 {
		t.Errorf("Expected 4 JSON vectors, got %d", len(jsonVectors))
	}

	foundID := false
	for _, v := range jsonVectors {
		if v.Type == VectorJSONBody && v.Key == "user.id" && v.Value == "123" {
			if len(v.JSONPath) == 2 && v.JSONPath[0] == "user" && v.JSONPath[1] == "id" {
				foundID = true
			}
		}
	}
	if !foundID {
		t.Error("Expected to find JSON vector 'user.id' with correct path")
	}
}

func TestMutateJSON(t *testing.T) {
	b := &BaseModule{}
	jsonBody := []byte(`{"user": {"id": 123, "name": "test"}, "active": true}`)
	path := []string{"user", "id"}
	newValue := "PROBE123"

	mutated, err := b.MutateJSON(jsonBody, path, newValue)
	if err != nil {
		t.Fatalf("MutateJSON failed: %v", err)
	}

	var data any
	if err := json.Unmarshal(mutated, &data); err != nil {
		t.Fatalf("Failed to unmarshal mutated JSON: %v", err)
	}

	m := data.(map[string]any)
	user := m["user"].(map[string]any)
	if user["id"] != newValue {
		t.Errorf("Expected user.id to be %s, got %v", newValue, user["id"])
	}
}

func TestOOBInfrastructure(t *testing.T) {
	manager := &OOBManager{PublicHost: "localhost"}
	// Use 127.0.0.1:0 to get a random available port
	err := manager.StartOOBReceiver("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start OOB receiver: %v", err)
	}
	defer manager.StopOOBReceiver()

	payload, id := manager.GenerateOOBPayload()
	if payload == "" || id == "" {
		t.Fatal("Failed to generate OOB payload")
	}

	// Simulate an interaction
	// The payload should be something like localhost:PORT/ID
	interactionURL := "http://" + manager.Listener.Addr().String() + "/" + id
	resp, err := http.Get(interactionURL)
	if err != nil {
		t.Fatalf("Failed to simulate interaction: %v", err)
	}
	resp.Body.Close()

	// Give it a tiny bit of time for the async server to record it if needed,
	// though usually it's synchronous in the handler.
	time.Sleep(10 * time.Millisecond)

	// Check interactions
	interactions := manager.GetInteractions(id)
	if len(interactions) != 1 {
		t.Errorf("Expected 1 interaction, got %d", len(interactions))
	} else {
		if interactions[0].ID != id {
			t.Errorf("Expected interaction ID %s, got %s", id, interactions[0].ID)
		}
		if interactions[0].Protocol != "http" {
			t.Errorf("Expected protocol http, got %s", interactions[0].Protocol)
		}
	}
}

func TestBuildRequestWithVector(t *testing.T) {
	b := &BaseModule{}
	ctx := context.Background()
	u, _ := url.Parse("http://example.com/api/test")

	// Test Form Body
	req, err := b.BuildRequestWithVector(ctx, "POST", u, InputVector{Type: VectorFormBody, Key: "username"}, "payload")
	if err != nil {
		t.Fatalf("Failed to build form request: %v", err)
	}
	if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("Incorrect content type")
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "username=payload") {
		t.Errorf("Form body missing payload: %s", string(body))
	}

	// Test JSON Body
	reqJSON, _ := b.BuildRequestWithVector(ctx, "POST", u, InputVector{Type: VectorJSONBody, Key: "username"}, "payload")
	if reqJSON.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Incorrect content type")
	}
	bodyJSON, _ := io.ReadAll(reqJSON.Body)
	if !strings.Contains(string(bodyJSON), `"username":"payload"`) {
		t.Errorf("JSON body missing payload: %s", string(bodyJSON))
	}
}

func TestDiscoverVectors_NilBody(t *testing.T) {
	b := &BaseModule{}
	u, _ := url.Parse("http://example.com")
	vectors, _ := b.DiscoverVectors(u, nil, "", nil)
	if len(vectors) != 0 {
		t.Errorf("Expected 0 vectors for empty inputs, got %d", len(vectors))
	}
}

func TestMutateJSON_InvalidJSON(t *testing.T) {
	b := &BaseModule{}
	newBody, err := b.MutateJSON([]byte(`{invalid: json}`), []string{"any"}, "payload")
	if err == nil {
		t.Errorf("Expected error for invalid JSON mutation")
	}
	if newBody != nil {
		t.Errorf("Expected nil body on error")
	}
}

func TestBuildRequestWithVector_UnknownType(t *testing.T) {
	b := &BaseModule{}
	u, _ := url.Parse("http://example.com")
	req, err := b.BuildRequestWithVector(context.Background(), "GET", u, InputVector{Type: "unknown", Key: "k", Value: "v"}, "payload")
	if err == nil {
		t.Error("Expected error for unknown vector type")
	}
	if req != nil {
		t.Error("Expected nil request on error")
	}
}
