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
	"sync"
	"testing"
	"time"
)

func TestDiscoverVectors(t *testing.T) {
	b := &BaseModule{}
	u, _ := url.Parse("http://example.com?q=test&id=1")
	vectors, _, err := b.DiscoverVectors(u, nil, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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
	vectors2, newBody, err := b.DiscoverVectors(u2, body, "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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

	vectors, _, err := b.DiscoverVectors(u, nil, "", headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	reflections, err := b.DiscoverReflection(context.Background(), u, vector)
	if err != nil {
		t.Fatalf("unexpected reflection probe error: %v", err)
	}
	if len(reflections) != 3 {
		t.Errorf("Expected 3 reflections for query param, got %d", len(reflections))
	}

	// Test Form Body
	vector2 := InputVector{Type: VectorFormBody, Key: "q", Value: "test"}
	reflections2, err := b.DiscoverReflection(context.Background(), u, vector2)
	if err != nil {
		t.Fatalf("unexpected reflection probe error: %v", err)
	}
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

	vectors, _, err := b.DiscoverVectors(u, body, "application/json", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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

	// Check hits
	hits := manager.Hits(id)
	if len(hits) != 1 {
		t.Errorf("Expected 1 hit, got %d", len(hits))
	} else if hits[0].Path != "/"+id {
		t.Errorf("Expected hit path /%s, got %s", id, hits[0].Path)
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
	vectors, _, err := b.DiscoverVectors(u, nil, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vectors) != 0 {
		t.Errorf("Expected 0 vectors for empty inputs, got %d", len(vectors))
	}
}

func TestDiscoverVectors_BodyReadError(t *testing.T) {
	b := &BaseModule{}
	u, _ := url.Parse("http://example.com")
	body := io.MultiReader(strings.NewReader(`{"a":1}`), &failingReader{})
	_, _, err := b.DiscoverVectors(u, body, "application/json", nil)
	if err == nil {
		t.Fatal("expected error for unreadable request body, got nil")
	}
}

type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("simulated read failure")
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

func TestReadBoundedBody(t *testing.T) {
	// Nil reader returns nil, nil
	data, err := ReadBoundedBody(nil, 100)
	if err != nil || data != nil {
		t.Fatalf("expected nil data on nil reader, got %v, %v", data, err)
	}

	// Normal bounded read
	input := strings.Repeat("a", 100)
	data, err = ReadBoundedBody(strings.NewReader(input), 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 50 {
		t.Fatalf("expected 50 bytes, got %d", len(data))
	}

	// Default fallback to MaxResponseBodyBytes
	smallInput := "hello world"
	data, err = ReadBoundedBody(strings.NewReader(smallInput), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != smallInput {
		t.Fatalf("expected %q, got %q", smallInput, string(data))
	}
}

func TestBaseModule_ConcurrentVectorAndBuildRequest(t *testing.T) {
	b := &BaseModule{}
	targetURL, _ := url.Parse("http://example.com/api?id=1")
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(val int) {
			defer wg.Done()
			body := strings.NewReader(fmt.Sprintf(`{"field": %d}`, val))
			headers := http.Header{"X-Trace": []string{fmt.Sprintf("trace-%d", val)}}
			_, _, _ = b.DiscoverVectors(targetURL, body, "application/json", headers)
		}(i)

		go func(val int) {
			defer wg.Done()
			vec := InputVector{Type: VectorQueryParam, Key: "id", Value: "1"}
			_, _ = b.BuildRequestWithVector(context.Background(), "GET", targetURL, vec, fmt.Sprintf("val-%d", val))
		}(i)
	}
	wg.Wait()
}

func TestDiscoverReflectionCookieVectorPreservesProbeAndSession(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>Cookie: %s</body></html>", r.Header.Get("Cookie"))
	}))
	defer ts.Close()

	b := &BaseModule{Client: ts.Client()}
	b.SetCookies("sid=abc123")

	u, _ := url.Parse(ts.URL)
	vector := InputVector{Type: VectorHeader, Key: "Cookie:sess", Value: "orig"}

	reflections, err := b.DiscoverReflection(context.Background(), u, vector)
	if err != nil {
		t.Fatalf("unexpected reflection probe error: %v", err)
	}
	if len(reflections) == 0 {
		t.Fatal("expected probe reflection for cookie vector, got none (probe was overwritten by session cookies?)")
	}

	// Re-run with a raw request to inspect the merged Cookie header contents.
	req, err := b.BuildRequestWithVector(context.Background(), "GET", u, vector, "PROBEMARKER")
	if err != nil {
		t.Fatalf("BuildRequestWithVector failed: %v", err)
	}
	cookie := req.Header.Get("Cookie")
	if !strings.Contains(cookie, "sess=PROBEMARKER") {
		t.Errorf("expected vector cookie in Cookie header, got %q", cookie)
	}
	// Session cookies must survive alongside the vector cookie.
	req.Header.Set("Cookie", mergeCookieHeaders(req.Header.Get("Cookie"), "sid=abc123"))
	cookie = req.Header.Get("Cookie")
	if !strings.Contains(cookie, "sid=abc123") {
		t.Errorf("expected session cookie merged into Cookie header, got %q", cookie)
	}
	if !strings.Contains(cookie, "sess=PROBEMARKER") {
		t.Errorf("expected vector cookie to survive merge, got %q", cookie)
	}
}

func TestDiscoverJSONVectorsNoAliasing(t *testing.T) {
	b := &BaseModule{}
	// Depth >= 4 with sibling keys at the deepest level: the previous
	// append(path, k) aliasing corrupted sibling JSONPaths.
	body := `{"a":{"x":{"p":{"q1":"1","q2":"2","q3":"3","q4":"4"}}}}`
	u, _ := url.Parse("http://example.com")
	vectors, _, err := b.DiscoverVectors(u, strings.NewReader(body), "application/json", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]bool{
		"a.x.p.q1": false,
		"a.x.p.q2": false,
		"a.x.p.q3": false,
		"a.x.p.q4": false,
	}
	if len(vectors) != len(expected) {
		t.Fatalf("expected %d JSON vectors, got %d: %#v", len(expected), len(vectors), vectors)
	}
	for _, v := range vectors {
		if v.Type != VectorJSONBody {
			t.Errorf("unexpected vector type %v", v.Type)
			continue
		}
		seen, ok := expected[v.Key]
		if !ok {
			t.Errorf("unexpected corrupted JSONPath key %q", v.Key)
			continue
		}
		if seen {
			t.Errorf("duplicate JSON vector key %q (aliasing bug)", v.Key)
		}
		expected[v.Key] = true
	}
	for k, seen := range expected {
		if !seen {
			t.Errorf("missing JSON vector key %q", k)
		}
	}
}

func TestBuildRequestWithVectorPreservesEncodedPayloads(t *testing.T) {
	b := &BaseModule{}

	// Query vector: pre-encoded payload must not be double-escaped.
	u, _ := url.Parse("http://example.com/api?id=1")
	vec := InputVector{Type: VectorQueryParam, Key: "q", Value: ""}
	req, err := b.BuildRequestWithVector(context.Background(), "GET", u, vec, "..%2f..%2fadmin")
	if err != nil {
		t.Fatalf("query vector build failed: %v", err)
	}
	if got := req.URL.RawQuery; !strings.Contains(got, "q=..%2f..%2fadmin") {
		t.Errorf("expected raw pre-encoded query payload, got %q", got)
	}
	if strings.Contains(req.URL.String(), "%252f") {
		t.Errorf("payload was double-encoded: %s", req.URL.String())
	}

	// Ordinary payloads still get encoded exactly once.
	req, err = b.BuildRequestWithVector(context.Background(), "GET", u, vec, "hello world")
	if err != nil {
		t.Fatalf("plain query vector build failed: %v", err)
	}
	if got := req.URL.RawQuery; !strings.Contains(got, "q=hello+world") {
		t.Errorf("expected plain payload encoded once, got %q", got)
	}

	// Path vector: pre-encoded payload must reach the wire verbatim.
	u2, _ := url.Parse("http://example.com/api/v1/resource")
	vec2 := InputVector{Type: VectorPathSegment, Key: "path[1]", Value: "v1"}
	req, err = b.BuildRequestWithVector(context.Background(), "GET", u2, vec2, "..%2fadmin")
	if err != nil {
		t.Fatalf("path vector build failed: %v", err)
	}
	if got := req.URL.EscapedPath(); !strings.Contains(got, "..%2fadmin") {
		t.Errorf("expected raw pre-encoded path payload, got %q", got)
	}
	if strings.Contains(req.URL.EscapedPath(), "%252f") {
		t.Errorf("path payload was double-encoded: %s", req.URL.EscapedPath())
	}
}

func TestBuildRequestWithVectorRejectsCorruptingInputs(t *testing.T) {
	b := &BaseModule{}
	b.OriginalBody = []byte("a=%zz&b=%zz") // invalid percent-escapes fail url.ParseQuery
	b.OriginalHeaders = http.Header{}

	u, _ := url.Parse("http://example.com")
	vec := InputVector{Type: VectorFormBody, Key: "q", Value: ""}
	if _, err := b.BuildRequestWithVector(context.Background(), "POST", u, vec, "payload"); err == nil {
		t.Error("expected error for unparseable original form body")
	}

	b.OriginalBody = []byte(`{"user":{"name":"bob"}}`)
	jsonVec := InputVector{Type: VectorJSONBody, Key: "user.missing", Value: "", JSONPath: []string{"user", "missing"}}
	if _, err := b.BuildRequestWithVector(context.Background(), "POST", u, jsonVec, "payload"); err == nil {
		t.Error("expected error for JSON mutation failure")
	}

	u2, _ := url.Parse("http://example.com/only")
	pathVec := InputVector{Type: VectorPathSegment, Key: "path[5]", Value: "seg"}
	if _, err := b.BuildRequestWithVector(context.Background(), "GET", u2, pathVec, "payload"); err == nil {
		t.Error("expected error for out-of-range path segment index")
	}
}

func TestDiscoverReflectionErrorOnTransportFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	urlOf := ts.URL
	ts.Close()

	b := &BaseModule{Client: &http.Client{Timeout: 2 * time.Second}}
	u, _ := url.Parse(urlOf)
	reflections, err := b.DiscoverReflection(context.Background(), u, InputVector{Type: VectorQueryParam, Key: "q", Value: ""})
	if err == nil {
		t.Fatal("expected transport error from DiscoverReflection")
	}
	if reflections != nil {
		t.Errorf("expected nil reflections on error, got %#v", reflections)
	}
}

func TestGenerateOOBPayloadWithoutHost(t *testing.T) {
	m := &OOBManager{}
	payload, id := m.GenerateOOBPayload()
	if payload != "" || id != "" {
		t.Errorf("expected empty payload/id when no OOB host is available, got %q/%q", payload, id)
	}
}
