package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type InputVectorType string

const (
	VectorQueryParam  InputVectorType = "query_param"
	VectorFormBody    InputVectorType = "form_body"
	VectorJSONBody    InputVectorType = "json_body"
	VectorHeader      InputVectorType = "header"
	VectorPathSegment InputVectorType = "path_segment"
)

type InputVector struct {
	Type     InputVectorType
	Key      string
	Value    string
	JSONPath []string // Path for nested JSON injection
}

type ReflectionType string

const (
	ContextHTML      ReflectionType = "html"
	ContextAttribute ReflectionType = "attribute"
	ContextScript    ReflectionType = "script"
	ContextUnknown   ReflectionType = "unknown"
)

type ReflectionContext struct {
	Type     ReflectionType
	Location int
}

type ProofOfConcept struct {
	Description string `json:"description"`
	Request     string `json:"request"`
}

type BaseModule struct {
	Client          *http.Client
	MaxThreads      int
	Mu              sync.Mutex
	PocMu           sync.Mutex
	Cookies         string
	OriginalHeaders http.Header
	OriginalBody    []byte
	PoCs            []ProofOfConcept
}

func (b *BaseModule) GetBaseModule() *BaseModule {
	return b
}

type OOBInteraction struct {
	ID        string
	Protocol  string // "http" or "dns"
	RemoteIP  string
	Timestamp time.Time
}

type OOBManager struct {
	PublicHost   string
	Listener     net.Listener
	Interactions map[string][]OOBInteraction
	Mu           sync.Mutex
}

func (m *OOBManager) StartOOBReceiver(listenAddr string) error {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	m.Listener = l
	m.Interactions = make(map[string][]OOBInteraction)

	go func() {
		_ = http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := strings.Trim(r.URL.Path, "/")
			if id != "" {
				interaction := OOBInteraction{
					ID:        id,
					Protocol:  "http",
					RemoteIP:  r.RemoteAddr,
					Timestamp: time.Now(),
				}
				m.Mu.Lock()
				m.Interactions[id] = append(m.Interactions[id], interaction)
				m.Mu.Unlock()
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "OK")
		}))
	}()
	return nil
}

func (m *OOBManager) StopOOBReceiver() {
	if m.Listener != nil {
		m.Listener.Close()
	}
}

func (m *OOBManager) GenerateOOBPayload() (string, string) {
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	host := m.PublicHost
	if host == "" && m.Listener != nil {
		host = m.Listener.Addr().String()
	}

	return fmt.Sprintf("%s/%s", host, id), id
}

func (m *OOBManager) GetInteractions(id string) []OOBInteraction {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	interactions, ok := m.Interactions[id]
	if !ok {
		return []OOBInteraction{}
	}
	return interactions
}

// DiscoverVectors finds all input vectors (query params, form body, etc.) from a request.
// It returns a new reader for the body so it can be read again if needed.
func (b *BaseModule) DiscoverVectors(u *url.URL, body io.Reader, contentType string, headers http.Header) ([]InputVector, io.Reader) {
	vectors := []InputVector{}
	var bodyBytes []byte
	var newBody io.Reader

	if headers != nil {
		b.OriginalHeaders = headers.Clone()
	} else {
		b.OriginalHeaders = http.Header{}
	}

	if body != nil {
		bodyBytes, _ = io.ReadAll(body)
		b.OriginalBody = bodyBytes
	} else {
		b.OriginalBody = nil
	}

	// Handle Query Parameters
	if u != nil {
		for k, vals := range u.Query() {
			for _, v := range vals {
				vectors = append(vectors, InputVector{Type: VectorQueryParam, Key: k, Value: v})
			}
		}
		// Handle Path Segments
		vectors = append(vectors, b.discoverPathVectors(u)...)
	}

	// Handle Headers
	if headers != nil {
		vectors = append(vectors, b.discoverHeaderVectors(headers)...)
	}

	// Handle Form Body (basic implementation)
	if strings.Contains(contentType, "application/x-www-form-urlencoded") && bodyBytes != nil {
		newBody = bytes.NewReader(bodyBytes)
		values, err := url.ParseQuery(string(bodyBytes))
		if err == nil {
			for k, vals := range values {
				for _, v := range vals {
					vectors = append(vectors, InputVector{Type: VectorFormBody, Key: k, Value: v})
				}
			}
		}
	} else if strings.Contains(contentType, "application/json") && bodyBytes != nil {
		newBody = bytes.NewReader(bodyBytes)
		var data any
		if err := json.Unmarshal(bodyBytes, &data); err == nil {
			vectors = append(vectors, b.discoverJSONVectors(data, []string{})...)
		}
	} else {
		if bodyBytes != nil {
			newBody = bytes.NewReader(bodyBytes)
		} else {
			newBody = nil
		}
	}
	return vectors, newBody
}

func (b *BaseModule) discoverHeaderVectors(headers http.Header) []InputVector {
	vectors := []InputVector{}
	standardHeaders := []string{"User-Agent", "Referer", "X-Forwarded-For", "Client-IP"}
	for _, h := range standardHeaders {
		if v := headers.Get(h); v != "" {
			vectors = append(vectors, InputVector{Type: VectorHeader, Key: h, Value: v})
		}
	}
	// Parse Cookies if present
	if cookieHeader := headers.Get("Cookie"); cookieHeader != "" {
		cookies := strings.Split(cookieHeader, ";")
		for _, c := range cookies {
			parts := strings.SplitN(strings.TrimSpace(c), "=", 2)
			if len(parts) == 2 {
				vectors = append(vectors, InputVector{Type: VectorHeader, Key: "Cookie:" + parts[0], Value: parts[1]})
			}
		}
	}
	return vectors
}

func (b *BaseModule) discoverPathVectors(u *url.URL) []InputVector {
	vectors := []InputVector{}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i, seg := range segments {
		if seg != "" {
			vectors = append(vectors, InputVector{Type: VectorPathSegment, Key: fmt.Sprintf("path[%d]", i), Value: seg})
		}
	}
	return vectors
}

func (b *BaseModule) discoverJSONVectors(data any, path []string) []InputVector {
	vectors := []InputVector{}
	switch v := data.(type) {
	case map[string]any:
		for k, val := range v {
			vectors = append(vectors, b.discoverJSONVectors(val, append(path, k))...)
		}
	case []any:
		if len(v) > 0 {
			vectors = append(vectors, b.discoverJSONVectors(v[0], append(path, "0"))...)
		}
	case string, float64, bool:
		vectors = append(vectors, InputVector{
			Type:     VectorJSONBody,
			Key:      strings.Join(path, "."),
			Value:    fmt.Sprint(v),
			JSONPath: path,
		})
	}
	return vectors
}

func (b *BaseModule) MutateJSON(body []byte, jsonPath []string, newValue string) ([]byte, error) {
	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	newData, err := b.setJSONValue(data, jsonPath, newValue)
	if err != nil {
		return nil, err
	}

	return json.Marshal(newData)
}

func (b *BaseModule) setJSONValue(data any, path []string, value string) (any, error) {
	if len(path) == 0 {
		return value, nil
	}

	key := path[0]
	switch v := data.(type) {
	case map[string]any:
		child, ok := v[key]
		if !ok {
			return nil, fmt.Errorf("key not found: %s", key)
		}
		newChild, err := b.setJSONValue(child, path[1:], value)
		if err != nil {
			return nil, err
		}
		v[key] = newChild
		return v, nil
	case []any:
		var idx int
		if _, err := fmt.Sscanf(key, "%d", &idx); err != nil {
			return nil, err
		}
		if idx < 0 || idx >= len(v) {
			return nil, fmt.Errorf("index out of bounds: %d", idx)
		}
		newChild, err := b.setJSONValue(v[idx], path[1:], value)
		if err != nil {
			return nil, err
		}
		v[idx] = newChild
		return v, nil
	}
	return nil, fmt.Errorf("path not found or not a container")
}

// BuildRequestWithVector constructs an HTTP request injecting the payload into the specified vector.
func (b *BaseModule) BuildRequestWithVector(ctx context.Context, method string, u *url.URL, vector InputVector, payload string) (*http.Request, error) {
	var body io.Reader
	if len(b.OriginalBody) > 0 {
		body = bytes.NewReader(b.OriginalBody)
	}

	var req *http.Request
	var err error
	var newU = *u

	switch vector.Type {
	case VectorQueryParam:
		q := newU.Query()
		q.Set(vector.Key, payload)
		newU.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, method, newU.String(), body)

	case VectorFormBody:
		var values url.Values
		if len(b.OriginalBody) > 0 {
			values, _ = url.ParseQuery(string(b.OriginalBody))
		} else {
			values = url.Values{}
		}
		values.Set(vector.Key, payload)
		req, err = http.NewRequestWithContext(ctx, method, newU.String(), strings.NewReader(values.Encode()))

	case VectorJSONBody:
		var newBodyBytes []byte
		if len(b.OriginalBody) > 0 {
			newBodyBytes, err = b.MutateJSON(b.OriginalBody, vector.JSONPath, payload)
			if err != nil {
				// fallback if mutate fails
				bodyMap := make(map[string]any)
				bodyMap[vector.Key] = payload
				newBodyBytes, _ = json.Marshal(bodyMap)
			}
		} else {
			bodyMap := make(map[string]any)
			bodyMap[vector.Key] = payload
			newBodyBytes, _ = json.Marshal(bodyMap)
		}
		req, err = http.NewRequestWithContext(ctx, method, newU.String(), bytes.NewReader(newBodyBytes))

	case VectorHeader:
		req, err = http.NewRequestWithContext(ctx, method, newU.String(), body)

	case VectorPathSegment:
		var idx int
		_, _ = fmt.Sscanf(vector.Key, "path[%d]", &idx)
		segments := strings.Split(strings.TrimLeft(newU.Path, "/"), "/")
		if idx >= 0 && idx < len(segments) {
			segments[idx] = payload
		}
		newU.Path = "/" + strings.Join(segments, "/")
		req, err = http.NewRequestWithContext(ctx, method, newU.String(), body)

	default:
		return nil, fmt.Errorf("unsupported vector type: %v", vector.Type)
	}

	if err != nil {
		return nil, err
	}

	// Copy original headers
	if b.OriginalHeaders != nil {
		req.Header = b.OriginalHeaders.Clone()
	} else {
		req.Header = http.Header{}
	}

	// Apply specific header mutations
	if vector.Type == VectorHeader {
		if strings.HasPrefix(strings.ToLower(vector.Key), "cookie:") {
			cookieName := strings.TrimSpace(vector.Key[7:])

			// We must replace this specific cookie in the Cookie header.
			var newCookies []string
			if cookieHeader := req.Header.Get("Cookie"); cookieHeader != "" {
				parts := strings.Split(cookieHeader, ";")
				for _, c := range parts {
					c = strings.TrimSpace(c)
					if !strings.HasPrefix(c, cookieName+"=") {
						newCookies = append(newCookies, c)
					}
				}
			}
			newCookies = append(newCookies, fmt.Sprintf("%s=%s", cookieName, payload))
			req.Header.Set("Cookie", strings.Join(newCookies, "; "))
		} else {
			req.Header.Set(vector.Key, payload)
		}
	} else if vector.Type == VectorFormBody {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else if vector.Type == VectorJSONBody {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

func (b *BaseModule) DiscoverReflection(ctx context.Context, u *url.URL, vector InputVector) []ReflectionContext {
	probe := "PROBE" + time.Now().Format("05.000")

	method := "GET"
	if vector.Type == VectorFormBody || vector.Type == VectorJSONBody {
		method = "POST"
	}

	req, err := b.BuildRequestWithVector(ctx, method, u, vector, probe)
	if err != nil || req == nil {
		return nil
	}

	client := b.Client
	if client == nil {
		client = http.DefaultClient
	}

	if b.Cookies != "" {
		req.Header.Set("Cookie", b.Cookies)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	body := string(bodyBytes)
	var reflections []ReflectionContext

	start := 0
	for {
		idx := strings.Index(body[start:], probe)
		if idx == -1 {
			break
		}
		absoluteIdx := start + idx
		contextType := b.analyzeContext(body, absoluteIdx, probe)
		reflections = append(reflections, ReflectionContext{
			Type:     contextType,
			Location: absoluteIdx,
		})
		start = absoluteIdx + len(probe)
	}

	return reflections
}

func (b *BaseModule) analyzeContext(body string, idx int, probe string) ReflectionType {
	// Very simple context analysis
	// Look back for tags or attributes
	preceding := body[:idx]

	// Check if we are inside a <script> tag
	scriptStart := strings.LastIndex(strings.ToLower(preceding), "<script")
	scriptEnd := strings.LastIndex(strings.ToLower(preceding), "</script>")
	if scriptStart > scriptEnd {
		return ContextScript
	}

	// Check if we are inside an attribute (e.g., value='PROBE')
	// Find the last '<'
	tagStart := strings.LastIndex(preceding, "<")
	tagEnd := strings.LastIndex(preceding, ">")
	if tagStart > tagEnd {
		// We are inside a tag. Check if we are inside quotes.
		// This is a very rough heuristic.
		inQuotes := false
		for i := tagStart; i < len(preceding); i++ {
			if body[i] == '"' || body[i] == '\'' {
				inQuotes = !inQuotes
			}
		}
		if inQuotes {
			return ContextAttribute
		}
	}

	return ContextHTML
}

func NewBaseModule() *BaseModule {
	return &BaseModule{
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
		MaxThreads: 10,
		PoCs:       make([]ProofOfConcept, 0),
	}
}

func escapeBash(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}

// GenerateCurlCommand builds a curl command string from an *http.Request and its body.
func GenerateCurlCommand(req *http.Request, bodyBytes []byte) string {
	if req == nil || req.URL == nil {
		return ""
	}

	// Try to get body from request if not provided
	if len(bodyBytes) == 0 && req.GetBody != nil {
		if bodyReadCloser, err := req.GetBody(); err == nil {
			bodyBytes, _ = io.ReadAll(bodyReadCloser)
			bodyReadCloser.Close()
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("curl -X %s '%s'", req.Method, escapeBash(req.URL.String())))
	for k, vals := range req.Header {
		for _, v := range vals {
			sb.WriteString(fmt.Sprintf(" -H '%s: %s'", escapeBash(k), escapeBash(v)))
		}
	}
	if len(bodyBytes) > 0 {
		// Escape single quotes for bash
		bodyStr := escapeBash(string(bodyBytes))
		sb.WriteString(fmt.Sprintf(" -d '%s'", bodyStr))
	}
	return sb.String()
}

// RecordPoC generates a curl command and records the Proof of Concept.
func (b *BaseModule) RecordPoC(req *http.Request, bodyBytes []byte, description string) {
	var curlCmd string
	if req != nil {
		curlCmd = GenerateCurlCommand(req, bodyBytes)
	} else {
		curlCmd = "No request generated"
	}
	b.PocMu.Lock()
	defer b.PocMu.Unlock()
	b.PoCs = append(b.PoCs, ProofOfConcept{
		Description: description,
		Request:     curlCmd,
	})
}
