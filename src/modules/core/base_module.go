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
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
)

type ReflectionContext struct {
	Type     ReflectionType
	Location int
}

type ProofOfConcept struct {
	Description string `json:"description"`
	Request     string `json:"request"`
}

const MaxResponseBodyBytes = 2 * 1024 * 1024 // 2 MB maximum bound to prevent memory exhaustion

// ReadBoundedBody reads up to maxBytes from r to prevent OOM memory exhaustion on unbounded streams or huge payloads.
func ReadBoundedBody(r io.Reader, maxBytes int64) ([]byte, error) {
	data, _, err := ReadBoundedBodyWithTruncation(r, maxBytes)
	return data, err
}

// ReadBoundedBodyWithTruncation behaves like ReadBoundedBody and additionally
// reports whether the reader was cut off at maxBytes, so callers can
// distinguish a genuinely short body from a silently truncated one.
func ReadBoundedBodyWithTruncation(r io.Reader, maxBytes int64) ([]byte, bool, error) {
	if r == nil {
		return nil, false, nil
	}
	if maxBytes <= 0 {
		maxBytes = MaxResponseBodyBytes
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBytes))
	if err != nil {
		return data, false, err
	}
	if int64(len(data)) == maxBytes {
		var probe [1]byte
		if n, _ := r.Read(probe[:]); n > 0 {
			return data, true, nil
		}
	}
	return data, false, nil
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

func (b *BaseModule) SetCookies(cookies string) {
	b.Mu.Lock()
	defer b.Mu.Unlock()
	b.Cookies = cookies
}

func (b *BaseModule) GetCookies() string {
	b.Mu.Lock()
	defer b.Mu.Unlock()
	return b.Cookies
}

func (b *BaseModule) GetPoCs() []ProofOfConcept {
	b.PocMu.Lock()
	defer b.PocMu.Unlock()
	if len(b.PoCs) == 0 {
		return nil
	}
	result := make([]ProofOfConcept, len(b.PoCs))
	copy(result, b.PoCs)
	return result
}

func (b *BaseModule) SetThreads(count int) {
	b.Mu.Lock()
	defer b.Mu.Unlock()
	if count > 0 {
		b.MaxThreads = count
	}
}

type OOBInteraction struct {
	ID        string
	Protocol  string // "http" or "dns"
	RemoteIP  string
	Path      string
	UserAgent string
	Timestamp time.Time
}

// OOBHit is one out-of-band callback received by the OOB listener, rendered
// in the shape modules record as proof-of-concept evidence.
type OOBHit struct {
	SourceIP  string
	Path      string
	UserAgent string
	Timestamp time.Time
}

// oobNoCallbackControl is the false-condition/baseline sentinel used when
// routing out-of-band callback evidence through EvaluateDifferentialEvidence:
// the true condition is a callback signal, the false condition and baseline
// are the no-callback control, so a callback yields EvidenceConfirmed while
// silence yields EvidenceWeak (candidate, not confirmed).
const oobNoCallbackControl = "no oob callback observed"

// oobEvidenceTier converts observed OOB callback hits into an evidence tier
// via EvaluateDifferentialEvidence: at least one callback for the interaction
// confirms the probe; silence stays inconclusive (candidate).
func oobEvidenceTier(id string, hits []OOBHit) EvidenceTier {
	signal := ""
	if len(hits) > 0 {
		signal = "oob callback observed for interaction " + id
	}
	return EvaluateDifferentialEvidence(signal, oobNoCallbackControl, oobNoCallbackControl, true)
}

// oobHitDescription renders a single OOB callback hit for PoC records.
func oobHitDescription(id string, h OOBHit) string {
	return fmt.Sprintf("OOB callback (id %s) from %s path %q user-agent %q", id, h.SourceIP, h.Path, h.UserAgent)
}

type OOBManager struct {
	PublicHost   string
	Listener     net.Listener
	Server       *http.Server
	Interactions map[string][]OOBInteraction
	Mu           sync.Mutex
}

// normalizeOOBHost canonicalizes a configured public OOB host for port
// detection and callback URL construction: a leading scheme (http://,
// https://, ...) and any path/query are stripped, and a bracket-wrapped bare
// host such as "[::1]" is unwrapped. Bracketed host:port forms like
// "[::1]:9000" are preserved verbatim so net.SplitHostPort keeps parsing them.
func normalizeOOBHost(host string) string {
	h := strings.TrimSpace(host)
	if i := strings.Index(h, "://"); i != -1 {
		h = h[i+3:]
		if j := strings.IndexAny(h, "/?#"); j != -1 {
			h = h[:j]
		}
	}
	if _, _, err := net.SplitHostPort(h); err != nil {
		h = strings.Trim(h, "[]")
	}
	return h
}

// oobHostIsLoopback reports whether the configured public OOB host (optionally
// host:port) refers to a loopback address.
func oobHostIsLoopback(host string) bool {
	h := host
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(h, "localhost")
}

// hostHasPort reports whether host already carries an explicit port.
func hostHasPort(host string) bool {
	_, _, err := net.SplitHostPort(host)
	return err == nil
}

func (m *OOBManager) StartOOBReceiver(listenAddr string) error {
	// With a configured public host the callback must be reachable from the
	// target's network, so bind on all interfaces instead of loopback. When
	// the public host carries an explicit port, the listener must use that
	// same port: GenerateOOBPayload names it verbatim, so an ephemeral bind
	// would leave callbacks pointing at a port nobody listens on.
	m.Mu.Lock()
	publicHost := normalizeOOBHost(m.PublicHost)
	m.Mu.Unlock()
	if publicHost != "" && !oobHostIsLoopback(publicHost) {
		if _, port, err := net.SplitHostPort(publicHost); err == nil && port != "" {
			listenAddr = net.JoinHostPort("0.0.0.0", port)
		} else {
			listenAddr = "0.0.0.0:0"
		}
	} else if publicHost != "" && hostHasPort(publicHost) {
		// Loopback public host with an explicit port: keep the loopback-safe
		// interface but honor the port the callback URLs name.
		if _, port, err := net.SplitHostPort(publicHost); err == nil && port != "" {
			listenAddr = net.JoinHostPort("127.0.0.1", port)
		}
	}
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.Trim(r.URL.Path, "/")
		if id != "" {
			interaction := OOBInteraction{
				ID:        id,
				Protocol:  "http",
				RemoteIP:  r.RemoteAddr,
				Path:      r.URL.Path,
				UserAgent: r.UserAgent(),
				Timestamp: time.Now(),
			}
			m.Mu.Lock()
			m.Interactions[id] = append(m.Interactions[id], interaction)
			m.Mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})
	m.Mu.Lock()
	m.Listener = l
	m.Interactions = make(map[string][]OOBInteraction)
	m.Server = &http.Server{Handler: handler}
	server := m.Server
	m.Mu.Unlock()

	go func() {
		_ = server.Serve(l)
	}()
	return nil
}

func (m *OOBManager) StopOOBReceiver() {
	// Snapshot and clear under the lock, then shut down outside of it:
	// Shutdown waits for in-flight handlers which themselves need m.Mu.
	m.Mu.Lock()
	server, listener := m.Server, m.Listener
	m.Server, m.Listener = nil, nil
	m.Mu.Unlock()

	if server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
	if listener != nil {
		_ = listener.Close()
	}
}

func (m *OOBManager) GenerateOOBPayload() (string, string) {
	m.Mu.Lock()
	host := normalizeOOBHost(m.PublicHost)
	listener := m.Listener
	m.Mu.Unlock()

	// No resolvable OOB host: a degenerate "/<id>" payload would produce a
	// malformed URL, so report the absence explicitly.
	if host == "" && listener != nil {
		host = listener.Addr().String()
	}
	if host == "" {
		return "", ""
	}
	// A public host without an explicit port needs the ephemeral listener
	// port appended, otherwise the callback URL would target port 80.
	if listener != nil && !hostHasPort(host) {
		if _, port, err := net.SplitHostPort(listener.Addr().String()); err == nil && port != "" {
			host = net.JoinHostPort(host, port)
		}
	}
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	return fmt.Sprintf("%s/%s", host, id), id
}

// Hits returns a snapshot of the out-of-band callback hits recorded by this
// manager. When id is non-empty only hits belonging to that interaction id
// are returned; an empty id returns every recorded hit.
func (m *OOBManager) Hits(id string) []OOBHit {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	hits := make([]OOBHit, 0)
	for interactionID, interactions := range m.Interactions {
		if id != "" && interactionID != id {
			continue
		}
		for _, in := range interactions {
			sourceIP := in.RemoteIP
			if host, _, err := net.SplitHostPort(in.RemoteIP); err == nil {
				sourceIP = host
			}
			hits = append(hits, OOBHit{
				SourceIP:  sourceIP,
				Path:      in.Path,
				UserAgent: in.UserAgent,
				Timestamp: in.Timestamp,
			})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Timestamp.Before(hits[j].Timestamp) })
	return hits
}

// DiscoverVectors finds all input vectors (query params, form body, etc.) from a request.
// It returns a new reader for the body so it can be read again if needed. If the
// body cannot be read, it returns an error instead of a partial result.
func (b *BaseModule) DiscoverVectors(u *url.URL, body io.Reader, contentType string, headers http.Header) ([]InputVector, io.Reader, error) {
	vectors := []InputVector{}
	var bodyBytes []byte
	var newBody io.Reader

	if body != nil {
		var err error
		bodyBytes, err = ReadBoundedBody(body, MaxResponseBodyBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("discover input vectors: failed to read request body: %w", err)
		}
	}

	b.Mu.Lock()
	if headers != nil {
		b.OriginalHeaders = headers.Clone()
	} else {
		b.OriginalHeaders = http.Header{}
	}
	b.OriginalBody = bodyBytes
	b.Mu.Unlock()

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
	return vectors, newBody, nil
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
			// Copy the path slice before appending: reusing `path`'s backing
			// array via append aliases sibling branches and corrupts stored
			// JSONPaths at depth >= 4.
			np := make([]string, len(path), len(path)+1)
			copy(np, path)
			np = append(np, k)
			vectors = append(vectors, b.discoverJSONVectors(val, np)...)
		}
	case []any:
		if len(v) > 0 {
			np := make([]string, len(path), len(path)+1)
			copy(np, path)
			np = append(np, "0")
			vectors = append(vectors, b.discoverJSONVectors(v[0], np)...)
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

// rawValuesWithPayload replaces the value of key with payload in values and
// returns the encoded query/body string. Payloads that already contain
// percent-encoding are spliced verbatim so they are not double-escaped
// ("..%2f" must reach the wire as "..%2f", not "..%252f").
func rawValuesWithPayload(values url.Values, key, payload string) string {
	if !strings.Contains(payload, "%") {
		values.Set(key, payload)
		return values.Encode()
	}
	values.Del(key)
	pairs := make([]string, 0, len(values)+1)
	for k, vs := range values {
		escapedKey := url.QueryEscape(k)
		for _, v := range vs {
			pairs = append(pairs, escapedKey+"="+url.QueryEscape(v))
		}
	}
	pairs = append(pairs, url.QueryEscape(key)+"="+payload)
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// BuildRequestWithVector constructs an HTTP request injecting the payload into the specified vector.
func (b *BaseModule) BuildRequestWithVector(ctx context.Context, method string, u *url.URL, vector InputVector, payload string) (*http.Request, error) {
	b.Mu.Lock()
	var origBody []byte
	if len(b.OriginalBody) > 0 {
		origBody = make([]byte, len(b.OriginalBody))
		copy(origBody, b.OriginalBody)
	}
	var origHeaders http.Header
	if b.OriginalHeaders != nil {
		origHeaders = b.OriginalHeaders.Clone()
	}
	b.Mu.Unlock()

	var body io.Reader
	if len(origBody) > 0 {
		body = bytes.NewReader(origBody)
	}

	var req *http.Request
	var err error
	var newU = *u

	switch vector.Type {
	case VectorQueryParam:
		newU.RawQuery = rawValuesWithPayload(newU.Query(), vector.Key, payload)
		req, err = http.NewRequestWithContext(ctx, method, newU.String(), body)

	case VectorFormBody:
		var values url.Values
		if len(origBody) > 0 {
			var parseErr error
			values, parseErr = url.ParseQuery(string(origBody))
			if parseErr != nil {
				// Sending a body containing only the payload would corrupt
				// differential judging; fail the vector instead.
				return nil, fmt.Errorf("failed to parse original form body for vector %q: %w", vector.Key, parseErr)
			}
		} else {
			values = url.Values{}
		}
		req, err = http.NewRequestWithContext(ctx, method, newU.String(), strings.NewReader(rawValuesWithPayload(values, vector.Key, payload)))

	case VectorJSONBody:
		var newBodyBytes []byte
		if len(origBody) > 0 {
			var mutateErr error
			newBodyBytes, mutateErr = b.MutateJSON(origBody, vector.JSONPath, payload)
			if mutateErr != nil {
				// Replacing the whole body with a fabricated flat object would
				// send a request the target never issued; fail instead.
				return nil, fmt.Errorf("failed to mutate JSON body for vector %q: %w", vector.Key, mutateErr)
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
		if _, err := fmt.Sscanf(vector.Key, "path[%d]", &idx); err != nil {
			return nil, fmt.Errorf("invalid path segment key format: %s", vector.Key)
		}
		segments := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
		if idx < 0 || idx >= len(segments) {
			// Silently skipping the mutation would judge an unmutated request.
			return nil, fmt.Errorf("path segment index out of range: %s", vector.Key)
		}
		if strings.Contains(payload, "%") {
			// Payload is already percent-encoded; keep it verbatim so
			// url.URL.String() does not re-escape '%' to "%25".
			segments[idx] = payload
		} else {
			segments[idx] = (&url.URL{Path: payload}).EscapedPath()
		}
		rawPath := "/" + strings.Join(segments, "/")
		decoded, decodeErr := url.PathUnescape(rawPath)
		if decodeErr != nil {
			return nil, fmt.Errorf("invalid encoded path payload for vector %q: %w", vector.Key, decodeErr)
		}
		newU.Path = decoded
		newU.RawPath = rawPath
		req, err = http.NewRequestWithContext(ctx, method, newU.String(), body)

	default:
		return nil, fmt.Errorf("unsupported vector type: %v", vector.Type)
	}

	if err != nil {
		return nil, err
	}

	// Copy original headers
	if origHeaders != nil {
		req.Header = origHeaders.Clone()
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

var reflectionProbeCounter uint64

// DiscoverReflection sends a canary probe through the given vector and reports
// where it was reflected. Build, transport, and read failures are returned as
// errors so callers can downgrade to "inconclusive" instead of treating the
// vector as unreflected.
func (b *BaseModule) DiscoverReflection(ctx context.Context, u *url.URL, vector InputVector) ([]ReflectionContext, error) {
	// Atomic suffix prevents probe collisions between requests issued within
	// the same millisecond.
	probe := fmt.Sprintf("PROBE%d.%s", atomic.AddUint64(&reflectionProbeCounter, 1), time.Now().Format("05.000"))

	method := "GET"
	if vector.Type == VectorFormBody || vector.Type == VectorJSONBody {
		method = "POST"
	}

	req, err := b.BuildRequestWithVector(ctx, method, u, vector, probe)
	if err != nil {
		return nil, fmt.Errorf("failed to build reflection probe request: %w", err)
	}
	if req == nil {
		return nil, fmt.Errorf("reflection probe request build returned nil")
	}

	client := b.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	cookies := b.GetCookies()
	if cookies != "" {
		if vector.Type == VectorHeader && strings.HasPrefix(strings.ToLower(vector.Key), "cookie:") {
			// Merge session cookies around the vector cookie instead of
			// overwriting the probe: overwriting discarded the injected
			// payload and produced empty reflections on authenticated targets.
			req.Header.Set("Cookie", mergeCookieHeaders(req.Header.Get("Cookie"), cookies))
		} else {
			req.Header.Set("Cookie", cookies)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reflection probe request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read reflection probe response: %w", err)
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

	return reflections, nil
}

// mergeCookieHeaders merges session cookies into a Cookie header without
// displacing cookies already present (the vector probe wins its own name).
func mergeCookieHeaders(existing, session string) string {
	if existing == "" {
		return session
	}
	if session == "" {
		return existing
	}
	present := make(map[string]bool)
	for _, part := range strings.Split(existing, ";") {
		name := strings.TrimSpace(part)
		if i := strings.Index(name, "="); i >= 0 {
			name = name[:i]
		}
		present[strings.ToLower(name)] = true
	}
	var extra []string
	for _, part := range strings.Split(session, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := part
		if i := strings.Index(part, "="); i >= 0 {
			name = part[:i]
		}
		if !present[strings.ToLower(name)] {
			present[strings.ToLower(name)] = true
			extra = append(extra, part)
		}
	}
	if len(extra) == 0 {
		return existing
	}
	return existing + "; " + strings.Join(extra, "; ")
}

var (
	// attributeValueSpanRe matches `name="value"` / `name='value'` spans so the
	// reflection position can be checked against the quoted value region
	// instead of relying on raw quote parity (apostrophes in text such as
	// title='It's' previously caused misclassification).
	attributeValueSpanRe = regexp.MustCompile(`[^\s"'>=]+\s*=\s*("[^"]*"|'[^']*')`)
	// unquotedAttrTailRe matches an attribute whose unquoted value is open at
	// the end of the inspected prefix (e.g. `<a href=PROBE`).
	unquotedAttrTailRe = regexp.MustCompile(`[^\s"'>=]+\s*=\s*[^\s"'<>]*$`)
	// openQuotedAttrTailRe matches an attribute whose quoted value is still
	// open at the end of the inspected prefix (e.g. `<input value='PROBE`).
	openQuotedAttrTailRe = regexp.MustCompile(`[^\s"'>=]+\s*=\s*("[^"]*|'[^']*)$`)
)

func (b *BaseModule) analyzeContext(body string, idx int, probe string) ReflectionType {
	// Look back for tags or attributes
	preceding := body[:idx]
	lower := strings.ToLower(preceding)

	// Check if we are inside a <script> tag. Require a real tag boundary
	// (whitespace, '>', or '/') after "<script" so occurrences inside JS
	// strings like `var s = "<script"` do not force ContextScript.
	scriptStart := strings.LastIndex(lower, "<script")
	scriptEnd := strings.LastIndex(lower, "</script>")
	if scriptStart > scriptEnd {
		tail := lower[scriptStart+len("<script"):]
		if tail == "" || tail[0] == '>' || tail[0] == '/' || tail[0] == ' ' || tail[0] == '\t' || tail[0] == '\n' || tail[0] == '\r' {
			return ContextScript
		}
	}

	// Check if we are inside an attribute (e.g., value='PROBE').
	// Find the last '<'
	tagStart := strings.LastIndex(preceding, "<")
	tagEnd := strings.LastIndex(preceding, ">")
	if tagStart > tagEnd {
		tag := preceding[tagStart:]
		rel := idx - tagStart
		for _, loc := range attributeValueSpanRe.FindAllStringSubmatchIndex(tag, -1) {
			// Group 2 is the quoted value including the quotes.
			if len(loc) >= 4 && rel >= loc[2] && rel < loc[3] {
				return ContextAttribute
			}
		}
		if unquotedAttrTailRe.MatchString(tag[:rel]) || openQuotedAttrTailRe.MatchString(tag[:rel]) {
			return ContextAttribute
		}
	}

	return ContextHTML
}

func NewBaseModule() *BaseModule {
	return &BaseModule{
		Client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: getDefaultTransport(),
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
			if b, err := ReadBoundedBody(bodyReadCloser, MaxResponseBodyBytes); err == nil {
				bodyBytes = b
			}
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
