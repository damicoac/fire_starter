package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// oobCallbackClient is a short-timeout client for the scripted target's
// callback fetch so a malformed OOB URL cannot hang a test handler.
var oobCallbackClient = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{}}

// fetchOOBCallback mimics a vulnerable target: it fetches a loopback OOB
// callback URL (127.0.0.1:<port>/<numeric id>) embedded in s, if present.
func fetchOOBCallback(s string) {
	const marker = "http://127.0.0.1:"
	idx := strings.Index(s, marker)
	if idx < 0 {
		// ServeMux path-cleaning collapses "//" to "/" inside path-carried
		// payloads, so match the collapsed form and rebuild the scheme.
		idx = strings.Index(s, "http:/127.0.0.1:")
		if idx < 0 {
			return
		}
		s = s[:idx] + marker + s[idx+len("http:/127.0.0.1:"):]
		idx = 0
	}
	rest := s[idx+len(marker):]
	end := 0
	for end < len(rest) && !isOOBURLTerminator(rest[end]) {
		end++
	}
	callbackURL := marker + rest[:end]
	hostPort := rest[:end]
	slash := strings.Index(hostPort, "/")
	if slash <= 0 || !isAllDigits(hostPort[slash+1:]) {
		return
	}
	resp, err := oobCallbackClient.Get(callbackURL)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func isOOBURLTerminator(c byte) bool {
	switch c {
	case ' ', '\'', '"', '\\', ')', '}', '<', '>':
		return true
	}
	return false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// mustFactory resolves a registered module factory or fails the test.
func mustFactory(t *testing.T, technique string) ModuleFactory {
	t.Helper()
	f, ok := GetModuleFactory(technique)
	if !ok {
		t.Fatalf("module %s not registered", technique)
	}
	return f
}

// freeTCPPort reserves an available loopback TCP port for the duration of the
// call and releases it, so tests can bind an explicit port without colliding.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestOOBManager_PublicHostBinding(t *testing.T) {
	// A non-loopback public host with an explicit port must bind that exact
	// port on all interfaces: callback URLs name the port verbatim, so an
	// ephemeral bind would leave them pointing at a dead port.
	port := freeTCPPort(t)
	public := &OOBManager{PublicHost: fmt.Sprintf("oob.example.com:%d", port)}
	if err := public.StartOOBReceiver("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer public.StopOOBReceiver()
	gotHost, gotPort, err := net.SplitHostPort(public.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Depending on the platform the wildcard listener reports as "0.0.0.0"
	// (IPv4-only socket) or "[::]" (dual-stack socket); both include loopback.
	if (gotHost != "0.0.0.0" && gotHost != "::") || gotPort != fmt.Sprintf("%d", port) {
		t.Errorf("expected wildcard bind on port %d for explicit-port public host, got %s",
			port, public.Listener.Addr().String())
	}

	// A portless non-loopback public host keeps the ephemeral all-interface bind.
	portless := &OOBManager{PublicHost: "oob.example.com"}
	if err := portless.StartOOBReceiver("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer portless.StopOOBReceiver()
	if strings.HasPrefix(portless.Listener.Addr().String(), "127.0.0.1") {
		t.Errorf("expected non-loopback bind for portless public host, got %s", portless.Listener.Addr().String())
	}

	// A loopback public host keeps the loopback-safe bind.
	loopback := &OOBManager{PublicHost: "127.0.0.1"}
	if err := loopback.StartOOBReceiver("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer loopback.StopOOBReceiver()
	if !strings.HasPrefix(loopback.Listener.Addr().String(), "127.0.0.1") {
		t.Errorf("expected loopback bind for loopback host, got %s", loopback.Listener.Addr().String())
	}

	// A loopback public host with an explicit port keeps the loopback-safe
	// interface but binds the named port.
	loPort := freeTCPPort(t)
	loopbackPorted := &OOBManager{PublicHost: fmt.Sprintf("127.0.0.1:%d", loPort)}
	if err := loopbackPorted.StartOOBReceiver("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer loopbackPorted.StopOOBReceiver()
	if got := loopbackPorted.Listener.Addr().String(); got != fmt.Sprintf("127.0.0.1:%d", loPort) {
		t.Errorf("expected 127.0.0.1:%d bind for loopback public host with port, got %s", loPort, got)
	}

	// A case-mixed loopback name still counts as loopback.
	cased := &OOBManager{PublicHost: "Localhost"}
	if err := cased.StartOOBReceiver("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer cased.StopOOBReceiver()
	if !strings.HasPrefix(cased.Listener.Addr().String(), "127.0.0.1") {
		t.Errorf("expected loopback bind for Localhost, got %s", cased.Listener.Addr().String())
	}
}

func TestOOBManager_GenerateOOBPayloadResolvesPort(t *testing.T) {
	// Loopback public host without a port must inherit the listener port so
	// the callback URL stays reachable.
	m := &OOBManager{PublicHost: "127.0.0.1"}
	if err := m.StartOOBReceiver("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer m.StopOOBReceiver()
	payload, id := m.GenerateOOBPayload()
	if id == "" {
		t.Fatal("expected non-empty interaction id")
	}
	_, port, err := net.SplitHostPort(m.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	want := "127.0.0.1:" + port + "/" + id
	if payload != want {
		t.Errorf("expected payload %q, got %q", want, payload)
	}

	// A public host with an explicit port is used verbatim.
	hosted := &OOBManager{PublicHost: "oob.example.com:9000"}
	hostedPayload, _ := hosted.GenerateOOBPayload()
	if !strings.HasPrefix(hostedPayload, "oob.example.com:9000/") {
		t.Errorf("expected explicit-port public host verbatim, got %q", hostedPayload)
	}

	// A portless public host with a listener inherits the listener port.
	portless := &OOBManager{PublicHost: "oob.example.com"}
	if err := portless.StartOOBReceiver("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer portless.StopOOBReceiver()
	_, port2, err := net.SplitHostPort(portless.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portlessPayload, _ := portless.GenerateOOBPayload()
	if !strings.HasPrefix(portlessPayload, "oob.example.com:"+port2+"/") {
		t.Errorf("expected listener port appended to portless host, got %q", portlessPayload)
	}
}

func TestOOBManager_HitsCaptureDetails(t *testing.T) {
	m := &OOBManager{}
	if err := m.StartOOBReceiver("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer m.StopOOBReceiver()

	payload, id := m.GenerateOOBPayload()
	if payload == "" || id == "" {
		t.Fatalf("expected resolvable OOB payload, got %q/%q", payload, id)
	}

	req, err := http.NewRequest("GET", "http://"+payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "oob-test-agent/1.0")
	resp, err := oobCallbackClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	hits := m.Hits(id)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for id %s, got %d", id, len(hits))
	}
	h := hits[0]
	if h.SourceIP != "127.0.0.1" {
		t.Errorf("expected source 127.0.0.1, got %q", h.SourceIP)
	}
	if h.Path != "/"+id {
		t.Errorf("expected path /%s, got %q", id, h.Path)
	}
	if h.UserAgent != "oob-test-agent/1.0" {
		t.Errorf("expected recorded user agent, got %q", h.UserAgent)
	}
	if h.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}

	// Per-id filtering excludes other interaction ids.
	if got := m.Hits("other-id"); len(got) != 0 {
		t.Errorf("expected no hits for unknown id, got %d", len(got))
	}
	if got := m.Hits(""); len(got) < 1 {
		t.Errorf("expected all hits with empty id, got %d", len(got))
	}
}

func TestOOBEvidenceTier(t *testing.T) {
	if tier := oobEvidenceTier("id1", []OOBHit{{SourceIP: "127.0.0.1"}}); tier != EvidenceConfirmed {
		t.Errorf("expected EvidenceConfirmed with a callback, got %s", tier)
	}
	if tier := oobEvidenceTier("id1", nil); tier != EvidenceWeak {
		t.Errorf("expected EvidenceWeak without a callback, got %s", tier)
	}
}

// TestSSRFExploitation_OOBCallbackConfirms runs the ssrf_exploitation module
// through its factory with oob_host set; the scripted target fetches the OOB
// callback URL and the finding flips to confirmed.
func TestSSRFExploitation_OOBCallbackConfirms(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, key := range []string{"url", "webhook", "endpoint"} {
			if v := r.URL.Query().Get(key); v != "" {
				fetchOOBCallback(v)
			}
		}
		_, _ = w.Write([]byte("index page"))
	}))
	defer ts.Close()

	mod, err := mustFactory(t, "ssrf_exploitation")(map[string]any{
		"url":      ts.URL,
		"oob_host": "127.0.0.1",
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	out, err := mod.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results := out.([]SSRFExploitationResult)
	found := false
	for _, res := range results {
		if res.Status == "vulnerable" && strings.Contains(strings.ToLower(res.Detail), "out-of-band") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an OOB-confirmed SSRF result, got: %+v", results)
	}

	tester := mod.GetUnderlying().(*SSRFExploitation)
	pocHit := false
	for _, poc := range tester.GetPoCs() {
		if strings.Contains(poc.Description, "OOB callback (id") {
			pocHit = true
		}
	}
	if !pocHit {
		t.Error("expected a per-callback OOB hit PoC record")
	}
}

// TestSSRFExploitation_OOBNoCallbackStaysCandidate: without a callback the
// blind SSRF finding must not be reported as confirmed.
func TestSSRFExploitation_OOBNoCallbackStaysCandidate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("index page"))
	}))
	defer ts.Close()

	mod, err := mustFactory(t, "ssrf_exploitation")(map[string]any{
		"url":      ts.URL,
		"oob_host": "127.0.0.1",
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	out, err := mod.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results := out.([]SSRFExploitationResult)
	for _, res := range results {
		if res.Status == "vulnerable" && strings.Contains(strings.ToLower(res.Detail), "out-of-band") {
			t.Fatalf("OOB finding must stay candidate without a callback, got: %+v", res)
		}
	}
}

// TestSSTI_OOBCallbackConfirmsViaEvidence runs the SSTI module through its
// factory with oob_host set; the scripted target evaluates the template and
// fetches the OOB callback URL, flipping the finding to confirmed.
func TestSSTI_OOBCallbackConfirmsViaEvidence(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		carrier := r.URL.Query().Get("q")
		if carrier == "" {
			carrier = r.URL.Query().Get("name")
		}
		if carrier == "" {
			carrier = r.URL.Query().Get("template")
		}
		if carrier == "" {
			carrier = r.URL.Path
		}
		fetchOOBCallback(carrier)
		_, _ = w.Write([]byte("Processed template"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	mod, err := mustFactory(t, "server_side_template_injection_ssti")(map[string]any{
		"url":      ts.URL + "/vulnerable",
		"oob_host": "127.0.0.1",
		"threads":  16,
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	out, err := mod.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results := out.([]ServerSideTemplateInjectionSstiResult)
	found := false
	for _, res := range results {
		if res.Status == "vulnerable" && strings.Contains(strings.ToLower(res.Detail), "oob") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an OOB-confirmed SSTI result, got: %+v", results)
	}

	tester := mod.GetUnderlying().(*ServerSideTemplateInjectionSsti)
	pocHit := false
	for _, poc := range tester.GetPoCs() {
		if strings.Contains(poc.Description, "OOB callback (id") {
			pocHit = true
		}
	}
	if !pocHit {
		t.Error("expected a per-callback OOB hit PoC record")
	}
}

// TestSSTI_OOBNoCallbackStaysCandidate: without a callback the blind SSTI
// finding must not be reported as confirmed.
func TestSSTI_OOBNoCallbackStaysCandidate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Processed template"))
	}))
	defer ts.Close()

	mod, err := mustFactory(t, "server_side_template_injection_ssti")(map[string]any{
		"url":      ts.URL + "/vulnerable",
		"oob_host": "127.0.0.1",
		"threads":  16,
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	out, err := mod.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results := out.([]ServerSideTemplateInjectionSstiResult)
	for _, res := range results {
		if res.Status == "vulnerable" && strings.Contains(strings.ToLower(res.Detail), "oob") {
			t.Fatalf("OOB finding must stay candidate without a callback, got: %+v", res)
		}
	}
}

// TestXXE_OOBCallbackConfirmsViaEvidence runs the XXE module through its
// factory with oob_host set; the scripted target's XML parser resolves the
// parameter entity and fetches the OOB callback URL.
func TestXXE_OOBCallbackConfirmsViaEvidence(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fetchOOBCallback(string(body))
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	mod, err := mustFactory(t, "xml_external_entity_injection_xxe")(map[string]any{
		"url":      ts.URL,
		"oob_host": "127.0.0.1",
		"threads":  8,
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	out, err := mod.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results := out.([]XMLExternalEntityInjectionXxeResult)
	found := false
	for _, res := range results {
		if res.Status == "vulnerable" && strings.Contains(strings.ToLower(res.Detail), "oob") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an OOB-confirmed XXE result, got: %+v", results)
	}

	tester := mod.GetUnderlying().(*XMLExternalEntityInjectionXxe)
	pocHit := false
	for _, poc := range tester.GetPoCs() {
		if strings.Contains(poc.Description, "OOB callback (id") {
			pocHit = true
		}
	}
	if !pocHit {
		t.Error("expected a per-callback OOB hit PoC record")
	}
}

// TestXXE_OOBNoCallbackStaysCandidate: without a callback the blind XXE
// finding must not be reported as confirmed.
func TestXXE_OOBNoCallbackStaysCandidate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	mod, err := mustFactory(t, "xml_external_entity_injection_xxe")(map[string]any{
		"url":      ts.URL,
		"oob_host": "127.0.0.1",
		"threads":  8,
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	out, err := mod.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results := out.([]XMLExternalEntityInjectionXxeResult)
	for _, res := range results {
		if res.Status == "vulnerable" && strings.Contains(strings.ToLower(res.Detail), "oob") {
			t.Fatalf("OOB finding must stay candidate without a callback, got: %+v", res)
		}
	}
}

func TestOOBManager_NormalizeOOBHost(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"oob.example.com", "oob.example.com"},
		{"oob.example.com:9000", "oob.example.com:9000"},
		{"https://oob.example.com", "oob.example.com"},
		{"http://oob.example.com:9000/", "oob.example.com:9000"},
		{"https://oob.example.com/path?x=1", "oob.example.com"},
		{"  oob.example.com  ", "oob.example.com"},
		{"[::1]", "::1"},
		{"[::1]:9000", "[::1]:9000"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeOOBHost(tt.in); got != tt.want {
			t.Errorf("normalizeOOBHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestOOBManager_GenerateOOBPayloadSchemeStripping(t *testing.T) {
	// A scheme'd public host must never leak into the callback URL
	// (http://[https://oob.example.com]:port/id would be malformed).
	m := &OOBManager{PublicHost: "https://oob.example.com"}
	if err := m.StartOOBReceiver("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer m.StopOOBReceiver()
	_, port, err := net.SplitHostPort(m.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	payload, id := m.GenerateOOBPayload()
	if want := "oob.example.com:" + port + "/" + id; payload != want {
		t.Errorf("expected payload %q, got %q", want, payload)
	}

	// An explicit port survives normalization verbatim.
	ported := &OOBManager{PublicHost: "https://oob.example.com:9000"}
	portedPayload, portedID := ported.GenerateOOBPayload()
	if want := "oob.example.com:9000/" + portedID; portedPayload != want {
		t.Errorf("expected payload %q, got %q", want, portedPayload)
	}

	// The loopback default stays unchanged.
	loopback := &OOBManager{PublicHost: "127.0.0.1"}
	if err := loopback.StartOOBReceiver("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer loopback.StopOOBReceiver()
	loPayload, loID := loopback.GenerateOOBPayload()
	_, loPort, err := net.SplitHostPort(loopback.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if want := "127.0.0.1:" + loPort + "/" + loID; loPayload != want {
		t.Errorf("expected payload %q, got %q", want, loPayload)
	}
}

// TestOOBManager_ExplicitPortEndToEnd: a public host carrying an explicit
// port binds exactly that port, and fetching the generated callback URL
// records a hit for the interaction id.
func TestOOBManager_ExplicitPortEndToEnd(t *testing.T) {
	port := freeTCPPort(t)
	m := &OOBManager{PublicHost: fmt.Sprintf("127.0.0.1:%d", port)}
	if err := m.StartOOBReceiver("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer m.StopOOBReceiver()

	payload, id := m.GenerateOOBPayload()
	if id == "" || !strings.HasPrefix(payload, fmt.Sprintf("127.0.0.1:%d/", port)) {
		t.Fatalf("unexpected payload %q (id %q)", payload, id)
	}

	resp, err := oobCallbackClient.Get("http://" + payload)
	if err != nil {
		t.Fatalf("callback fetch failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	deadline := time.Now().Add(2 * time.Second)
	for len(m.Hits(id)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	hits := m.Hits(id)
	if len(hits) == 0 {
		t.Fatal("expected the fetched callback URL to be recorded as a hit")
	}
	if !strings.HasSuffix(hits[0].Path, "/"+id) {
		t.Errorf("expected hit path /%s, got %q", id, hits[0].Path)
	}
}

// TestSSRFExploitation_OOBExplicitPortEndToEnd runs the ssrf_exploitation
// module with an oob_host carrying an explicit port: the listener must bind
// that port, the scripted target must reach the generated callback URL, and
// the finding must flip to confirmed.
func TestSSRFExploitation_OOBExplicitPortEndToEnd(t *testing.T) {
	port := freeTCPPort(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, key := range []string{"url", "webhook", "endpoint"} {
			if v := r.URL.Query().Get(key); v != "" {
				fetchOOBCallback(v)
			}
		}
		_, _ = w.Write([]byte("index page"))
	}))
	defer ts.Close()

	mod, err := mustFactory(t, "ssrf_exploitation")(map[string]any{
		"url":      ts.URL,
		"oob_host": fmt.Sprintf("127.0.0.1:%d", port),
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	out, err := mod.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results := out.([]SSRFExploitationResult)
	found := false
	for _, res := range results {
		if res.Status == "vulnerable" && strings.Contains(strings.ToLower(res.Detail), "out-of-band") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an OOB-confirmed SSRF result with explicit-port oob_host, got: %+v", results)
	}
}
