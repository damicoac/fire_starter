package core

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"sync"
	"time"
)

type UnrestrictedFileUploadResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type UnrestrictedFileUpload struct {
	BaseModule
	Target  string
	results []UnrestrictedFileUploadResult
}

func NewUnrestrictedFileUpload(target string) *UnrestrictedFileUpload {
	return &UnrestrictedFileUpload{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *UnrestrictedFileUpload) Execute(ctx context.Context) ([]UnrestrictedFileUploadResult, error) {
	m.results = make([]UnrestrictedFileUploadResult, 0)

	endpoints := []string{
		"/upload",
		"/api/upload",
		"/files/upload",
		"/media/upload",
	}

	payloads := []struct {
		filename string
		content  []byte
		mime     string
	}{
		{"test.php", []byte("<?php echo 'vuln'; ?>"), "application/x-php"},
		{"test.jsp", []byte("<% out.println(\"vuln\"); %>"), "application/octet-stream"},
		{"test.exe", []byte("MZ\x90\x00\x03\x00\x00\x00"), "application/x-msdownload"},
		{"test.html", []byte("<script>alert(1)</script>"), "text/html"},
	}

	var wg sync.WaitGroup
	jobs := make(chan string, len(endpoints))
	for _, ep := range endpoints {
		jobs <- ep
	}
	close(jobs)

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					for _, p := range payloads {
						m.testUpload(ctx, ep, p.filename, p.content, p.mime)
					}
				}
			}
		}()
	}

	wg.Wait()
	if len(m.results) == 0 {
		m.Mu.Lock()
		m.results = append(m.results, UnrestrictedFileUploadResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "No upload endpoint on the tested paths accepted a dangerous file type with retrievable storage.",
		})
		m.Mu.Unlock()
	}
	return m.results, nil
}

func (m *UnrestrictedFileUpload) testUpload(ctx context.Context, endpoint, filename string, content []byte, mimeType string) {
	testURL := m.Target + endpoint

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create the file part with the declared MIME type as an explicit
	// Content-Type header (CreateFormFile always sends octet-stream).
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, filename))
	header.Set("Content-Type", mimeType)
	part, err := writer.CreatePart(header)
	if err != nil {
		return
	}
	part.Write(content)

	// Add a submit button field just in case
	writer.WriteField("submit", "Upload")
	writer.Close()

	req, err := http.NewRequestWithContext(ctx, "POST", testURL, body)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	respBody, readErr := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if readErr != nil {
		// An unreadable response body must never be judged as an accepted
		// upload; the run-level summary accounts for it as inconclusive.
		return
	}

	// A 200/201 without rejection vocabulary only shows acceptance: flag the
	// upload as vulnerable only when a follow-up GET of the served path
	// returns the exact canary content (storage proof). The rejection
	// vocabulary covers differently-worded validators ("file extension
	// rejected", "unsupported file type", "upload failed", ...).
	rejectionTokens := []string{
		"invalid", "error", "not allowed", "not permitted", "unsupported",
		"rejected", "denied", "forbidden", "disallowed", "failed",
	}
	if (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated) &&
		!containsAnyToken(string(respBody), rejectionTokens) {

		if m.storageVerified(ctx, endpoint, filename, content) {
			m.Mu.Lock()
			m.RecordPoC(req, body.Bytes(), fmt.Sprintf("Uploaded dangerous file type (%s) to %s and retrieved the stored canary", filename, testURL))
			m.results = append(m.results, UnrestrictedFileUploadResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: fmt.Sprintf("Unrestricted file upload at %s: %s was accepted and served back with its original content", testURL, filename),
			})
			m.Mu.Unlock()
		} else {
			m.Mu.Lock()
			m.results = append(m.results, UnrestrictedFileUploadResult{
				Target: m.Target,
				Status: "inconclusive",
				Detail: fmt.Sprintf("Upload of %s to %s returned HTTP %d without a rejection, but the stored file could not be retrieved; storage unverified", filename, testURL, resp.StatusCode),
			})
			m.Mu.Unlock()
		}
	}
}

// storageVerified attempts to retrieve the uploaded canary from the paths a
// typical server would serve it from and requires the exact canary content to
// come back, proving the file was actually stored.
func (m *UnrestrictedFileUpload) storageVerified(ctx context.Context, endpoint, filename string, canary []byte) bool {
	candidates := []string{
		m.Target + endpoint + "/" + filename,
		m.Target + "/uploads/" + filename,
		m.Target + "/" + filename,
	}
	for _, u := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := m.Client.Do(req)
		if err != nil {
			continue
		}
		body, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
		resp.Body.Close()
		if err != nil || resp.StatusCode < 200 || resp.StatusCode > 299 {
			continue
		}
		if bytes.Contains(body, canary) {
			return true
		}
	}
	return false
}

func init() {
	RegisterModule("unrestricted_file_upload_analysis", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting UnrestrictedFileUploadAnalysis on: %s", target))
		tester := NewUnrestrictedFileUpload(target)
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
