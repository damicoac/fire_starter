package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
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
	return m.results, nil
}

func (m *UnrestrictedFileUpload) testUpload(ctx context.Context, endpoint, filename string, content []byte, mimeType string) {
	testURL := m.Target + endpoint

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create form file
	part, err := writer.CreateFormFile("file", filename)
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

	respBody, _ := io.ReadAll(resp.Body)

	// Simple heuristic: if it returns 200/201 and doesn't complain about the file type
	if (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated) &&
		!bytes.Contains(bytes.ToLower(respBody), []byte("invalid file type")) &&
		!bytes.Contains(bytes.ToLower(respBody), []byte("error")) &&
		!bytes.Contains(bytes.ToLower(respBody), []byte("not allowed")) {

		m.Mu.Lock()
		m.RecordPoC(req, body.Bytes(), fmt.Sprintf("Successfully uploaded dangerous file type (%s) to %s", filename, testURL))
		m.results = append(m.results, UnrestrictedFileUploadResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: fmt.Sprintf("Possible unrestricted file upload detected at %s using %s", testURL, filename),
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("unrestricted_file_upload_analysis", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "http://127.0.0.1")
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
