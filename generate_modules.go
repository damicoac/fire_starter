package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/template"
)

type Decision struct {
	UseCase              string `json:"use_case"`
	Technique            string `json:"technique"`
	Function             string `json:"function"`
	ProblemTheToolSolves string `json:"problem_the_tool_solves"`
	Identifier           string `json:"identifier"`
}

type DecisionsData struct {
	Decisions []Decision `json:"decisions"`
}

type TemplateData struct {
	PackageName   string
	StructName    string
	ResultName    string
	Technique     string
	Description   string
}

const moduleTemplate = `package modules

import (
	"context"
	"sync"
)

// {{.ResultName}} holds the result of the {{.StructName}} module execution.
type {{.ResultName}} struct {
	Target string ` + "`" + `json:"target"` + "`" + `
	Status string ` + "`" + `json:"status"` + "`" + `
	Detail string ` + "`" + `json:"detail,omitempty"` + "`" + `
}

// {{.StructName}} executes the {{.Technique}} security technique.
// Description: {{.Description}}
type {{.StructName}} struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []{{.ResultName}}
}

// New{{.StructName}} creates a new instance of {{.StructName}}.
func New{{.StructName}}(target string) *{{.StructName}} {
	return &{{.StructName}}{
		Target:     target,
		maxThreads: 10, // Reasonable default concurrency
	}
}

// SetThreads sets the number of concurrent execution threads.
func (m *{{.StructName}}) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

// Execute performs the module's core tasks concurrently.
func (m *{{.StructName}}) Execute(ctx context.Context) ([]{{.ResultName}}, error) {
	m.results = make([]{{.ResultName}}, 0)

	// In a real implementation, jobs would be specific tasks or payloads
	jobs := make(chan string, 100)
	var wg sync.WaitGroup

	// Dummy job population
	for i := 0; i < 5; i++ {
		jobs <- fmt.Sprintf("payload-%d", i)
	}
	close(jobs)

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					// TODO: Implement actual {{.Technique}} logic here
					_ = job // use job

					m.mu.Lock()
					m.results = append(m.results, {{.ResultName}}{
						Target: m.Target,
						Status: "completed",
						Detail: "Processed " + job,
					})
					m.mu.Unlock()
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
		// Wait for remaining goroutines to exit after cancellation
		<-done
		return m.results, ctx.Err()
	}
}
`

// toCamelCase converts snake_case to CamelCase
func toCamelCase(s string) string {
	parts := strings.Split(s, "_")
	for i := range parts {
		if parts[i] == "api" {
			parts[i] = "API"
		} else if parts[i] == "xss" {
			parts[i] = "XSS"
		} else if parts[i] == "sql" {
			parts[i] = "SQL"
		} else if parts[i] == "idor" {
			parts[i] = "IDOR"
		} else if parts[i] == "csrf" {
			parts[i] = "CSRF"
		} else if parts[i] == "ssrf" {
			parts[i] = "SSRF"
		} else if parts[i] == "jwt" {
			parts[i] = "JWT"
		} else if parts[i] == "xml" {
			parts[i] = "XML"
		} else if parts[i] == "dom" {
			parts[i] = "DOM"
		} else if parts[i] == "os" {
			parts[i] = "OS"
		} else if parts[i] == "saml" {
			parts[i] = "SAML"
		} else if parts[i] == "ldap" {
			parts[i] = "LDAP"
		} else if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

func main() {
	jsonFile, err := os.ReadFile("src/matrix/decisions.json")
	if err != nil {
		fmt.Println("Error reading decisions.json:", err)
		return
	}

	var data DecisionsData
	if err := json.Unmarshal(jsonFile, &data); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

	tmpl, err := template.New("module").Parse(moduleTemplate)
	if err != nil {
		fmt.Println("Error parsing template:", err)
		return
	}

	// We'll also need to add fmt to imports in the template dynamically if it's used
	// The template above uses fmt.Sprintf, so we need to ensure fmt is imported.
	// Actually, let's just make sure fmt is in the template.

	for _, d := range data.Decisions {
		fileName := fmt.Sprintf("src/modules/%s.go", d.Technique)
		
		// Skip if file already exists
		if _, err := os.Stat(fileName); err == nil {
			fmt.Printf("Skipping %s, already exists.\n", fileName)
			continue
		}

		structName := toCamelCase(d.Technique)
		
		td := TemplateData{
			PackageName: "modules",
			StructName:  structName,
			ResultName:  structName + "Result",
			Technique:   d.Technique,
			Description: d.Function,
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, td); err != nil {
			fmt.Println("Error executing template:", err)
			continue
		}

		// Ensure imports include fmt
		content := buf.String()
		content = strings.Replace(content, "import (\n\t\"context\"", "import (\n\t\"context\"\n\t\"fmt\"", 1)

		if err := os.WriteFile(fileName, []byte(content), 0644); err != nil {
			fmt.Println("Error writing file:", err)
		} else {
			fmt.Printf("Created %s\n", fileName)
		}
	}
}
