package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestWebCrawler_Crawl(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `
			<html>
				<body>
					<a href="/page1">Page 1</a>
					<a href="/page2">Page 2</a>
					<img src="/image.png" />
					<a href="https://external.com/out">Out of scope</a>
				</body>
			</html>
		`)
	})

	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `
			<html>
				<body>
					<a href="/page3">Page 3</a>
					<link rel="stylesheet" href="/style.css">
				</body>
			</html>
		`)
	})

	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body><h1>Page 2</h1></body></html>`)
	})

	mux.HandleFunc("/page3", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body><h1>Page 3</h1></body></html>`)
	})

	mux.HandleFunc("/image.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("fake image data"))
	})

	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write([]byte("body { color: red; }"))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	crawler := NewWebCrawler(ts.URL, nil, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	sort.Strings(results)

	hasRoot := false
	hasPage1 := false
	hasPage2 := false
	hasImage := false
	hasExternal := false

	for _, u := range results {
		if u == ts.URL || u == ts.URL+"/" {
			hasRoot = true
		}
		if strings.HasSuffix(u, "/page1") {
			hasPage1 = true
		}
		if strings.HasSuffix(u, "/page2") {
			hasPage2 = true
		}
		if strings.HasSuffix(u, "/image.png") {
			hasImage = true
		}
		if strings.Contains(u, "external.com") {
			hasExternal = true
		}
	}

	if !hasRoot {
		t.Errorf("Expected root page in crawled results, got: %v", results)
	}
	if !hasPage1 {
		t.Errorf("Expected /page1 in crawled results, got: %v", results)
	}
	if !hasPage2 {
		t.Errorf("Expected /page2 in crawled results, got: %v", results)
	}
	if !hasImage {
		t.Errorf("Expected static asset /image.png in crawled results, got: %v", results)
	}
	if hasExternal {
		t.Errorf("External link should have been filtered out of scope, got: %v", results)
	}
}

func TestWebCrawler_Crawl_SubpathRelativeLinks(t *testing.T) {
	mux := http.NewServeMux()

	// Entry page links into a DIFFERENT directory; the relative href under test
	// is served only on that subpage, so resolution against the entry URL
	// (the old bug) would produce /blog/comments.html instead of the correct
	// /blog/guides/comments.html.
	mux.HandleFunc("/blog/post1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body><a href="guides/post2">Guide</a></body></html>`)
	})

	mux.HandleFunc("/blog/guides/post2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body><a href="comments.html">Comments</a></body></html>`)
	})

	mux.HandleFunc("/blog/guides/comments.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body><h1>Comments</h1></body></html>`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	crawler := NewWebCrawler(ts.URL+"/blog/post1", nil, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	foundComments := false
	bogusComments := false
	for _, u := range results {
		if strings.HasSuffix(u, "/blog/guides/comments.html") {
			foundComments = true
		}
		if strings.HasSuffix(u, "/blog/comments.html") {
			bogusComments = true
		}
	}
	if !foundComments {
		t.Errorf("Expected relative link on /blog/guides/post2 to resolve against that page (/blog/guides/comments.html), got: %v", results)
	}
	if bogusComments {
		t.Errorf("Relative link must not be resolved against the entry URL (/blog/comments.html is wrong), got: %v", results)
	}
}

func TestWebCrawler_ContextCancel(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprintln(w, "<html><body>slow</body></html>")
	}))
	defer ts.Close()

	crawler := NewWebCrawler(ts.URL, nil, 3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	results, err := crawler.Crawl(ctx)
	if err != nil {
		t.Fatalf("Expected no error on cancel, got %v", err)
	}
	if len(results) > 0 {
		t.Errorf("Expected 0 results on canceled context, got %d", len(results))
	}
}
