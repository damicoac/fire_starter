package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func main() {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	req1, _ := http.NewRequest("GET", "http://192.168.64.4/DVWA/login.php", nil)
	resp1, err := client.Do(req1)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp1.Body.Close()
	
	body, _ := io.ReadAll(resp1.Body)
	re := regexp.MustCompile(`name='user_token' value='([a-zA-Z0-9]+)'`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		fmt.Println("No token found")
		return
	}
	token := matches[1]
	
	var sessionCookie string
	for _, c := range resp1.Cookies() {
		if c.Name == "PHPSESSID" {
			sessionCookie = c.Value
		}
	}
	
	form := url.Values{}
	form.Add("username", "admin")
	form.Add("password", "password")
	form.Add("Login", "Login")
	form.Add("user_token", token)
	
	req2, _ := http.NewRequest("POST", "http://192.168.64.4/DVWA/login.php", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: sessionCookie})
	req2.AddCookie(&http.Cookie{Name: "security", Value: "low"})
	
	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp2.Body.Close()
	
	// On successful login, DVWA usually redirects to index.php
	if resp2.StatusCode == 302 {
		fmt.Printf("PHPSESSID=%s; security=low\n", sessionCookie)
	} else {
		fmt.Println("Login failed, status:", resp2.StatusCode)
	}
}
