package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"temp-email/internal/db"

	"github.com/gorilla/mux"
)

// SubdomainResult represents a single subdomain discovery result
type SubdomainResult struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

// SubfinderResponse represents the response from subfinder API
type SubfinderResponse struct {
	Domain      string            `json:"domain"`
	Subdomains  []SubdomainResult `json:"subdomains"`
	Count       int               `json:"count"`
	TimeSeconds float64           `json:"time_seconds"`
}

func GetInbox(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	address := vars["address"]
	emailDomain := os.Getenv("EMAIL_DOMAIN")
	if emailDomain == "" || !strings.HasSuffix(address, "@"+emailDomain) {
		http.Error(w, "Invalid email address", http.StatusBadRequest)
		return
	}

	emails, err := db.GetEmails(address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(emails)
}

// GetSubdomains discovers subdomains for a given domain using subfinder
func GetSubdomains(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := vars["domain"]

	if domain == "" {
		http.Error(w, "Domain parameter is required", http.StatusBadRequest)
		return
	}

	// Basic domain validation
	if !isValidDomain(domain) {
		http.Error(w, "Invalid domain format", http.StatusBadRequest)
		return
	}

	// Execute subfinder command with timeout context
	ctx := r.Context()
	cmd := exec.CommandContext(ctx, "subfinder", "-d", domain, "-json")
	output, err := cmd.Output()

	if err != nil {
		// Check if subfinder is not found
		if strings.Contains(err.Error(), "executable file not found") {
			http.Error(w, "Subfinder tool not found. Please install subfinder first.", http.StatusInternalServerError)
			return
		}
		// Check if context was cancelled (timeout)
		if ctx.Err() == context.DeadlineExceeded {
			http.Error(w, "Subfinder command timed out", http.StatusRequestTimeout)
			return
		}
		http.Error(w, "Error executing subfinder: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the output
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var subdomains []SubdomainResult
	var timeInfo string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip non-JSON lines (headers, info messages)
		if !strings.HasPrefix(line, "{") {
			if strings.Contains(line, "Found") && strings.Contains(line, "subdomains") && strings.Contains(line, "in") {
				timeInfo = line
			}
			continue
		}

		var result SubdomainResult
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			subdomains = append(subdomains, result)
		}
	}

	// Extract time information if available
	timeSeconds := 0.0
	if timeInfo != "" {
		// Parse time info like "Found 12 subdomains for pipedream.in in 10 seconds 124 milliseconds"
		re := regexp.MustCompile(`in (\d+) seconds? (\d+) milliseconds?`)
		matches := re.FindStringSubmatch(timeInfo)
		if len(matches) == 3 {
			if seconds, err := strconv.Atoi(matches[1]); err == nil {
				if milliseconds, err := strconv.Atoi(matches[2]); err == nil {
					timeSeconds = float64(seconds) + float64(milliseconds)/1000.0
				}
			}
		}
	}

	response := SubfinderResponse{
		Domain:      domain,
		Subdomains:  subdomains,
		Count:       len(subdomains),
		TimeSeconds: timeSeconds,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// isValidDomain performs basic domain validation
func isValidDomain(domain string) bool {
	// Simple validation - domain should contain at least one dot and no spaces
	if strings.Contains(domain, " ") || !strings.Contains(domain, ".") {
		return false
	}

	// Check for common invalid characters
	invalidChars := []string{"http://", "https://", "ftp://", "://"}
	for _, invalid := range invalidChars {
		if strings.HasPrefix(domain, invalid) {
			return false
		}
	}

	return true
}
