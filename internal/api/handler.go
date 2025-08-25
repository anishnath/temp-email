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
	"time"

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

// PortScanResult represents a single port scan result
type PortScanResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version,omitempty"`
}

// NmapScanResponse represents the response from nmap API
type NmapScanResponse struct {
	Target     string           `json:"target"`
	ScanType   string           `json:"scan_type"`
	Ports      []PortScanResult `json:"ports"`
	OpenPorts  int              `json:"open_ports"`
	TotalPorts int              `json:"total_ports"`
	ScanTime   float64          `json:"scan_time_seconds"`
	Status     string           `json:"status"`
}

// WhoisRecord represents a single whois record field
type WhoisRecord struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

// WhoisResponse represents the response from whois API
type WhoisResponse struct {
	Domain       string        `json:"domain"`
	Registrar    string        `json:"registrar,omitempty"`
	Created      string        `json:"created,omitempty"`
	Updated      string        `json:"updated,omitempty"`
	Expires      string        `json:"expires,omitempty"`
	DomainStatus string        `json:"domain_status,omitempty"`
	NameServers  []string      `json:"name_servers,omitempty"`
	RawData      []WhoisRecord `json:"raw_data"`
	LookupTime   float64       `json:"lookup_time_seconds"`
	Status       string        `json:"status"`
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

// GetPortScan performs port scanning on a target using nmap
func GetPortScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	target := vars["target"]

	if target == "" {
		http.Error(w, "Target parameter is required", http.StatusBadRequest)
		return
	}

	// Get query parameters for scan options
	scanType := r.URL.Query().Get("scan_type")
	if scanType == "" {
		scanType = "quick" // Default to quick scan
	}

	// Validate scan type
	validScanTypes := map[string]bool{
		"quick":  true,
		"full":   true,
		"top":    true,
		"custom": true,
	}
	if !validScanTypes[scanType] {
		http.Error(w, "Invalid scan_type. Use: quick, full, top, or custom", http.StatusBadRequest)
		return
	}

	// Build nmap command based on scan type
	var cmd *exec.Cmd
	switch scanType {
	case "quick":
		// Quick scan: top 1000 ports, no version detection
		cmd = exec.CommandContext(r.Context(), "nmap", "-F", "-T4", "--open", target)
	case "full":
		// Full scan: all 65535 ports with version detection
		cmd = exec.CommandContext(r.Context(), "nmap", "-p-", "-sV", "-T4", "--open", target)
	case "top":
		// Top ports scan: most common ports with version detection
		cmd = exec.CommandContext(r.Context(), "nmap", "-sV", "-T4", "--open", target)
	case "custom":
		// Custom scan: allow user to specify ports
		ports := r.URL.Query().Get("ports")
		if ports == "" {
			ports = "80,443,22,21,25,53,110,143,993,995" // Default custom ports
		}
		cmd = exec.CommandContext(r.Context(), "nmap", "-p", ports, "-sV", "-T4", "--open", target)
	}

	// Execute nmap command
	output, err := cmd.Output()

	if err != nil {
		// Check if nmap is not found
		if strings.Contains(err.Error(), "executable file not found") {
			http.Error(w, "Nmap tool not found. Please install nmap first.", http.StatusInternalServerError)
			return
		}
		// Check if context was cancelled (timeout)
		if r.Context().Err() == context.DeadlineExceeded {
			http.Error(w, "Nmap scan timed out", http.StatusRequestTimeout)
			return
		}
		http.Error(w, "Error executing nmap: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse nmap output
	ports, scanTime, err := parseNmapOutput(string(output))
	if err != nil {
		http.Error(w, "Error parsing nmap output: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Count open ports
	openPorts := 0
	for _, port := range ports {
		if port.State == "open" {
			openPorts++
		}
	}

	response := NmapScanResponse{
		Target:     target,
		ScanType:   scanType,
		Ports:      ports,
		OpenPorts:  openPorts,
		TotalPorts: len(ports),
		ScanTime:   scanTime,
		Status:     "completed",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// parseNmapOutput parses the nmap command output and extracts port information
func parseNmapOutput(output string) ([]PortScanResult, float64, error) {
	var ports []PortScanResult
	var scanTime float64

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and headers
		if line == "" || strings.HasPrefix(line, "Starting") || strings.HasPrefix(line, "Nmap scan") {
			continue
		}

		// Parse scan time
		if strings.Contains(line, "scanned in") {
			// Extract time from "Nmap scan report for example.com (192.168.1.1) scanned in 2.34 seconds"
			re := regexp.MustCompile(`scanned in ([\d.]+) seconds?`)
			matches := re.FindStringSubmatch(line)
			if len(matches) == 2 {
				if time, err := strconv.ParseFloat(matches[1], 64); err == nil {
					scanTime = time
				}
			}
			continue
		}

		// Parse port lines like "80/tcp   open  http     Apache httpd 2.4.41"
		// or "22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.2"
		portRe := regexp.MustCompile(`^(\d+)/(\w+)\s+(\w+)\s+(\w+)(?:\s+(.+))?$`)
		matches := portRe.FindStringSubmatch(line)

		if len(matches) >= 5 {
			portNum, err := strconv.Atoi(matches[1])
			if err != nil {
				continue
			}

			port := PortScanResult{
				Port:     portNum,
				Protocol: matches[2],
				State:    matches[3],
				Service:  matches[4],
			}

			// Add version info if available
			if len(matches) > 5 && matches[5] != "" {
				port.Version = strings.TrimSpace(matches[5])
			}

			ports = append(ports, port)
		}
	}

	return ports, scanTime, nil
}

// GetWhois performs whois lookup on a domain using the whois command
func GetWhois(w http.ResponseWriter, r *http.Request) {
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

	// Execute whois command
	startTime := time.Now()
	cmd := exec.CommandContext(r.Context(), "whois", domain)
	output, err := cmd.Output()
	lookupTime := time.Since(startTime).Seconds()

	if err != nil {
		// Check if whois is not found
		if strings.Contains(err.Error(), "executable file not found") {
			http.Error(w, "Whois tool not found. Please install whois first.", http.StatusInternalServerError)
			return
		}
		// Check if context was cancelled (timeout)
		if r.Context().Err() == context.DeadlineExceeded {
			http.Error(w, "Whois lookup timed out", http.StatusRequestTimeout)
			return
		}
		http.Error(w, "Error executing whois: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse whois output
	whoisData := parseWhoisOutput(string(output))

	// Extract key information
	registrar := extractWhoisField(whoisData, "registrar")
	created := extractWhoisField(whoisData, "created")
	updated := extractWhoisField(whoisData, "updated")
	expires := extractWhoisField(whoisData, "expires")
	domainStatus := extractWhoisField(whoisData, "status")
	nameServers := extractWhoisNameServers(whoisData)

	response := WhoisResponse{
		Domain:       domain,
		Registrar:    registrar,
		Created:      created,
		Updated:      updated,
		Expires:      expires,
		DomainStatus: domainStatus,
		NameServers:  nameServers,
		RawData:      whoisData,
		LookupTime:   lookupTime,
		Status:       "completed",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// parseWhoisOutput parses the whois command output and extracts structured data
func parseWhoisOutput(output string) []WhoisRecord {
	var records []WhoisRecord

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines, comments, and headers
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse whois fields like "Registrar: Example Registrar, Inc."
		// or "Created: 2020-01-01T00:00:00Z"
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				field := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Skip empty values
				if value != "" {
					records = append(records, WhoisRecord{
						Field: field,
						Value: value,
					})
				}
			}
		}
	}

	return records
}

// extractWhoisField extracts a specific field value from whois data
func extractWhoisField(records []WhoisRecord, fieldName string) string {
	fieldNameLower := strings.ToLower(fieldName)

	for _, record := range records {
		if strings.Contains(strings.ToLower(record.Field), fieldNameLower) {
			return record.Value
		}
	}

	return ""
}

// extractWhoisNameServers extracts all nameserver entries from whois data
func extractWhoisNameServers(records []WhoisRecord) []string {
	var nameServers []string

	for _, record := range records {
		fieldLower := strings.ToLower(record.Field)
		if strings.Contains(fieldLower, "name server") ||
			strings.Contains(fieldLower, "nameserver") ||
			strings.Contains(fieldLower, "nserver") {
			nameServers = append(nameServers, record.Value)
		}
	}

	return nameServers
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
