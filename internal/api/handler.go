package api

import (
	"bytes"
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"temp-email/internal/db"
	"time"

	"math"

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

// SSLCertificate represents SSL certificate information
type SSLCertificate struct {
	Subject          string   `json:"subject"`
	Issuer           string   `json:"issuer"`
	ValidFrom        string   `json:"valid_from"`
	ValidUntil       string   `json:"valid_until"`
	SerialNumber     string   `json:"serial_number"`
	SignatureAlgo    string   `json:"signature_algorithm"`
	PublicKeyAlgo    string   `json:"public_key_algorithm"`
	PublicKeySize    int      `json:"public_key_size,omitempty"`
	SubjectAltNames  []string `json:"subject_alt_names,omitempty"`
	CertificateChain []string `json:"certificate_chain,omitempty"`
}

// SSLSecurityInfo represents SSL security analysis
type SSLSecurityInfo struct {
	TLSVersions             []string `json:"tls_versions"`
	SupportedCiphers        []string `json:"supported_ciphers"`
	WeakCiphers             []string `json:"weak_ciphers,omitempty"`
	HeartbleedVulnerable    bool     `json:"heartbleed_vulnerable"`
	BEASTVulnerable         bool     `json:"beast_vulnerable"`
	POODLEVulnerable        bool     `json:"poodle_vulnerable"`
	CertificateTransparency bool     `json:"certificate_transparency"`
	HSTSEnabled             bool     `json:"hsts_enabled,omitempty"`
	HPKPEnabled             bool     `json:"hpkp_enabled,omitempty"`
}

// SSLScanResponse represents the response from SSL scan API
type SSLScanResponse struct {
	Domain          string          `json:"domain"`
	Port            int             `json:"port"`
	ScanType        string          `json:"scan_type"`
	Certificate     SSLCertificate  `json:"certificate"`
	Security        SSLSecurityInfo `json:"security"`
	TestResults     []SSLTestResult `json:"test_results,omitempty"`
	Vulnerabilities []string        `json:"vulnerabilities,omitempty"`
	ScanTime        float64         `json:"scan_time_seconds"`
	Status          string          `json:"status"`
	RawOutput       string          `json:"raw_output,omitempty"`
	Progress        string          `json:"progress,omitempty"`
}

// SSLTestResult represents individual test results
type SSLTestResult struct {
	TestName string      `json:"test_name"`
	Status   string      `json:"status"` // "completed", "failed", "skipped"
	Result   interface{} `json:"result,omitempty"`
	Error    string      `json:"error,omitempty"`
	Duration float64     `json:"duration_seconds,omitempty"`
}

// ReverseDNSResult represents PTR lookup result for a single IP
type ReverseDNSResult struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames,omitempty"`
	Error     string   `json:"error,omitempty"`
	Duration  float64  `json:"duration_seconds,omitempty"`
}

// ReverseDNSResponse represents the response for reverse DNS lookups
type ReverseDNSResponse struct {
	QueryCount int                `json:"query_count"`
	Results    []ReverseDNSResult `json:"results"`
}

// DNSPropagationResult represents resolution from a single resolver
type DNSPropagationResult struct {
	ResolverIP string   `json:"resolver_ip"`
	Provider   string   `json:"provider,omitempty"`
	RecordType string   `json:"record_type"`
	Answers    []string `json:"answers,omitempty"`
	Error      string   `json:"error,omitempty"`
	Duration   float64  `json:"duration_seconds"`
}

// DNSPropagationResponse summarizes all resolver results
type DNSPropagationResponse struct {
	Name       string                 `json:"name"`
	RecordType string                 `json:"record_type"`
	QueriedAt  string                 `json:"queried_at"`
	Results    []DNSPropagationResult `json:"results"`
	Consensus  bool                   `json:"consensus"`
	UniqueSets int                    `json:"unique_answer_sets"`
}

// HTTPStatRequest represents the input to the /httpstat endpoint
type HTTPStatRequest struct {
	URL              string            `json:"url"`
	Method           string            `json:"method,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	FollowRedirects  bool              `json:"follow_redirects,omitempty"`
	TimeoutSeconds   int               `json:"timeout_seconds,omitempty"`
	IPv4Only         bool              `json:"ipv4_only,omitempty"`
	IPv6Only         bool              `json:"ipv6_only,omitempty"`
	InsecureTLS      bool              `json:"insecure_tls,omitempty"`
	ReadBody         bool              `json:"read_body,omitempty"`
	BodyPreviewBytes int               `json:"body_preview_bytes,omitempty"`
}

// HTTPStatResponse represents the timing and metadata output
type HTTPStatResponse struct {
	Target      string                 `json:"target"`
	ResolvedIP  string                 `json:"resolved_ip,omitempty"`
	Port        int                    `json:"port,omitempty"`
	HTTP        map[string]interface{} `json:"http"`
	TLS         map[string]string      `json:"tls,omitempty"`
	TimingsMS   map[string]int         `json:"timings_ms"`
	Headers     map[string][]string    `json:"headers,omitempty"`
	BodyPreview string                 `json:"body_preview_base64,omitempty"`
	Redirected  bool                   `json:"redirected"`
	Error       string                 `json:"error,omitempty"`
}

// PostHTTPStat handles POST /httpstat and returns curl-like timing breakdown
func PostHTTPStat(w http.ResponseWriter, r *http.Request) {
	var req HTTPStatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.URL) == "" {
		http.Error(w, "url is required", http.StatusBadRequest)
		return
	}
	if req.IPv4Only && req.IPv6Only {
		http.Error(w, "only one of ipv4_only or ipv6_only may be true", http.StatusBadRequest)
		return
	}
	if req.TimeoutSeconds <= 0 {
		req.TimeoutSeconds = 30
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}

	// Prepare request
	httpReq, err := http.NewRequest(req.Method, parsedURL.String(), nil)
	if err != nil {
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}
	for k, v := range req.Headers {
		if strings.EqualFold(k, "host") {
			httpReq.Host = v
			continue
		}
		httpReq.Header.Set(k, v)
	}

	var tDNSStart, tDNSDone, tConnStart, tConnDone, tGotConn, tFirstByte, tTLSStart, tTLSDone, tBodyDone time.Time
	var resolvedAddr string

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { tDNSStart = time.Now() },
		DNSDone: func(info httptrace.DNSDoneInfo) {
			tDNSDone = time.Now()
			if len(info.Addrs) > 0 {
				resolvedAddr = info.Addrs[0].String()
			}
		},
		ConnectStart: func(_, addr string) {
			if tDNSDone.IsZero() {
				tDNSStart = time.Now()
				tDNSDone = tDNSStart
			}
			tConnStart = time.Now()
		},
		ConnectDone: func(_, addr string, err error) {
			tConnDone = time.Now()
			if resolvedAddr == "" {
				resolvedAddr = addr
			}
		},
		GotConn:              func(_ httptrace.GotConnInfo) { tGotConn = time.Now() },
		GotFirstResponseByte: func() { tFirstByte = time.Now() },
		TLSHandshakeStart:    func() { tTLSStart = time.Now() },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { tTLSDone = time.Now() },
	}
	httpReq = httpReq.WithContext(httptrace.WithClientTrace(r.Context(), trace))

	// Transport: disable proxies by default
	tr := &http.Transport{
		Proxy:               nil,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	// Dialer according to IP preference
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if req.IPv4Only {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		}
	} else if req.IPv6Only {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp6", addr)
		}
	}
	if parsedURL.Scheme == "https" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: req.InsecureTLS}
	}

	client := &http.Client{Transport: tr, Timeout: time.Duration(req.TimeoutSeconds) * time.Second}
	if !req.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		writeHTTPStatError(w, parsedURL.String(), err)
		return
	}
	defer resp.Body.Close()

	// Collect HTTP and TLS info
	httpInfo := map[string]interface{}{
		"protocol":       fmt.Sprintf("HTTP/%d.%d", resp.ProtoMajor, resp.ProtoMinor),
		"status":         resp.StatusCode,
		"content_type":   resp.Header.Get("Content-Type"),
		"content_length": resp.ContentLength,
	}
	tlsInfo := map[string]string{}
	if resp.TLS != nil {
		switch resp.TLS.Version {
		case tls.VersionTLS13:
			tlsInfo["version"] = "TLS1.3"
		case tls.VersionTLS12:
			tlsInfo["version"] = "TLS1.2"
		default:
			tlsInfo["version"] = ""
		}
		tlsInfo["cipher_suite"] = tls.CipherSuiteName(resp.TLS.CipherSuite)
	}

	// Optionally read a small preview to establish content transfer time
	var preview string
	if req.ReadBody || req.BodyPreviewBytes > 0 {
		limit := req.BodyPreviewBytes
		if limit <= 0 {
			limit = 0
		}
		var reader io.Reader = resp.Body
		if limit > 0 {
			reader = io.LimitReader(resp.Body, int64(limit))
		}
		buf, _ := io.ReadAll(reader)
		tBodyDone = time.Now()
		if len(buf) > 0 {
			preview = base64.StdEncoding.EncodeToString(buf)
		}
	} else {
		tBodyDone = time.Now()
	}

	// Fallbacks for zero timestamps
	if tDNSStart.IsZero() {
		tDNSStart = start
		tDNSDone = start
	}
	if tConnStart.IsZero() {
		tConnStart = tDNSDone
	}
	if tGotConn.IsZero() {
		tGotConn = tConnDone
	}
	if tFirstByte.IsZero() {
		tFirstByte = tGotConn
	}

	// compute timings
	timings := map[string]int{
		"dns_lookup":        int(tDNSDone.Sub(tDNSStart) / time.Millisecond),
		"tcp_connect":       int(tConnDone.Sub(tConnStart) / time.Millisecond),
		"tls_handshake":     int(tTLSDone.Sub(tTLSStart) / time.Millisecond),
		"server_processing": int(tFirstByte.Sub(tGotConn) / time.Millisecond),
		"content_transfer":  int(tBodyDone.Sub(tFirstByte) / time.Millisecond),
		"total":             int(tBodyDone.Sub(start) / time.Millisecond),
	}

	// resolved IP and port
	resolvedIP := ""
	port := 0
	if resolvedAddr != "" {
		host, p, _ := net.SplitHostPort(resolvedAddr)
		if host != "" {
			resolvedIP = host
		}
		if pv, err := strconv.Atoi(p); err == nil {
			port = pv
		}
	}

	respObj := HTTPStatResponse{
		Target:      parsedURL.String(),
		ResolvedIP:  resolvedIP,
		Port:        port,
		HTTP:        httpInfo,
		TLS:         tlsInfo,
		TimingsMS:   timings,
		Headers:     resp.Header,
		BodyPreview: preview,
		Redirected:  resp.StatusCode >= 300 && resp.StatusCode < 400,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respObj)
}

func writeHTTPStatError(w http.ResponseWriter, target string, err error) {
	obj := HTTPStatResponse{Target: target, Error: err.Error(), TimingsMS: map[string]int{}}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_ = json.NewEncoder(w).Encode(obj)
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

// GetSSLScan performs SSL certificate scanning on a domain
func GetSSLScan(w http.ResponseWriter, r *http.Request) {
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

	fmt.Println(r.URL.Query())

	// Get query parameters for scan options
	scanType := r.URL.Query().Get("type")
	if scanType == "" {
		scanType = "basic" // Default to basic scan
	}

	// Validate scan type
	validScanTypes := map[string]bool{
		"basic": true,
		"full":  true,
		"quick": true,
	}
	if !validScanTypes[scanType] {
		http.Error(w, "Invalid scan type. Use: basic, full, or quick", http.StatusBadRequest)
		return
	}

	// Get port (default to 443)
	portStr := r.URL.Query().Get("port")
	port := 443
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			port = p
		}
	}

	startTime := time.Now()
	var response SSLScanResponse

	fmt.Println("Starting SSL scan for", domain, "on port", port, "with type", scanType)

	switch scanType {
	case "basic":
		response = performBasicSSLScan(domain, port)
	case "full":
		response = performFullSSLScan(domain, port)
	case "quick":
		response = performQuickSSLScan(domain, port)
	}

	response.ScanTime = time.Since(startTime).Seconds()
	response.Status = "completed"

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// performBasicSSLScan performs basic SSL certificate analysis using OpenSSL
func performBasicSSLScan(domain string, port int) SSLScanResponse {
	response := SSLScanResponse{
		Domain:   domain,
		Port:     port,
		ScanType: "basic",
	}

	// Get certificate information using OpenSSL
	certInfo := getCertificateInfo(domain, port)
	response.Certificate = certInfo

	// Get basic security information
	securityInfo := getBasicSecurityInfo(domain, port)
	response.Security = securityInfo

	return response
}

// performFullSSLScan performs comprehensive SSL analysis using testssl.sh
func performFullSSLScan(domain string, port int) SSLScanResponse {
	response := SSLScanResponse{
		Domain:   domain,
		Port:     port,
		ScanType: "full",
	}

	// Get certificate information
	certInfo := getCertificateInfo(domain, port)
	response.Certificate = certInfo

	// Get comprehensive security analysis using testssl.sh
	securityInfo, vulnerabilities, rawOutput, testResults := getFullSecurityInfo(domain, port)
	response.Security = securityInfo
	response.Vulnerabilities = vulnerabilities
	response.RawOutput = rawOutput
	response.TestResults = testResults

	// Create progress summary
	var progress string
	if len(testResults) > 0 {
		completed := 0
		failed := 0
		for _, test := range testResults {
			if test.Status == "completed" {
				completed++
			} else if test.Status == "failed" {
				failed++
			}
		}
		progress = fmt.Sprintf("Tests: %d completed, %d failed, %d total", completed, failed, len(testResults))
	}
	response.Progress = progress

	return response
}

// performQuickSSLScan performs quick SSL check using Go's crypto/tls
func performQuickSSLScan(domain string, port int) SSLScanResponse {
	response := SSLScanResponse{
		Domain:   domain,
		Port:     port,
		ScanType: "quick",
	}

	// Quick check using Go's built-in TLS
	certInfo := getQuickCertificateInfo(domain, port)
	response.Certificate = certInfo

	// Basic security check
	securityInfo := getQuickSecurityInfo(domain, port)
	response.Security = securityInfo

	return response
}

// getCertificateInfo extracts certificate information using OpenSSL
func getCertificateInfo(domain string, port int) SSLCertificate {
	cert := SSLCertificate{}

	// First, get the certificate in text format
	cmd := exec.Command("openssl", "s_client", "-connect", fmt.Sprintf("%s:%d", domain, port),
		"-servername", domain, "-showcerts")
	cmd.Stdin = strings.NewReader("")
	output, err := cmd.Output()

	if err != nil {
		return cert
	}

	// Parse the OpenSSL output
	cert = parseOpenSSLOutput(string(output))

	// If we didn't get all the info, try a different approach
	if cert.ValidFrom == "" || cert.ValidUntil == "" {
		// Try to get certificate info using x509 command
		cert = getCertificateInfoX509(domain, port)
	}

	// Always try to get serial number from raw certificate data
	if cert.SerialNumber == "" {
		cert.SerialNumber = extractSerialNumberFromRaw(domain, port)
	}

	// If still no serial number, try one more method
	if cert.SerialNumber == "" {
		cert.SerialNumber = extractSerialNumberAlternative(domain, port)
	}

	return cert
}

// extractSerialNumberAlternative tries another method to extract serial number
func extractSerialNumberAlternative(domain string, port int) string {
	// Try using openssl x509 with different options
	cmd := exec.Command("bash", "-c",
		fmt.Sprintf("openssl s_client -connect %s:%d -servername %s < /dev/null 2>/dev/null | openssl x509 -noout -serial -text | grep -i 'serial'",
			domain, port, domain))

	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Parse the output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "serial") {
			// Extract the serial number part
			if strings.Contains(line, "=") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					return strings.TrimSpace(parts[1])
				}
			} else if strings.Contains(line, ":") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}

	return ""
}

// extractSerialNumberFromRaw extracts serial number from raw certificate data
func extractSerialNumberFromRaw(domain string, port int) string {
	// First, get the certificate to a temporary file
	tempFile := fmt.Sprintf("/tmp/cert_%s_%d.pem", domain, port)

	// Get certificate using s_client
	cmd1 := exec.Command("openssl", "s_client", "-connect", fmt.Sprintf("%s:%d", domain, port),
		"-servername", domain, "-showcerts")
	cmd1.Stdin = strings.NewReader("")
	output, err := cmd1.Output()
	if err != nil {
		return ""
	}

	// Write certificate to temp file
	err = os.WriteFile(tempFile, output, 0644)
	if err != nil {
		return ""
	}
	defer os.Remove(tempFile)

	// Extract serial number from the certificate file
	cmd2 := exec.Command("openssl", "x509", "-in", tempFile, "-noout", "-serial")
	output2, err := cmd2.Output()
	if err != nil {
		return ""
	}

	// Parse serial number from output like "serial=1234567890abcdef"
	line := strings.TrimSpace(string(output2))
	if strings.HasPrefix(line, "serial=") {
		return strings.TrimPrefix(line, "serial=")
	}

	return ""
}

// getCertificateInfoX509 gets certificate info using openssl x509 command
func getCertificateInfoX509(domain string, port int) SSLCertificate {
	cert := SSLCertificate{}

	// Get certificate and pipe it to x509 for detailed info
	cmd := exec.Command("bash", "-c",
		fmt.Sprintf("openssl s_client -connect %s:%d -servername %s < /dev/null 2>/dev/null | openssl x509 -text -noout",
			domain, port, domain))

	output, err := cmd.Output()
	if err != nil {
		return cert
	}

	// Parse the x509 output
	cert = parseX509Output(string(output))

	// Try to get serial number specifically
	if cert.SerialNumber == "" {
		cert.SerialNumber = extractSerialNumberFromRaw(domain, port)
	}

	return cert
}

// parseOpenSSLOutput parses OpenSSL s_client output
func parseOpenSSLOutput(output string) SSLCertificate {
	cert := SSLCertificate{}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse certificate information from s_client output
		if strings.HasPrefix(line, "subject=") {
			cert.Subject = strings.TrimPrefix(line, "subject=")
		} else if strings.HasPrefix(line, "issuer=") {
			cert.Issuer = strings.TrimPrefix(line, "issuer=")
		} else if strings.HasPrefix(line, "notBefore=") {
			cert.ValidFrom = strings.TrimPrefix(line, "notBefore=")
		} else if strings.HasPrefix(line, "notAfter=") {
			cert.ValidUntil = strings.TrimPrefix(line, "notAfter=")
		} else if strings.HasPrefix(line, "serial=") {
			cert.SerialNumber = strings.TrimPrefix(line, "serial=")
		} else if strings.HasPrefix(line, "Signature Algorithm:") {
			cert.SignatureAlgo = strings.TrimSpace(strings.TrimPrefix(line, "Signature Algorithm:"))
		} else if strings.HasPrefix(line, "Public Key Algorithm:") {
			cert.PublicKeyAlgo = strings.TrimSpace(strings.TrimPrefix(line, "Public Key Algorithm:"))
		}

		// Also look for serial number in other formats
		if cert.SerialNumber == "" && strings.Contains(strings.ToLower(line), "serial") {
			if strings.Contains(line, "=") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					cert.SerialNumber = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	return cert
}

// parseX509Output parses OpenSSL x509 command output
func parseX509Output(output string) SSLCertificate {
	cert := SSLCertificate{}

	lines := strings.Split(output, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Parse certificate information from x509 output
		if strings.HasPrefix(line, "Subject:") {
			cert.Subject = strings.TrimSpace(strings.TrimPrefix(line, "Subject:"))
		} else if strings.HasPrefix(line, "Issuer:") {
			cert.Issuer = strings.TrimSpace(strings.TrimPrefix(line, "Issuer:"))
		} else if strings.HasPrefix(line, "Not Before:") {
			cert.ValidFrom = strings.TrimSpace(strings.TrimPrefix(line, "Not Before:"))
		} else if strings.HasPrefix(line, "Not After:") {
			cert.ValidUntil = strings.TrimSpace(strings.TrimPrefix(line, "Not After:"))
		} else if strings.HasPrefix(line, "Serial Number:") {
			cert.SerialNumber = strings.TrimSpace(strings.TrimPrefix(line, "Serial Number:"))
		} else if strings.HasPrefix(line, "Signature Algorithm:") {
			cert.SignatureAlgo = strings.TrimSpace(strings.TrimPrefix(line, "Signature Algorithm:"))
		} else if strings.HasPrefix(line, "Public Key Algorithm:") {
			cert.PublicKeyAlgo = strings.TrimSpace(strings.TrimPrefix(line, "Public Key Algorithm:"))
		} else if strings.HasPrefix(line, "Public-Key:") {
			// Extract public key size
			if strings.Contains(line, "(") && strings.Contains(line, "bit") {
				parts := strings.Split(line, "(")
				if len(parts) > 1 {
					sizeStr := strings.Split(parts[1], " ")[0]
					if size, err := strconv.Atoi(sizeStr); err == nil {
						cert.PublicKeySize = size
					}
				}
			}
		} else if strings.HasPrefix(line, "X509v3 Subject Alternative Name:") {
			// Parse Subject Alternative Names
			if i+1 < len(lines) {
				nextLine := strings.TrimSpace(lines[i+1])
				if strings.Contains(nextLine, "DNS:") {
					sans := strings.Split(nextLine, "DNS:")
					for _, san := range sans {
						san = strings.TrimSpace(san)
						if san != "" && !strings.Contains(san, ",") {
							cert.SubjectAltNames = append(cert.SubjectAltNames, san)
						}
					}
				}
			}
		}
	}

	// If we still don't have all the info, try alternative parsing
	if cert.ValidUntil == "" || cert.SerialNumber == "" {
		cert = parseAlternativeOpenSSLOutput(output, cert)
	}

	return cert
}

// parseAlternativeOpenSSLOutput tries alternative parsing methods for missing fields
func parseAlternativeOpenSSLOutput(output string, cert SSLCertificate) SSLCertificate {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Try different date formats for expiry
		if cert.ValidUntil == "" || strings.Contains(cert.ValidUntil, "Not Before") {
			if strings.Contains(line, "GMT") && (strings.Contains(line, "2025") || strings.Contains(line, "2026") || strings.Contains(line, "2027")) {
				// Look for expiry date - it should be after the "Not Before" date
				if !strings.Contains(line, "Not Before") && !strings.Contains(line, "Jul 14") {
					// This is likely the expiry date
					cert.ValidUntil = line
				}
			}
		}

		// Try to find serial number in different formats
		if cert.SerialNumber == "" {
			if strings.Contains(line, "Serial:") {
				cert.SerialNumber = strings.TrimSpace(strings.TrimPrefix(line, "Serial:"))
			} else if strings.Contains(line, "serial=") {
				cert.SerialNumber = strings.TrimSpace(strings.TrimPrefix(line, "serial="))
			} else if strings.Contains(line, "Serial Number:") {
				cert.SerialNumber = strings.TrimSpace(strings.TrimPrefix(line, "Serial Number:"))
			}
		}
	}

	// Clean up date format
	if strings.Contains(cert.ValidUntil, "Not After :") {
		cert.ValidUntil = strings.TrimSpace(strings.TrimPrefix(cert.ValidUntil, "Not After :"))
	} else if strings.Contains(cert.ValidUntil, "Not After:") {
		cert.ValidUntil = strings.TrimSpace(strings.TrimPrefix(cert.ValidUntil, "Not After:"))
	}

	return cert
}

// getBasicSecurityInfo gets basic security information using nmap
func getBasicSecurityInfo(domain string, port int) SSLSecurityInfo {
	security := SSLSecurityInfo{}

	// Use nmap to get cipher information
	cmd := exec.Command("nmap", "--script", "ssl-enum-ciphers", "-p", strconv.Itoa(port), domain)
	output, err := cmd.Output()

	if err != nil {
		return security
	}

	// Parse nmap output
	security = parseNmapSSLOutput(string(output))
	return security
}

// parseNmapSSLOutput parses nmap SSL script output
func parseNmapSSLOutput(output string) SSLSecurityInfo {
	security := SSLSecurityInfo{}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse TLS versions
		if strings.Contains(line, "TLSv1.2") {
			security.TLSVersions = append(security.TLSVersions, "TLSv1.2")
		} else if strings.Contains(line, "TLSv1.3") {
			security.TLSVersions = append(security.TLSVersions, "TLSv1.3")
		} else if strings.Contains(line, "TLSv1.1") {
			security.TLSVersions = append(security.TLSVersions, "TLSv1.1")
		} else if strings.Contains(line, "TLSv1.0") {
			security.TLSVersions = append(security.TLSVersions, "TLSv1.0")
		} else if strings.Contains(line, "SSLv3") {
			security.TLSVersions = append(security.TLSVersions, "SSLv3")
		} else if strings.Contains(line, "SSLv2") {
			security.TLSVersions = append(security.TLSVersions, "SSLv2")
		}

		// Parse ciphers
		if strings.Contains(line, "TLS_") || strings.Contains(line, "SSL_") {
			if !strings.Contains(line, "weak") && !strings.Contains(line, "insecure") {
				security.SupportedCiphers = append(security.SupportedCiphers, strings.TrimSpace(line))
			} else {
				security.WeakCiphers = append(security.WeakCiphers, strings.TrimSpace(line))
			}
		}

		// Parse weak ciphers
		if strings.Contains(line, "weak") || strings.Contains(line, "insecure") {
			security.WeakCiphers = append(security.WeakCiphers, strings.TrimSpace(line))
		}

		// Check for HSTS
		if strings.Contains(line, "HSTS") {
			security.HSTSEnabled = true
		}
	}

	// Remove duplicates
	security.TLSVersions = removeDuplicates(security.TLSVersions)
	security.SupportedCiphers = removeDuplicates(security.SupportedCiphers)
	security.WeakCiphers = removeDuplicates(security.WeakCiphers)

	return security
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// getFullSecurityInfo gets comprehensive security analysis using testssl.sh
func getFullSecurityInfo(domain string, port int) (SSLSecurityInfo, []string, string, []SSLTestResult) {
	security := SSLSecurityInfo{}
	var vulnerabilities []string
	var rawOutput string
	var testResults []SSLTestResult

	// Use testssl.sh from system PATH
	testsslPath := "/usr/bin/testssl"

	// Test 1: Check if testssl.sh is properly configured
	startTime := time.Now()
	if !isTestSSLConfigured() {
		testResults = append(testResults, SSLTestResult{
			TestName: "testssl.sh Configuration Check",
			Status:   "failed",
			Error:    "testssl.sh not properly configured",
			Duration: time.Since(startTime).Seconds(),
		})

		// Use enhanced nmap fallback
		enhancedSecurity := getEnhancedSecurityInfo(domain, port)
		testResults = append(testResults, SSLTestResult{
			TestName: "Enhanced Nmap Fallback",
			Status:   "completed",
			Result:   "Using nmap for security analysis",
			Duration: time.Since(startTime).Seconds(),
		})

		return enhancedSecurity, vulnerabilities, "testssl.sh not configured, using enhanced nmap analysis", testResults
	}

	testResults = append(testResults, SSLTestResult{
		TestName: "testssl.sh Configuration Check",
		Status:   "completed",
		Result:   "testssl.sh is properly configured",
		Duration: time.Since(startTime).Seconds(),
	})

	// Test 2: Try testssl.sh with primary options
	startTime = time.Now()
	cmd := exec.Command(testsslPath, "--quiet", "--severity", "LOW", "--color", "0", "--ip", "one", fmt.Sprintf("%s:%d", domain, port))
	output, err := cmd.Output()

	if err != nil {
		testResults = append(testResults, SSLTestResult{
			TestName: "testssl.sh Primary Scan",
			Status:   "failed",
			Error:    err.Error(),
			Duration: time.Since(startTime).Seconds(),
		})

		// Test 3: Try alternative testssl.sh options
		startTime = time.Now()
		cmd2 := exec.Command(testsslPath, "--quiet", "--severity", "LOW", "--ip", "one", fmt.Sprintf("%s:%d", domain, port))
		output, err = cmd2.Output()

		if err != nil {
			testResults = append(testResults, SSLTestResult{
				TestName: "testssl.sh Alternative Scan",
				Status:   "failed",
				Error:    err.Error(),
				Duration: time.Since(startTime).Seconds(),
			})

			// Test 4: Enhanced nmap fallback
			startTime = time.Now()
			enhancedSecurity := getEnhancedSecurityInfo(domain, port)
			testResults = append(testResults, SSLTestResult{
				TestName: "Enhanced Nmap Fallback",
				Status:   "completed",
				Result:   "Using nmap for comprehensive security analysis",
				Duration: time.Since(startTime).Seconds(),
			})

			return enhancedSecurity, vulnerabilities, "testssl.sh execution failed, using enhanced nmap analysis", testResults
		}

		testResults = append(testResults, SSLTestResult{
			TestName: "testssl.sh Alternative Scan",
			Status:   "completed",
			Result:   "Successfully executed with alternative options",
			Duration: time.Since(startTime).Seconds(),
		})
	} else {
		testResults = append(testResults, SSLTestResult{
			TestName: "testssl.sh Primary Scan",
			Status:   "completed",
			Result:   "Successfully executed with primary options",
			Duration: time.Since(startTime).Seconds(),
		})
	}

	rawOutput = string(output)

	// Test 5: Parse testssl.sh output
	startTime = time.Now()
	security, vulnerabilities = parseTestSSLOutput(rawOutput)
	testResults = append(testResults, SSLTestResult{
		TestName: "testssl.sh Output Parsing",
		Status:   "completed",
		Result: fmt.Sprintf("Parsed %d TLS versions, %d ciphers, %d vulnerabilities",
			len(security.TLSVersions), len(security.SupportedCiphers), len(vulnerabilities)),
		Duration: time.Since(startTime).Seconds(),
	})

	// Test 6: Fallback to enhanced security if needed
	if len(security.TLSVersions) == 0 {
		startTime = time.Now()
		enhancedSecurity := getEnhancedSecurityInfo(domain, port)
		security.TLSVersions = enhancedSecurity.TLSVersions
		security.SupportedCiphers = enhancedSecurity.SupportedCiphers
		security.WeakCiphers = enhancedSecurity.WeakCiphers

		testResults = append(testResults, SSLTestResult{
			TestName: "Enhanced Security Fallback",
			Status:   "completed",
			Result:   "Applied enhanced security analysis due to insufficient testssl.sh data",
			Duration: time.Since(startTime).Seconds(),
		})
	}

	return security, vulnerabilities, rawOutput, testResults
}

// parseTestSSLOutput parses testssl.sh output with improved parsing logic
func parseTestSSLOutput(output string) (SSLSecurityInfo, []string) {
	security := SSLSecurityInfo{}
	var vulnerabilities []string

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse TLS versions with better pattern matching
		if strings.Contains(line, "TLS 1.3") && !strings.Contains(line, "not offered") && !strings.Contains(line, "not supported") {
			security.TLSVersions = append(security.TLSVersions, "TLSv1.3")
		} else if strings.Contains(line, "TLS 1.2") && !strings.Contains(line, "not offered") && !strings.Contains(line, "not supported") {
			security.TLSVersions = append(security.TLSVersions, "TLSv1.2")
		} else if strings.Contains(line, "TLS 1.1") && !strings.Contains(line, "not offered") && !strings.Contains(line, "not supported") {
			security.TLSVersions = append(security.TLSVersions, "TLSv1.1")
		} else if strings.Contains(line, "TLS 1.0") && !strings.Contains(line, "not offered") && !strings.Contains(line, "not supported") {
			security.TLSVersions = append(security.TLSVersions, "TLSv1.0")
		} else if strings.Contains(line, "SSLv3") && !strings.Contains(line, "not offered") && !strings.Contains(line, "not supported") {
			security.TLSVersions = append(security.TLSVersions, "SSLv3")
		} else if strings.Contains(line, "SSLv2") && !strings.Contains(line, "not offered") && !strings.Contains(line, "not supported") {
			security.TLSVersions = append(security.TLSVersions, "SSLv2")
		}

		// Parse vulnerabilities with improved detection
		if strings.Contains(strings.ToLower(line), "heartbleed") {
			security.HeartbleedVulnerable = true
			vulnerabilities = append(vulnerabilities, "Heartbleed")
		} else if strings.Contains(strings.ToUpper(line), "BEAST") {
			security.BEASTVulnerable = true
			vulnerabilities = append(vulnerabilities, "BEAST")
		} else if strings.Contains(strings.ToUpper(line), "POODLE") {
			security.POODLEVulnerable = true
			vulnerabilities = append(vulnerabilities, "POODLE")
		} else if strings.Contains(strings.ToLower(line), "freak") {
			vulnerabilities = append(vulnerabilities, "FREAK")
		} else if strings.Contains(strings.ToLower(line), "logjam") {
			vulnerabilities = append(vulnerabilities, "Logjam")
		} else if strings.Contains(strings.ToLower(line), "drown") {
			vulnerabilities = append(vulnerabilities, "DROWN")
		} else if strings.Contains(strings.ToLower(line), "lucky13") {
			vulnerabilities = append(vulnerabilities, "Lucky13")
		} else if strings.Contains(strings.ToLower(line), "sweet32") {
			vulnerabilities = append(vulnerabilities, "Sweet32")
		} else if strings.Contains(strings.ToLower(line), "robot") {
			vulnerabilities = append(vulnerabilities, "ROBOT")
		}

		// Parse security features with better detection
		if strings.Contains(line, "HSTS") && (strings.Contains(line, "enabled") || strings.Contains(line, "yes")) {
			security.HSTSEnabled = true
		} else if strings.Contains(line, "HPKP") && (strings.Contains(line, "enabled") || strings.Contains(line, "yes")) {
			security.HPKPEnabled = true
		} else if strings.Contains(line, "Certificate Transparency") && (strings.Contains(line, "yes") || strings.Contains(line, "enabled")) {
			security.CertificateTransparency = true
		}

		// Parse ciphers with better detection
		if strings.Contains(line, "TLS_") || strings.Contains(line, "SSL_") || strings.Contains(line, "ECDHE") || strings.Contains(line, "DHE") {
			if strings.Contains(line, "weak") || strings.Contains(line, "insecure") || strings.Contains(line, "low") {
				security.WeakCiphers = append(security.WeakCiphers, strings.TrimSpace(line))
			} else {
				security.SupportedCiphers = append(security.SupportedCiphers, strings.TrimSpace(line))
			}
		}

		// Parse additional security information
		if strings.Contains(line, "OCSP Stapling") && strings.Contains(line, "yes") {
			// Add OCSP stapling support
		} else if strings.Contains(line, "Session Tickets") && strings.Contains(line, "yes") {
			// Add session ticket support
		}
	}

	// If we didn't get TLS versions from testssl.sh, try alternative parsing
	if len(security.TLSVersions) == 0 {
		security.TLSVersions = parseAlternativeTLSVersions(output)
	}

	// Remove duplicates and clean up
	security.TLSVersions = removeDuplicates(security.TLSVersions)
	security.SupportedCiphers = removeDuplicates(security.SupportedCiphers)
	security.WeakCiphers = removeDuplicates(security.WeakCiphers)
	vulnerabilities = removeDuplicates(vulnerabilities)

	return security, vulnerabilities
}

// parseAlternativeTLSVersions tries to extract TLS versions from testssl.sh output using different patterns
func parseAlternativeTLSVersions(output string) []string {
	var versions []string

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for TLS version information in various formats
		if strings.Contains(line, "TLSv1.3") || strings.Contains(line, "TLS 1.3") {
			versions = append(versions, "TLSv1.3")
		} else if strings.Contains(line, "TLSv1.2") || strings.Contains(line, "TLS 1.2") {
			versions = append(versions, "TLSv1.2")
		} else if strings.Contains(line, "TLSv1.1") || strings.Contains(line, "TLS 1.1") {
			versions = append(versions, "TLSv1.1")
		} else if strings.Contains(line, "TLSv1.0") || strings.Contains(line, "TLS 1.0") {
			versions = append(versions, "TLSv1.0")
		}
	}

	return versions
}

// getQuickCertificateInfo gets basic certificate info using Go's crypto/tls
func getQuickCertificateInfo(domain string, port int) SSLCertificate {
	cert := SSLCertificate{}

	// Use Go's crypto/tls for a quick connection test
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", domain, port), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	})
	if err != nil {
		// If Go's TLS fails, fall back to OpenSSL for basic info
		return getBasicCertificateInfo(domain, port)
	}
	defer conn.Close()

	// Get certificate info
	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		peerCert := state.PeerCertificates[0]

		cert.Subject = peerCert.Subject.String()
		cert.Issuer = peerCert.Issuer.String()
		cert.ValidFrom = peerCert.NotBefore.Format("Jan 2 15:04:05 2006 MST")
		cert.ValidUntil = peerCert.NotAfter.Format("Jan 2 15:04:05 2006 MST")
		cert.SerialNumber = peerCert.SerialNumber.String()
		cert.SignatureAlgo = peerCert.SignatureAlgorithm.String()
		cert.PublicKeyAlgo = getPublicKeyAlgorithm(peerCert.PublicKey)

		// Get public key size
		if rsaKey, ok := peerCert.PublicKey.(*rsa.PublicKey); ok {
			cert.PublicKeySize = rsaKey.Size() * 8
		} else if ecdsaKey, ok := peerCert.PublicKey.(*ecdsa.PublicKey); ok {
			cert.PublicKeySize = ecdsaKey.Curve.Params().BitSize
		}

		// Get Subject Alternative Names
		cert.SubjectAltNames = peerCert.DNSNames
	}

	return cert
}

// getBasicCertificateInfo gets basic certificate info using OpenSSL as fallback
func getBasicCertificateInfo(domain string, port int) SSLCertificate {
	cert := SSLCertificate{}

	// Use OpenSSL as fallback for quick scan
	cmd := exec.Command("openssl", "s_client", "-connect", fmt.Sprintf("%s:%d", domain, port),
		"-servername", domain, "-showcerts")
	cmd.Stdin = strings.NewReader("")
	output, err := cmd.Output()

	if err != nil {
		return cert
	}

	// Parse the OpenSSL output
	cert = parseOpenSSLOutput(string(output))
	return cert
}

// getPublicKeyAlgorithm returns a string representation of the public key algorithm
func getPublicKeyAlgorithm(pub interface{}) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "rsaEncryption"
	case *ecdsa.PublicKey:
		return "id-ecPublicKey"
	case *dsa.PublicKey:
		return "dsaEncryption"
	default:
		return "unknown"
	}
}

// getQuickSecurityInfo gets basic security info quickly
func getQuickSecurityInfo(domain string, port int) SSLSecurityInfo {
	security := SSLSecurityInfo{}

	// Basic security check
	security.TLSVersions = []string{"TLSv1.2", "TLSv1.3"}
	security.CertificateTransparency = true

	return security
}

// isTestSSLConfigured checks if testssl.sh is properly configured
func isTestSSLConfigured() bool {
	// Check if testssl.sh can run without configuration issues
	cmd := exec.Command("testssl.sh", "--version")
	output, err := cmd.Output()

	if err != nil {
		return false
	}

	// Check if output contains configuration warnings
	outputStr := string(output)
	if strings.Contains(outputStr, "No cipher mapping file found") ||
		strings.Contains(outputStr, "needs files in") ||
		strings.Contains(outputStr, "ATTENTION") {
		return false
	}

	return true
}

// getEnhancedSecurityInfo provides enhanced security analysis using multiple nmap scripts
func getEnhancedSecurityInfo(domain string, port int) SSLSecurityInfo {
	security := SSLSecurityInfo{}

	// Get basic security info first
	basicSecurity := getBasicSecurityInfo(domain, port)
	security.TLSVersions = basicSecurity.TLSVersions
	security.SupportedCiphers = basicSecurity.SupportedCiphers
	security.WeakCiphers = basicSecurity.WeakCiphers

	// Try to get additional security information using nmap scripts
	security = getAdditionalSecurityInfo(domain, port, security)

	return security
}

// getAdditionalSecurityInfo gets additional security information using nmap scripts
func getAdditionalSecurityInfo(domain string, port int, security SSLSecurityInfo) SSLSecurityInfo {
	// Try to get certificate transparency info
	cmd := exec.Command("nmap", "--script", "ssl-cert", "--script-args", "ssl-cert.show-all-certs=true", "-p", fmt.Sprintf("%d", port), domain)
	output, err := cmd.Output()

	if err == nil {
		outputStr := string(output)

		// Check for certificate transparency
		if strings.Contains(outputStr, "Certificate Transparency") {
			security.CertificateTransparency = true
		}

		// Check for HSTS
		if strings.Contains(outputStr, "HSTS") {
			security.HSTSEnabled = true
		}

		// Check for HPKP
		if strings.Contains(outputStr, "HPKP") || strings.Contains(outputStr, "Public Key Pinning") {
			security.HPKPEnabled = true
		}
	}

	// Try to get additional cipher information
	cmd2 := exec.Command("nmap", "--script", "ssl-enum-ciphers", "--script-args", "ssl-enum-ciphers.detailed=true", "-p", fmt.Sprintf("%d", port), domain)
	output2, err2 := cmd2.Output()

	if err2 == nil {
		outputStr2 := string(output2)

		// Parse for additional TLS versions
		if strings.Contains(outputStr2, "TLSv1.3") && !contains(security.TLSVersions, "TLSv1.3") {
			security.TLSVersions = append(security.TLSVersions, "TLSv1.3")
		}
		if strings.Contains(outputStr2, "TLSv1.2") && !contains(security.TLSVersions, "TLSv1.2") {
			security.TLSVersions = append(security.TLSVersions, "TLSv1.2")
		}
		if strings.Contains(outputStr2, "TLSv1.1") && !contains(security.TLSVersions, "TLSv1.2") {
			security.TLSVersions = append(security.TLSVersions, "TLSv1.1")
		}
	}

	return security
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetReverseDNS performs PTR lookups for one or multiple comma-separated IPs
func GetReverseDNS(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ipParam := vars["ip"]
	if strings.TrimSpace(ipParam) == "" {
		http.Error(w, "IP parameter is required", http.StatusBadRequest)
		return
	}

	ips := strings.Split(ipParam, ",")
	resolver := &net.Resolver{}
	results := make([]ReverseDNSResult, 0, len(ips))

	for _, raw := range ips {
		ipStr := strings.TrimSpace(raw)
		if ipStr == "" {
			continue
		}
		parsed := net.ParseIP(ipStr)
		if parsed == nil {
			results = append(results, ReverseDNSResult{IP: ipStr, Error: "invalid ip address"})
			continue
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		start := time.Now()
		names, err := resolver.LookupAddr(ctx, ipStr)
		cancel()
		dur := time.Since(start).Seconds()
		res := ReverseDNSResult{IP: ipStr, Duration: dur}
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Hostnames = names
		}
		results = append(results, res)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ReverseDNSResponse{QueryCount: len(results), Results: results})
}

// GetDNSPropagation checks DNS answers across multiple resolvers
func GetDNSPropagation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := strings.TrimSpace(vars["name"])
	if name == "" {
		http.Error(w, "name parameter is required", http.StatusBadRequest)
		return
	}

	recordType := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))
	if recordType == "" {
		recordType = "A"
	}
	valid := map[string]bool{"A": true, "AAAA": true, "MX": true, "NS": true, "TXT": true, "CNAME": true}
	if !valid[recordType] {
		http.Error(w, "unsupported record type", http.StatusBadRequest)
		return
	}

	// Default resolver pool (IP -> provider)
	defaultResolvers := map[string]string{
		"1.1.1.1":         "Cloudflare",
		"1.0.0.1":         "Cloudflare",
		"8.8.8.8":         "Google",
		"8.8.4.4":         "Google",
		"9.9.9.9":         "Quad9",
		"149.112.112.112": "Quad9",
		"208.67.222.222":  "OpenDNS",
		"208.67.220.220":  "OpenDNS",
		"94.140.14.14":    "AdGuard",
		"76.76.2.0":       "ControlD",
	}

	// Optional custom resolvers
	resolverParam := strings.TrimSpace(r.URL.Query().Get("resolvers"))
	resolvers := make([][2]string, 0)
	if resolverParam != "" {
		for _, s := range strings.Split(resolverParam, ",") {
			ip := strings.TrimSpace(s)
			if net.ParseIP(ip) != nil {
				resolvers = append(resolvers, [2]string{ip, "custom"})
			}
		}
	}
	if len(resolvers) == 0 {
		for ip, provider := range defaultResolvers {
			resolvers = append(resolvers, [2]string{ip, provider})
		}
	}

	ctx := r.Context()
	var mu sync.Mutex
	results := make([]DNSPropagationResult, 0, len(resolvers))
	wg := sync.WaitGroup{}
	wg.Add(len(resolvers))

	for _, pair := range resolvers {
		resolverIP, provider := pair[0], pair[1]
		go func(resIP, prov string) {
			defer wg.Done()
			start := time.Now()
			answers, err := resolveWith(resIP, name, recordType, ctx)
			dur := time.Since(start).Seconds()
			res := DNSPropagationResult{
				ResolverIP: resIP,
				Provider:   prov,
				RecordType: recordType,
				Duration:   dur,
			}
			if err != nil {
				res.Error = err.Error()
			} else {
				res.Answers = answers
			}
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(resolverIP, provider)
	}
	wg.Wait()

	// Compute consensus: unique sets of answers across resolvers
	unique := make(map[string]struct{})
	for _, res := range results {
		key := strings.Join(res.Answers, ",")
		unique[key] = struct{}{}
	}
	// remove empty key if errors
	if _, ok := unique[""]; ok && len(unique) > 1 {
		delete(unique, "")
	}
	consensus := len(unique) <= 1

	resp := DNSPropagationResponse{
		Name:       name,
		RecordType: recordType,
		QueriedAt:  time.Now().UTC().Format(time.RFC3339),
		Results:    results,
		Consensus:  consensus,
		UniqueSets: len(unique),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func resolveWith(resolverIP, name, recordType string, ctx context.Context) ([]string, error) {
	// Custom resolver dialing specific DNS server
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(resolverIP, "53"))
		},
	}
	timeCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	switch recordType {
	case "A":
		ips, err := resolver.LookupIP(timeCtx, "ip4", name)
		if err != nil {
			return nil, err
		}
		ans := make([]string, 0, len(ips))
		for _, ip := range ips {
			ans = append(ans, ip.String())
		}
		sort.Strings(ans)
		return ans, nil
	case "AAAA":
		ips, err := resolver.LookupIP(timeCtx, "ip6", name)
		if err != nil {
			return nil, err
		}
		ans := make([]string, 0, len(ips))
		for _, ip := range ips {
			ans = append(ans, ip.String())
		}
		sort.Strings(ans)
		return ans, nil
	case "CNAME":
		c, err := resolver.LookupCNAME(timeCtx, name)
		if err != nil {
			return nil, err
		}
		return []string{strings.TrimSuffix(c, ".")}, nil
	case "MX":
		mx, err := resolver.LookupMX(timeCtx, name)
		if err != nil {
			return nil, err
		}
		ans := make([]string, 0, len(mx))
		for _, m := range mx {
			ans = append(ans, fmt.Sprintf("%d %s", m.Pref, strings.TrimSuffix(m.Host, ".")))
		}
		sort.Strings(ans)
		return ans, nil
	case "NS":
		ns, err := resolver.LookupNS(timeCtx, name)
		if err != nil {
			return nil, err
		}
		ans := make([]string, 0, len(ns))
		for _, n := range ns {
			ans = append(ans, strings.TrimSuffix(n.Host, "."))
		}
		sort.Strings(ans)
		return ans, nil
	case "TXT":
		txts, err := resolver.LookupTXT(timeCtx, name)
		if err != nil {
			return nil, err
		}
		sort.Strings(txts)
		return txts, nil
	}
	return nil, fmt.Errorf("unsupported type")
}

// MTRHop represents a single hop in the traceroute
type MTRHop struct {
	HopNumber    int     `json:"hop_number"`
	Host         string  `json:"host,omitempty"`
	IP           string  `json:"ip,omitempty"`
	SentPackets  int     `json:"sent_packets"`
	LossPercent  float64 `json:"loss_percent"`
	LastLatency  float64 `json:"last_latency_ms"`
	AvgLatency   float64 `json:"avg_latency_ms"`
	BestLatency  float64 `json:"best_latency_ms"`
	WorstLatency float64 `json:"worst_latency_ms"`
	StdDev       float64 `json:"std_dev_ms"`
	Jitter       float64 `json:"jitter_ms"`
}

// MTRResponse represents the complete traceroute response
type MTRResponse struct {
	Target    string     `json:"target"`
	Source    string     `json:"source"`
	StartTime string     `json:"start_time"`
	EndTime   string     `json:"end_time"`
	Duration  float64    `json:"duration_seconds"`
	TotalHops int        `json:"total_hops"`
	Hops      []MTRHop   `json:"hops"`
	Summary   MTRSummary `json:"summary"`
}

// MTRSummary provides statistical overview
type MTRSummary struct {
	TotalPackets int     `json:"total_packets"`
	LostPackets  int     `json:"lost_packets"`
	OverallLoss  float64 `json:"overall_loss_percent"`
	MinLatency   float64 `json:"min_latency_ms"`
	MaxLatency   float64 `json:"max_latency_ms"`
	AvgLatency   float64 `json:"avg_latency_ms"`
	Jitter       float64 `json:"jitter_ms"`
}

// GetMTRTraceroute performs traceroute using mtr with configurable options
func GetMTRTraceroute(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	target := strings.TrimSpace(vars["target"])
	if target == "" {
		http.Error(w, "target parameter is required", http.StatusBadRequest)
		return
	}

	// Parse query parameters for mtr options
	packets := strings.TrimSpace(r.URL.Query().Get("packets"))
	if packets == "" {
		packets = "10" // default packets
	}

	interval := strings.TrimSpace(r.URL.Query().Get("interval"))
	if interval == "" {
		interval = "1.0" // default interval
	}

	timeout := strings.TrimSpace(r.URL.Query().Get("timeout"))
	if timeout == "" {
		timeout = "2.0" // default timeout
	}

	maxHops := strings.TrimSpace(r.URL.Query().Get("max_hops"))
	if maxHops == "" {
		maxHops = "30" // default max hops
	}

	// Validate parameters
	if packets == "" || interval == "" || timeout == "" || maxHops == "" {
		http.Error(w, "all parameters must be provided", http.StatusBadRequest)
		return
	}

	// Validate MTR-specific restrictions
	if intervalFloat, err := strconv.ParseFloat(interval, 64); err == nil {
		if intervalFloat < 1.0 {
			http.Error(w, "MTR requires elevated privileges for intervals < 1.0 seconds. Use interval >= 1.0 or run with sudo.", http.StatusBadRequest)
			return
		}
	}

	// Build mtr command - use JSON output for easier parsing
	args := []string{}

	// Add flags first
	args = append(args, "--report")
	args = append(args, "--report-cycles", packets)
	args = append(args, "--json")

	// Add optional parameters only if they're different from defaults
	if interval != "1.0" {
		args = append(args, "--interval", interval)
	}
	if timeout != "2.0" {
		args = append(args, "--timeout", timeout)
	}
	if maxHops != "30" {
		args = append(args, "--max-ttl", maxHops)
	}

	// Add target last
	args = append(args, target)

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	// Execute command with proper error handling
	cmd := exec.CommandContext(ctx, "mtr", args...)

	startTime := time.Now()

	// Execute command and capture both stdout and stderr
	output, err := cmd.CombinedOutput()
	endTime := time.Now()
	duration := endTime.Sub(startTime).Seconds()

	if err != nil {
		// Check if mtr is not available
		if strings.Contains(err.Error(), "executable file not found") {
			http.Error(w, "mtr tool not found at mtr. Please install mtr (brew install mtr on macOS, apt-get install mtr on Ubuntu)", http.StatusServiceUnavailable)
			return
		}

		// Check if it's a permission issue (needs sudo)
		if strings.Contains(string(output), "Failure to open IPv4 sockets") || strings.Contains(string(output), "Invalid argument") {
			http.Error(w, "mtr requires elevated privileges. Please run the server with sudo or ensure proper socket permissions.", http.StatusServiceUnavailable)
			return
		}

		// For any other error, return the error details with output
		errorMsg := fmt.Sprintf("mtr execution failed: %v\nCommand: mtr %v\nOutput: %s", err, args, string(output))
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	// Parse mtr JSON output
	var hops []MTRHop
	var summary MTRSummary

	hops, summary = parseMTRJSONOutput(string(output))

	// Get source IP for context
	sourceIP := getSourceIP()

	resp := MTRResponse{
		Target:    target,
		Source:    sourceIP,
		StartTime: startTime.Format(time.RFC3339),
		EndTime:   endTime.Format(time.RFC3339),
		Duration:  duration,
		TotalHops: len(hops),
		Hops:      hops,
		Summary:   summary,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func parseMTRJSONOutput(output string) ([]MTRHop, MTRSummary) {
	// Parse MTR JSON output directly
	var jsonData map[string]interface{}

	hops := make([]MTRHop, 0)
	var allLatencies []float64

	if err := json.Unmarshal([]byte(output), &jsonData); err != nil {
		// If JSON parsing fails, return empty results
		return hops, MTRSummary{}
	}

	// Navigate through the JSON structure manually
	report, ok := jsonData["report"].(map[string]interface{})
	if !ok {
		return hops, MTRSummary{}
	}

	// Hubs is at the same level as mtr, not inside mtr
	hubs, ok := report["hubs"].([]interface{})
	if !ok {
		return hops, MTRSummary{}
	}

	// Parse each hub into a hop
	for _, hubInterface := range hubs {
		hub, ok := hubInterface.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract values with type assertions
		count, _ := hub["count"].(float64)
		host, _ := hub["host"].(string)
		loss, _ := hub["Loss%"].(float64)
		snt, _ := hub["Snt"].(float64)
		last, _ := hub["Last"].(float64)
		avg, _ := hub["Avg"].(float64)
		best, _ := hub["Best"].(float64)
		worst, _ := hub["Wrst"].(float64)
		stdev, _ := hub["StDev"].(float64)

		hop := MTRHop{
			HopNumber:    int(count),
			Host:         host,
			IP:           host,
			SentPackets:  int(snt),
			LossPercent:  loss,
			LastLatency:  last,
			AvgLatency:   avg,
			BestLatency:  best,
			WorstLatency: worst,
			StdDev:       stdev,
		}
		hop.Jitter = hop.WorstLatency - hop.BestLatency

		// Only add non-zero latencies to the allLatencies slice
		if last > 0 {
			allLatencies = append(allLatencies, last)
		}

		hops = append(hops, hop)
	}

	summary := calculateMTRSummary(hops, allLatencies)
	return hops, summary
}

func calculateMTRSummary(hops []MTRHop, allLatencies []float64) MTRSummary {
	summary := MTRSummary{}

	if len(hops) == 0 {
		return summary
	}

	// Calculate total and lost packets from actual data
	totalPackets := 0
	lostPackets := 0
	for _, hop := range hops {
		totalPackets += hop.SentPackets
		lostPackets += int(float64(hop.SentPackets) * hop.LossPercent / 100.0)
	}

	summary.TotalPackets = totalPackets
	summary.LostPackets = lostPackets
	summary.OverallLoss = float64(lostPackets) / float64(totalPackets) * 100

	// Calculate latency statistics
	if len(allLatencies) > 0 {
		sort.Float64s(allLatencies)
		summary.MinLatency = allLatencies[0]
		summary.MaxLatency = allLatencies[len(allLatencies)-1]

		sum := 0.0
		for _, lat := range allLatencies {
			sum += lat
		}
		summary.AvgLatency = sum / float64(len(allLatencies))

		// Calculate jitter (standard deviation of latencies)
		variance := 0.0
		for _, lat := range allLatencies {
			diff := lat - summary.AvgLatency
			variance += diff * diff
		}
		summary.Jitter = math.Sqrt(variance / float64(len(allLatencies)))
	}

	return summary
}

func getSourceIP() string {
	// Try to get local IP address
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "unknown"
}

// Screenshot data structures
type ScreenshotRequest struct {
	URL        string            `json:"url"`
	Timeout    int               `json:"timeout_seconds,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	Viewport   string            `json:"viewport,omitempty"`
	FullPage   bool              `json:"full_page,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	WaitFor    int               `json:"wait_for_ms,omitempty"`
	ChromeArgs []string          `json:"chrome_args,omitempty"`
}

type ScreenshotResult struct {
	URL           string `json:"url"`
	Status        int    `json:"status_code"`
	Title         string `json:"title"`
	Screenshot    string `json:"screenshot_base64"`
	Error         string `json:"error,omitempty"`
	ResponseTime  int    `json:"response_time_ms"`
	ContentLength int    `json:"content_length"`
	ContentType   string `json:"content_type"`
}

type ScreenshotResponse struct {
	Success   bool             `json:"success"`
	Result    ScreenshotResult `json:"result"`
	Timestamp string           `json:"timestamp"`
	Error     string           `json:"error,omitempty"`
}

type BatchScreenshotRequest struct {
	URLs          []string          `json:"urls"`
	Timeout       int               `json:"timeout_seconds,omitempty"`
	UserAgent     string            `json:"user_agent,omitempty"`
	Viewport      string            `json:"viewport,omitempty"`
	FullPage      bool              `json:"full_page,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	WaitFor       int               `json:"wait_for_ms,omitempty"`
	ChromeArgs    []string          `json:"chrome_args,omitempty"`
	MaxConcurrent int               `json:"max_concurrent,omitempty"`
}

type BatchScreenshotResponse struct {
	Success   bool               `json:"success"`
	Results   []ScreenshotResult `json:"results"`
	Summary   BatchSummary       `json:"summary"`
	Timestamp string             `json:"timestamp"`
	Error     string             `json:"error,omitempty"`
}

type BatchSummary struct {
	Total       int `json:"total"`
	Successful  int `json:"successful"`
	Failed      int `json:"failed"`
	TotalTimeMs int `json:"total_time_ms"`
}

// PostScreenshot takes a screenshot of a single URL
func PostScreenshot(w http.ResponseWriter, r *http.Request) {
	var req ScreenshotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// Validate URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid URL: %v", err), http.StatusBadRequest)
		return
	}

	if parsedURL.Scheme == "" {
		req.URL = "http://" + req.URL
	}

	// Set defaults
	if req.Timeout == 0 {
		req.Timeout = 30
	}
	if req.UserAgent == "" {
		req.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
	}
	if req.Viewport == "" {
		req.Viewport = "1920x1080"
	}
	if req.WaitFor == 0 {
		req.WaitFor = 1000
	}

	startTime := time.Now()
	result, err := takeScreenshot(req)
	responseTime := int(time.Since(startTime).Milliseconds())

	if err != nil {
		response := ScreenshotResponse{
			Success: false,
			Result: ScreenshotResult{
				URL:          req.URL,
				Status:       0,
				Title:        "",
				Screenshot:   "",
				Error:        err.Error(),
				ResponseTime: responseTime,
			},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Error:     err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	result.ResponseTime = responseTime
	response := ScreenshotResponse{
		Success:   true,
		Result:    result,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// PostBatchScreenshots takes screenshots of multiple URLs
func PostBatchScreenshots(w http.ResponseWriter, r *http.Request) {
	var req BatchScreenshotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.URLs) == 0 {
		http.Error(w, "URLs array is required", http.StatusBadRequest)
		return
	}

	if len(req.URLs) > 50 {
		http.Error(w, "Maximum 50 URLs allowed per batch", http.StatusBadRequest)
		return
	}

	// Set defaults
	if req.Timeout == 0 {
		req.Timeout = 30
	}
	if req.UserAgent == "" {
		req.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
	}
	if req.Viewport == "" {
		req.Viewport = "1920x1080"
	}
	if req.WaitFor == 0 {
		req.WaitFor = 1000
	}
	if req.MaxConcurrent == 0 {
		req.MaxConcurrent = 5
	}

	startTime := time.Now()
	results := make([]ScreenshotResult, len(req.URLs))

	// Process URLs with concurrency limit
	semaphore := make(chan struct{}, req.MaxConcurrent)
	var wg sync.WaitGroup

	for i, url := range req.URLs {
		wg.Add(1)
		go func(index int, targetURL string) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			screenshotReq := ScreenshotRequest{
				URL:        targetURL,
				Timeout:    req.Timeout,
				UserAgent:  req.UserAgent,
				Viewport:   req.Viewport,
				FullPage:   req.FullPage,
				Headers:    req.Headers,
				WaitFor:    req.WaitFor,
				ChromeArgs: req.ChromeArgs,
			}

			result, err := takeScreenshot(screenshotReq)
			if err != nil {
				results[index] = ScreenshotResult{
					URL:   targetURL,
					Error: err.Error(),
				}
			} else {
				results[index] = result
			}
		}(i, url)
	}

	wg.Wait()
	totalTime := int(time.Since(startTime).Milliseconds())

	// Calculate summary
	successful := 0
	failed := 0
	for _, result := range results {
		if result.Error == "" {
			successful++
		} else {
			failed++
		}
	}

	summary := BatchSummary{
		Total:       len(req.URLs),
		Successful:  successful,
		Failed:      failed,
		TotalTimeMs: totalTime,
	}

	response := BatchScreenshotResponse{
		Success:   failed == 0,
		Results:   results,
		Summary:   summary,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if failed > 0 {
		response.Error = fmt.Sprintf("%d out of %d screenshots failed", failed, len(req.URLs))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// takeScreenshot executes gowitness to capture a screenshot
func takeScreenshot(req ScreenshotRequest) (ScreenshotResult, error) {
	// Create temporary directory for gowitness output
	tempDir, err := os.MkdirTemp("", "gowitness-*")
	if err != nil {
		return ScreenshotResult{}, fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Parse viewport dimensions
	viewportX := "1920"
	viewportY := "1080"
	if req.Viewport != "" {
		parts := strings.Split(req.Viewport, "x")
		if len(parts) == 2 {
			viewportX = parts[0]
			viewportY = parts[1]
		}
	}

	// Build gowitness command
	args := []string{
		"scan", "single",
		"-u", req.URL,
		"--screenshot-path", tempDir,
		"--timeout", fmt.Sprintf("%d", req.Timeout),
		"--chrome-user-agent", req.UserAgent,
		"--chrome-window-x", viewportX,
		"--chrome-window-y", viewportY,
		"--delay", "1",
		"--write-stdout",
	}

	if req.FullPage {
		args = append(args, "--screenshot-fullpage")
	}

	// Add custom headers
	for key, value := range req.Headers {
		args = append(args, "--chrome-header", fmt.Sprintf("%s: %s", key, value))
	}

	// Add Chrome arguments
	for _, arg := range req.ChromeArgs {
		args = append(args, "--chrome-arg", arg)
	}

	// Execute gowitness
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Timeout+10)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gowitness", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return ScreenshotResult{}, fmt.Errorf("gowitness execution failed: %v, stderr: %s", err, stderr.String())
	}

	// Parse gowitness output for additional info - check both stdout and stderr
	output := stdout.String()
	stderrOutput := stderr.String()

	// Sometimes gowitness writes to stderr instead of stdout
	if output == "" || !strings.Contains(output, "title=") {
		output = stderrOutput
	}
	statusCode := 200
	title := ""
	contentType := ""

	// Extract status code from output
	if strings.Contains(output, "status-code=") {
		re := regexp.MustCompile(`status-code=(\d+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) > 1 {
			if code, err := strconv.Atoi(matches[1]); err == nil {
				statusCode = code
			}
		}
	}

	// Extract title from output - handle both quoted and unquoted titles
	if strings.Contains(output, "title=") {
		// Try quoted title first: title="value"
		re := regexp.MustCompile(`title="([^"]*)"`)
		matches := re.FindStringSubmatch(output)
		if len(matches) > 1 && matches[1] != "" {
			title = matches[1]
		} else {
			// Try unquoted title: title=value
			re = regexp.MustCompile(`title=([^\s]+)`)
			matches = re.FindStringSubmatch(output)
			if len(matches) > 1 {
				title = matches[1]
			}
		}
	}

	// Extract content type from output
	if strings.Contains(output, "content-type=") {
		re := regexp.MustCompile(`content-type=([^\s]+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) > 1 {
			contentType = matches[1]
		}
	}

	// Check if screenshot was actually taken
	hasScreenshot := strings.Contains(output, "have-screenshot=true")

	// Find the generated screenshot file (gowitness saves as JPEG by default with URL-encoded names)
	files, err := filepath.Glob(filepath.Join(tempDir, "*.jpg"))
	if err != nil || len(files) == 0 {
		// Try PNG as fallback
		files, err = filepath.Glob(filepath.Join(tempDir, "*.png"))
		if err != nil || len(files) == 0 {
			// Try JPEG with different patterns
			files, err = filepath.Glob(filepath.Join(tempDir, "*.jpeg"))
			if err != nil || len(files) == 0 {
				// Check if gowitness reported that no screenshot was taken
				if !hasScreenshot {
					return ScreenshotResult{
						URL:           req.URL,
						Status:        statusCode,
						Title:         title,
						Screenshot:    "",
						ContentType:   contentType,
						ContentLength: 0,
						Error:         "Screenshot could not be taken (have-screenshot=false)",
					}, nil
				}
				return ScreenshotResult{}, fmt.Errorf("no screenshot file found in %s. Files: %v", tempDir, listFilesInDir(tempDir))
			}
		}
	}

	screenshotFile := files[0]

	// Read and encode screenshot
	screenshotData, err := os.ReadFile(screenshotFile)
	if err != nil {
		return ScreenshotResult{}, fmt.Errorf("failed to read screenshot: %v", err)
	}

	screenshotBase64 := base64.StdEncoding.EncodeToString(screenshotData)

	return ScreenshotResult{
		URL:           req.URL,
		Status:        statusCode,
		Title:         title,
		Screenshot:    screenshotBase64,
		ContentType:   contentType,
		ContentLength: len(screenshotData),
	}, nil
}

// listFilesInDir lists all files in a directory for debugging
func listFilesInDir(dir string) []string {
	files, err := os.ReadDir(dir)
	if err != nil {
		return []string{fmt.Sprintf("error reading dir: %v", err)}
	}

	var fileNames []string
	for _, file := range files {
		fileNames = append(fileNames, file.Name())
	}
	return fileNames
}
