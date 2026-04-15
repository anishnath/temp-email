package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"temp-email/internal/api"
	"temp-email/internal/latex"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

var emailDomain string
var serverPort string

func init() {
	if err := godotenv.Load("config/.env"); err != nil {
		log.Println("No .env file found, relying on system env vars")
	}
	emailDomain = os.Getenv("EMAIL_DOMAIN")
	if emailDomain == "" {
		log.Fatal("EMAIL_DOMAIN is not set")
	}

	// Get server port from environment, default to 8080
	serverPort = os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = "8080"
	}
}

func main() {
	// Start LaTeX compile worker pool
	latexCfg := latex.LoadConfig()
	latex.StartWorkerPool(latexCfg.WorkerPoolSize)

	// Init Pastebin (optional; skips if R2 not configured)
	if err := api.InitPastebin(); err != nil {
		log.Printf("Pastebin init skipped: %v", err)
	}
	api.StartPastebinCleanup()

	r := mux.NewRouter()

	// Email-related endpoints
	r.HandleFunc("/generate", generateEmail).Methods("GET")
	r.HandleFunc("/inbox/{address}", api.GetInbox).Methods("GET")

	// LaTeX compilation API (served from main process)
	r.HandleFunc("/api/latex/compile", api.GetLaTeXCompile).Methods("POST")
	r.HandleFunc("/api/latex/tikz/compile", api.PostTikzCompile).Methods("POST")
	r.HandleFunc("/api/latex/upload", api.GetLaTeXUpload).Methods("POST")
	r.HandleFunc("/api/latex/jobs/{jobId}/status", api.GetLaTeXJobStatus).Methods("GET")
	r.HandleFunc("/api/latex/jobs/{jobId}/pdf", api.GetLaTeXJobPDF).Methods("GET")
	r.HandleFunc("/api/latex/jobs/{jobId}/svg", api.GetLaTeXJobSVG).Methods("GET")
	r.HandleFunc("/api/latex/jobs/{jobId}/logs", api.GetLaTeXJobLogs).Methods("GET")

	// Arduino CLI compile (temp sketch dir, cleaned after compile + delayed cleanup)
	r.HandleFunc("/api/arduino-compile", api.PostArduinoCompile).Methods("POST")
	r.HandleFunc("/api/arduino-libraries", api.GetArduinoLibrariesOverview).Methods("GET")
	r.HandleFunc("/api/arduino-libraries/installed", api.GetArduinoLibrariesInstalled).Methods("GET")
	r.HandleFunc("/api/arduino-libraries/search", api.GetArduinoLibrariesSearch).Methods("GET")
	r.HandleFunc("/api/arduino-libraries/install", api.PostArduinoLibraryInstall).Methods("POST")

	// Arduino QEMU simulation (ESP32 boards — SSE streaming)
	r.HandleFunc("/api/arduino-simulate/start", api.PostArduinoSimulateStart).Methods("POST")
	r.HandleFunc("/api/arduino-simulate/stop", api.PostArduinoSimulateStop).Methods("POST")
	r.HandleFunc("/api/arduino-simulate/input", api.PostArduinoSimulateInput).Methods("POST")
	r.HandleFunc("/api/arduino-simulate/stream", api.GetArduinoSimulateStream).Methods("GET")

	// Raspberry Pi 3 QEMU simulation (SSE streaming)
	r.HandleFunc("/api/pi-simulate/start", api.PostPiSimulateStart).Methods("POST")
	r.HandleFunc("/api/pi-simulate/stop", api.PostPiSimulateStop).Methods("POST")
	r.HandleFunc("/api/pi-simulate/input", api.PostPiSimulateInput).Methods("POST")
	r.HandleFunc("/api/pi-simulate/gpio", api.PostPiSimulateGPIO).Methods("POST")
	r.HandleFunc("/api/pi-simulate/stream", api.GetPiSimulateStream).Methods("GET")

	// Network and security tool endpoints
	r.HandleFunc("/subdomains/{domain}", api.GetSubdomains).Methods("GET")
	r.HandleFunc("/portscan/{target}", api.GetPortScan).Methods("GET")
	r.HandleFunc("/whois/{domain}", api.GetWhois).Methods("GET")
	r.HandleFunc("/sslscan/{domain}", api.GetSSLScan).Methods("GET")
	r.HandleFunc("/revdns/{ip}", api.GetReverseDNS).Methods("GET")
	r.HandleFunc("/dnsprop/{name}", api.GetDNSPropagation).Methods("GET")
	r.HandleFunc("/mtr/{target}", api.GetMTRTraceroute).Methods("GET")
	r.HandleFunc("/httpstat", api.PostHTTPStat).Methods("POST")
	r.HandleFunc("/screenshot", api.PostScreenshot).Methods("POST")
	r.HandleFunc("/screenshots", api.PostBatchScreenshots).Methods("POST")

	// Lighthouse single-page audit (runs local lighthouse CLI, results stored in SQLite)
	r.HandleFunc("/api/lighthouse", api.PostLighthouse).Methods("POST")
	r.HandleFunc("/api/lighthouse/audits", api.GetLighthouseAudits).Methods("GET")
	r.HandleFunc("/api/lighthouse/audits/{id}", api.GetLighthouseAuditByID).Methods("GET")

	// SEO site audit (SQLite; SEOnaut-compatible crawlers and issue rules)
	r.HandleFunc("/api/seo/crawls", api.GetSEOCrawlList).Methods("GET")
	r.HandleFunc("/api/seo/crawl", api.PostSEOStartCrawl).Methods("POST")
	r.HandleFunc("/api/seo/crawl/{id}/cancel", api.PostSEOCancelCrawl).Methods("POST")
	r.HandleFunc("/api/seo/crawl/{id}/findings", api.GetSEOFindings).Methods("GET")
	r.HandleFunc("/api/seo/crawl/{id}/issues/pages", api.GetSEOPagesForIssue).Methods("GET")
	r.HandleFunc("/api/seo/crawl/{id}/page/{page_id}", api.GetSEOPageDetail).Methods("GET")
	r.HandleFunc("/api/seo/crawl/{id}", api.GetSEOStatus).Methods("GET")

	// Pastebin API
	r.HandleFunc("/api/pastebin", api.PostPastebin).Methods("POST")
	r.HandleFunc("/api/pastebin/keys", api.PostPastebinKeys).Methods("POST")
	r.HandleFunc("/api/pastebin/health", api.GetPastebinHealth).Methods("GET")
	r.HandleFunc("/api/pastebin/stats", api.GetPastebinStats).Methods("GET")
	r.HandleFunc("/api/pastebin/recent", api.GetPastebinRecent).Methods("GET")
	r.HandleFunc("/api/pastebin/mine", api.GetPastebinMine).Methods("GET")
	// {id} uses regex so "health", "stats", "keys", "mine" don't match
	// {id} requires 8+ chars (excludes health, stats, keys, mine)
	r.HandleFunc(`/api/pastebin/{id:[a-z0-9][a-z0-9_-]{7,}}/raw`, api.GetPastebinRaw).Methods("GET")
	r.HandleFunc(`/api/pastebin/{id:[a-z0-9][a-z0-9_-]{7,}}`, api.GetPastebin).Methods("GET")
	r.HandleFunc(`/api/pastebin/{id:[a-z0-9][a-z0-9_-]{7,}}`, api.DeletePastebin).Methods("DELETE")

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("static")))

	allowedOrigins := []string{
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"https://831f-2402-e280-2254-198-3993-c8a9-dbde-b0f4.ngrok-free.app",
		"https://preview--temporary-inbox-now.lovable.app",
		"https://procmail.xyz",
		"https://procmail.xyz",
		"https://api.procmail.xyz",
		"https://goodbanners.xyz",
		"https://8gwifi.org",
	}

	corsHandler := handlers.CORS(
		handlers.AllowedOrigins(allowedOrigins),
		handlers.AllowedMethods([]string{"GET", "POST", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "X-API-Key", "X-Delete-Token"}),
	)

	// Gzip responses when Accept-Encoding includes gzip (gorilla CompressHandler).
	// Many clients decode automatically (browsers, curl --compressed). For manual
	// gunzip: send Accept-Encoding: gzip, read raw body bytes, inflate with zlib/gzip.
	srv := &http.Server{
		Addr:    ":" + serverPort,
		Handler: corsHandler(handlers.CompressHandler(r)),
	}
	log.Println("Starting server on :" + serverPort)
	log.Fatal(srv.ListenAndServe())
}

func generateEmail(w http.ResponseWriter, r *http.Request) {
	rand.Seed(time.Now().UnixNano())
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	email := fmt.Sprintf("%s@%s", b, emailDomain)
	fmt.Fprint(w, email)
}
