package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"temp-email/internal/api"

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
	r := mux.NewRouter()

	// Email-related endpoints
	r.HandleFunc("/generate", generateEmail).Methods("GET")
	r.HandleFunc("/inbox/{address}", api.GetInbox).Methods("GET")

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
		handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type"}),
	)

	srv := &http.Server{
		Addr:    ":" + serverPort,
		Handler: corsHandler(r),
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
