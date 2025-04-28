package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"temp-email/internal/api"
)

var emailDomain string

func init() {
	if err := godotenv.Load("config/.env"); err != nil {
		log.Println("No .env file found, relying on system env vars")
	}
	emailDomain = os.Getenv("EMAIL_DOMAIN")
	if emailDomain == "" {
		log.Fatal("EMAIL_DOMAIN is not set")
	}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/generate", generateEmail).Methods("GET")
	r.HandleFunc("/inbox/{address}", api.GetInbox).Methods("GET")
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("static")))

	allowedOrigins := []string{
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"https://831f-2402-e280-2254-198-3993-c8a9-dbde-b0f4.ngrok-free.app",
		"https://preview--temporary-inbox-now.lovable.app",
	}

	corsHandler := handlers.CORS(
		handlers.AllowedOrigins(allowedOrigins),
		handlers.AllowedMethods([]string{"GET", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type"}),
	)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: corsHandler(r),
	}
	log.Println("Starting server on :8080")
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
