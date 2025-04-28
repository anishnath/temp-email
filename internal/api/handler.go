package api

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"temp-email/internal/db"

	"github.com/gorilla/mux"
)

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
	fmt.Fprintf(w, "[")
	for i, email := range emails {
		if i > 0 {
			fmt.Fprintf(w, ",")
		}
		fmt.Fprintf(w, `{"sender":"%s","subject":"%s","body":"%s","received_at":"%s"}`,
			email.Sender, email.Subject, email.Body, email.ReceivedAt)
	}
	fmt.Fprintf(w, "]")
}
