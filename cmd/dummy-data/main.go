package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"temp-email/internal/db"
	"temp-email/pkg/utils"

	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load("config/.env"); err != nil {
		log.Println("No .env file found, relying on system env vars")
	}

	dbPath := os.Getenv("EMAIL_DB_PATH")
	if dbPath == "" {
		log.Fatal("EMAIL_DB_PATH is not set")
	}
	emailDomain := os.Getenv("EMAIL_DOMAIN")
	if emailDomain == "" {
		log.Fatal("EMAIL_DOMAIN is not set")
	}

	// Generate and insert 10 dummy records
	for i := 0; i < 10; i++ {
		_ = fmt.Sprintf("%s@%s", utils.RandomString(8), emailDomain)
		sender := fmt.Sprintf("sender%s@example.com", utils.RandomString(4))
		subject := fmt.Sprintf("Test Email %d", i+1)
		body := fmt.Sprintf("This is a dummy email body for record %d.\n", i+1)
		_ = time.Now().Add(-time.Duration(rand.Intn(60)) * time.Minute).Format("2006-01-02 15:04:05")
		_ = time.Now().Add(time.Hour).Format("2006-01-02 15:04:05")

		err := db.SaveEmail("fglo36vj@test.com", sender, subject, body)
		if err != nil {
			log.Printf("Failed to insert record %d: %v", i+1, err)
			continue
		}
		log.Printf("Inserted record: %s", "sylllp14@test.com")
	}

	log.Println("Dummy data generation complete")
}
