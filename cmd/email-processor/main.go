package main

import (
	"fmt"
	"github.com/joho/godotenv"
	"os"
	"temp-email/internal/email"
)

func init() {
	if err := godotenv.Load("/home/ec2-user/go/src/temp-email/config/.env"); err != nil {
		fmt.Println("No .env file found, relying on system env vars")
	}
}

func main() {
	if err := email.ProcessEmail(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
