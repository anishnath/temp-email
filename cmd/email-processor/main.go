package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", os.Getenv("EMAIL_DB_PATH"))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	msg, err := mail.ReadMessage(os.Stdin)
	if err != nil {
		panic(err)
	}

	from := msg.Header.Get("From")
	to := msg.Header.Get("To")
	subject := msg.Header.Get("Subject")

	var plaintextBody, htmlBody string

	contentType := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		panic(err)
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(msg.Body, params["boundary"])

		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				panic(err)
			}

			buf := new(bytes.Buffer)
			buf.ReadFrom(p)

			switch {
			case strings.HasPrefix(p.Header.Get("Content-Type"), "text/plain"):
				plaintextBody = buf.String()
			case strings.HasPrefix(p.Header.Get("Content-Type"), "text/html"):
				htmlBody = buf.String()
			}
		}
	} else {
		// Single part email
		bodyBytes, _ := io.ReadAll(msg.Body)
		plaintextBody = string(bodyBytes)
	}

	expires := time.Now().Add(24 * time.Minute).Format("2006-01-02 15:04:05")

	_, err = db.Exec(`INSERT INTO emails (temp_address, sender, subject, plaintext_body, html_body, expires_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		to, from, subject, plaintextBody, htmlBody, expires)
	if err != nil {
		panic(err)
	}

	fmt.Println("Saved email successfully.")
}
