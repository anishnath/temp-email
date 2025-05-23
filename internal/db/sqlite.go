package db

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"os"
)

type Email struct {
	Sender        string
	Subject       string
	PlainTextBody string
	HTMLBody      string
	ReceivedAt    string
}

func GetEmails(address string) ([]Email, error) {
	dbPath := os.Getenv("EMAIL_DB_PATH")
	if dbPath == "" {
		return nil, os.ErrNotExist
	}
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT sender, subject, plaintext_body, html_body, received_at
		FROM emails
		WHERE (temp_address = ? OR temp_address LIKE '%<%' || ? || '%>')
		  AND expires_at > datetime('now')
	`, address, address)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var emails []Email
	for rows.Next() {
		var e Email
		if err := rows.Scan(&e.Sender, &e.Subject, &e.PlainTextBody, &e.HTMLBody, &e.ReceivedAt); err != nil {
			return nil, err
		}
		emails = append(emails, e)
	}
	return emails, nil
}

func SaveEmail(address, sender, subject, body string) error {
	dbPath := os.Getenv("EMAIL_DB_PATH")
	if dbPath == "" {
		return os.ErrNotExist
	}
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`
		INSERT INTO emails (temp_address, sender, subject, body, expires_at)
		VALUES (?, ?, ?, ?, datetime('now', '+1 hour'))
	`, address, sender, subject, body)
	return err
}
