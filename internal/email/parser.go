package email

import (
	"bufio"
	"os"
	"strings"
	"temp-email/internal/db"
)

func ProcessEmail() error {
	scanner := bufio.NewScanner(os.Stdin)
	var address, sender, subject, body string
	var inBody bool

	for scanner.Scan() {
		line := scanner.Text()
		if inBody {
			body += line + "\n"
			continue
		}
		if line == "" {
			inBody = true
			continue
		}
		if strings.HasPrefix(line, "To: ") {
			address = strings.TrimPrefix(line, "To: ")
		} else if strings.HasPrefix(line, "From: ") {
			sender = strings.TrimPrefix(line, "From: ")
		} else if strings.HasPrefix(line, "Subject: ") {
			subject = strings.TrimPrefix(line, "Subject: ")
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return db.SaveEmail(address, sender, subject, body)
}
