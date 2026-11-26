// Package mail sends plain-text notifications through an unauthenticated relay
// (noggin's MAIL_SERVER), the same way noggin does.
package mail

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"mime"
	netmail "net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type Mailer struct {
	Addr    string // host:port
	From    string // header form, "Name <addr>"
	Enabled bool
}

func New(server string, port int, from string, enabled bool) *Mailer {
	return &Mailer{Addr: server + ":" + strconv.Itoa(port), From: from, Enabled: enabled}
}

// Send delivers one message. Recipients without an address are skipped.
func (m *Mailer) Send(to []string, subject, body string) error {
	if m == nil || !m.Enabled {
		return nil
	}
	var rcpts []string
	for _, t := range to {
		if t = strings.TrimSpace(t); t != "" {
			rcpts = append(rcpts, t)
		}
	}
	if len(rcpts) == 0 {
		return nil
	}
	from, err := netmail.ParseAddress(m.From)
	if err != nil {
		return fmt.Errorf("mail: sender: %w", err)
	}
	id := make([]byte, 12)
	rand.Read(id)
	domain := from.Address[strings.LastIndexByte(from.Address, '@')+1:]

	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from.String())
	if len(rcpts) == 1 {
		fmt.Fprintf(&b, "To: %s\r\n", rcpts[0])
	} else {
		b.WriteString("To: undisclosed-recipients:;\r\n")
	}
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id), domain)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\nAuto-Submitted: auto-generated\r\n\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	return smtp.SendMail(m.Addr, nil, from.Address, rcpts, []byte(b.String()))
}

// SendAsync sends in the background and logs failures.
func (m *Mailer) SendAsync(to []string, subject, body string) {
	if m == nil || !m.Enabled {
		return
	}
	go func() {
		if err := m.Send(to, subject, body); err != nil {
			slog.Warn("mail failed", "subject", subject, "rcpts", len(to), "err", err)
		}
	}()
}
