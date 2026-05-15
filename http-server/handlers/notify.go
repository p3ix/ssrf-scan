package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ssrf-box/http-server/db"
)

// Notifier sends real-time alerts to Discord, Telegram, and Slack when an interaction is received.
type Notifier struct {
	discordWebhook   string
	telegramBotToken string
	telegramChatID   string
	slackWebhook     string
	httpCli          *http.Client
}

func NewNotifier() *Notifier {
	return &Notifier{
		discordWebhook:   os.Getenv("DISCORD_WEBHOOK"),
		telegramBotToken: os.Getenv("TELEGRAM_BOT_TOKEN"),
		telegramChatID:   os.Getenv("TELEGRAM_CHAT_ID"),
		slackWebhook:     os.Getenv("SLACK_WEBHOOK"),
		httpCli:          &http.Client{Timeout: 15 * time.Second},
	}
}

// Notify sends the interaction to all configured webhooks asynchronously, with retry.
func (n *Notifier) Notify(i *db.Interaction) {
	if n.discordWebhook != "" {
		go n.withRetry(func() error { return n.sendDiscord(i) }, "discord")
	}
	if n.telegramBotToken != "" && n.telegramChatID != "" {
		go n.withRetry(func() error { return n.sendTelegram(i) }, "telegram")
	}
	if n.slackWebhook != "" {
		go n.withRetry(func() error { return n.sendSlack(i) }, "slack")
	}
}

// withRetry calls fn up to 3 times with exponential backoff (2s, 4s).
func (n *Notifier) withRetry(fn func() error, label string) {
	for attempt := 0; attempt < 3; attempt++ {
		if err := fn(); err == nil {
			return
		} else if attempt < 2 {
			log.Printf("[NOTIFY] %s error (attempt %d/3), retrying: %v", label, attempt+1, err)
			time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
		} else {
			log.Printf("[NOTIFY] %s failed after 3 attempts", label)
		}
	}
}

func notifyMsg(i *db.Interaction) string {
	decoded := i.DecodedData
	if decoded == "" {
		decoded = i.RawData
	}
	return fmt.Sprintf("SSRF-BOX Hit!\nType: %s | UUID: %s\nFrom: %s\nPath: %s\nDecoded: %s\nTime: %s",
		i.Type, i.UUID, i.SourceIP, i.Path, decoded, i.Timestamp.Format(time.RFC3339))
}

func (n *Notifier) sendDiscord(i *db.Interaction) error {
	msg := "```\n" + notifyMsg(i) + "\n```"
	payload, _ := json.Marshal(map[string]string{"content": msg})
	resp, err := n.httpCli.Post(n.discordWebhook, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (n *Notifier) sendTelegram(i *db.Interaction) error {
	payload, _ := json.Marshal(map[string]string{
		"chat_id": n.telegramChatID,
		"text":    notifyMsg(i),
	})
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.telegramBotToken)
	resp, err := n.httpCli.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// sendSlack posts to a Slack incoming webhook (same format as Discord but key is "text").
func (n *Notifier) sendSlack(i *db.Interaction) error {
	payload, _ := json.Marshal(map[string]string{"text": notifyMsg(i)})
	resp, err := n.httpCli.Post(n.slackWebhook, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
