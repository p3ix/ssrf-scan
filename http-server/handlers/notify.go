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

// Notifier sends real-time alerts to Discord/Telegram when an interaction is received.
type Notifier struct {
	discordWebhook     string
	telegramBotToken   string
	telegramChatID     string
	httpCli            *http.Client
}

func NewNotifier() *Notifier {
	return &Notifier{
		discordWebhook:   os.Getenv("DISCORD_WEBHOOK"),
		telegramBotToken: os.Getenv("TELEGRAM_BOT_TOKEN"),
		telegramChatID:   os.Getenv("TELEGRAM_CHAT_ID"),
		httpCli:          &http.Client{Timeout: 5 * time.Second},
	}
}

// Notify sends the interaction to configured webhooks asynchronously.
func (n *Notifier) Notify(i *db.Interaction) {
	if n.discordWebhook != "" {
		go n.sendDiscord(i)
	}
	if n.telegramBotToken != "" && n.telegramChatID != "" {
		go n.sendTelegram(i)
	}
}

func (n *Notifier) sendDiscord(i *db.Interaction) {
	msg := fmt.Sprintf("🎯 **SSRF-BOX Interaction**\n```\nType: %s\nUUID: %s\nFrom: %s\nPath: %s\nDecoded: %s\nTime: %s\n```",
		i.Type, i.UUID, i.SourceIP, i.Path, i.DecodedData, i.Timestamp.Format(time.RFC3339))

	payload, _ := json.Marshal(map[string]string{"content": msg})
	resp, err := n.httpCli.Post(n.discordWebhook, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("[NOTIFY] Discord error: %v", err)
		return
	}
	resp.Body.Close()
}

func (n *Notifier) sendTelegram(i *db.Interaction) {
	text := fmt.Sprintf("🎯 SSRF-BOX Hit!\nType: %s\nUUID: %s\nFrom: %s\nPath: %s\nDecoded: %s\nTime: %s",
		i.Type, i.UUID, i.SourceIP, i.Path, i.DecodedData, i.Timestamp.Format(time.RFC3339))

	payload, _ := json.Marshal(map[string]string{
		"chat_id": n.telegramChatID,
		"text":    text,
	})
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.telegramBotToken)
	resp, err := n.httpCli.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("[NOTIFY] Telegram error: %v", err)
		return
	}
	resp.Body.Close()
}
