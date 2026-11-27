package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type webhookPayload struct {
	Role           string `json:"role"`
	Event          string `json:"event"`
	Subject        string `json:"subject"`
	Body           string `json:"body"`
	Severity       string `json:"severity"`
	Timestamp      string `json:"timestamp"`
	ProjectName    string `json:"project_name"`
	ProjectVersion string `json:"project_version"`
	AppURL         string `json:"app_url"`
}

type webhookTarget struct {
	transport string
	endpoint  string
	secret    string
}

var webhookFailureLogTimes sync.Map

func (s *Server) dispatchAdminWebhooks(event, subject, body, severity string) {
	if s.config == nil {
		return
	}
	webhooks := s.config.Contact.Admin.Webhooks
	targets := []webhookTarget{
		{"telegram", webhooks.Telegram, webhooks.TelegramSecret},
		{"discord", webhooks.Discord, webhooks.DiscordSecret},
		{"slack", webhooks.Slack, webhooks.SlackSecret},
		{"mattermost", webhooks.Mattermost, webhooks.MattermostSecret},
		{"pushover", webhooks.Pushover, webhooks.PushoverSecret},
		{"gotify", webhooks.Gotify, webhooks.GotifySecret},
		{"generic", webhooks.Generic, webhooks.GenericSecret},
	}
	eventTime := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	for _, target := range targets {
		if strings.TrimSpace(target.endpoint) == "" {
			continue
		}
		id, err := webhookUUIDv7()
		if err != nil {
			s.logWebhookFailure(target.transport, err)
			continue
		}
		payload := webhookPayload{
			Role: "admin", Event: event, Subject: subject, Body: body, Severity: severity,
			Timestamp:   eventTime,
			ProjectName: "caswhois", ProjectVersion: Version, AppURL: OfficialSite,
		}
		go s.retryWebhook(target, payload, id)
	}
}
func (s *Server) retryWebhook(target webhookTarget, payload webhookPayload, id string) {
	delays := []time.Duration{0, time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour, 24 * time.Hour}
	for attempt, delay := range delays {
		if delay > 0 {
			time.Sleep(delay)
		}
		if err := deliverWebhook(context.Background(), target, payload, id); err == nil {
			return
		} else if attempt == len(delays)-1 {
			s.logWebhookFailure(target.transport, err)
		}
	}
}

func deliverWebhook(ctx context.Context, target webhookTarget, payload webhookPayload, id string) error {
	secret, err := base64.StdEncoding.DecodeString(target.secret)
	if err != nil || len(secret) != 32 {
		return errors.New("webhook signing secret is invalid")
	}
	endpoint, err := url.Parse(target.endpoint)
	if err != nil || endpoint.Host == "" || endpoint.Scheme != "https" {
		return errors.New("webhook endpoint must be a valid HTTPS URL")
	}
	message := payload.Subject + "\n\n" + payload.Body
	var body []byte
	contentType := "application/json"
	switch target.transport {
	case "telegram":
		query := endpoint.Query()
		query.Set("text", message)
		endpoint.RawQuery = query.Encode()
	case "discord":
		body, err = json.Marshal(map[string]string{"content": message, "username": payload.ProjectName})
	case "slack", "mattermost":
		body, err = json.Marshal(map[string]string{"text": message})
	case "pushover":
		query := endpoint.Query()
		form := url.Values{"user": {query.Get("user")}, "token": {query.Get("token")}, "title": {payload.Subject}, "message": {payload.Body}, "priority": {webhookPriority(target.transport, payload.Severity)}}
		endpoint.RawQuery = ""
		endpoint.ForceQuery = false
		body = []byte(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	case "gotify":
		if !strings.HasSuffix(strings.TrimRight(endpoint.Path, "/"), "/message") {
			endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/message"
		}
		body, err = json.Marshal(map[string]any{"title": payload.Subject, "message": payload.Body, "priority": gotifyPriority(payload.Severity)})
	case "generic":
		body, err = json.Marshal(payload)
	default:
		return fmt.Errorf("unsupported webhook transport %q", target.transport)
	}
	if err != nil {
		return fmt.Errorf("encode webhook request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return errors.New("create webhook request")
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("X-Webhook-Signature", "sha256="+webhookSignature(secret, body))
	request.Header.Set("X-Webhook-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	request.Header.Set("X-Webhook-ID", id)
	request.Header.Set("X-Webhook-Event", payload.Event)
	request.Header.Set("User-Agent", payload.ProjectName+"/"+payload.ProjectVersion+" (+"+payload.AppURL+")")
	client := &http.Client{Timeout: 8 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("webhook request failed")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
	}
	return nil
}

func webhookSignature(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func webhookUUIDv7() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	millis := uint64(time.Now().UnixMilli())
	value[0] = byte(millis >> 40)
	value[1] = byte(millis >> 32)
	value[2] = byte(millis >> 24)
	value[3] = byte(millis >> 16)
	value[4] = byte(millis >> 8)
	value[5] = byte(millis)
	value[6] = value[6]&0x0f | 0x70
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func webhookPriority(_ string, severity string) string {
	if severity == "critical" {
		return "1"
	}
	return "0"
}

func gotifyPriority(severity string) int {
	switch severity {
	case "critical":
		return 8
	case "warning":
		return 5
	default:
		return 2
	}
}

func (s *Server) logWebhookFailure(transport string, err error) {
	key := "admin." + transport
	now := time.Now()
	if previous, ok := webhookFailureLogTimes.Load(key); ok && now.Sub(previous.(time.Time)) < time.Minute {
		return
	}
	webhookFailureLogTimes.Store(key, now)
	if s.logger != nil {
		s.logger.Warn("notify.webhook_failed", "role", "admin", "transport", transport, "reason", err.Error())
	} else {
		log.Printf("WARN: notify.webhook_failed role=admin transport=%s", transport)
	}
}
