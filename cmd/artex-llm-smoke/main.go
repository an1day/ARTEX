// Command artex-llm-smoke checks the configured ARTEX provider with synthetic
// messages and a single in-process echo tool. It never connects to a pentest target.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/llm"
)

type redactedWriter struct{ secret string }

func (w redactedWriter) Write(p []byte) (int, error) {
	_, err := fmt.Fprint(os.Stderr, strings.ReplaceAll(string(p), w.secret, "[REDACTED]"))
	return len(p), err
}

func main() {
	if err := run(); err != nil {
		// Errors may include gateway response snippets, so redact the configured key.
		message := err.Error()
		for _, name := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"} {
			if secret := os.Getenv(name); secret != "" {
				message = strings.ReplaceAll(message, secret, "[REDACTED]")
			}
		}
		fmt.Fprintln(os.Stderr, message)
		os.Exit(1)
	}
}

func run() error {
	cfg, ok := agent.FromEnv()
	if !ok {
		return fmt.Errorf("missing ARTEX LLM environment configuration")
	}
	log.SetOutput(redactedWriter{cfg.APIKey})
	cfg.Retry.ConnectAttempts = -1
	cfg.Retry.EmptyAttempts = -1
	provider, err := cfg.NewProvider()
	if err != nil {
		return fmt.Errorf("provider initialization: %w", err)
	}
	fmt.Printf("provider=%s model=%s\n", cfg.Provider(), cfg.Model)
	complete := func(req llm.CompletionRequest) (llm.Message, string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		message, stop, _, err := provider.Complete(ctx, req)
		return message, stop, err
	}
	req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("Reply with PONG only.")}, MaxTokens: 512}
	message, stop, err := complete(req)
	if err != nil {
		return fmt.Errorf("nonstream: %w", err)
	}
	if strings.TrimSpace(message.Text()) != "PONG" || stop != "end_turn" {
		return fmt.Errorf("nonstream: expected PONG and end_turn")
	}
	fmt.Println("nonstream=passed")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	var text strings.Builder
	stopped := false
	for event, err := range provider.Stream(ctx, req) {
		if err != nil {
			cancel()
			return fmt.Errorf("stream: %w", err)
		}
		if event.Type == llm.SETextDelta {
			text.WriteString(event.Text)
			if text.Len() > 65536 {
				cancel()
				return fmt.Errorf("stream: text byte budget exceeded")
			}
		}
		if event.Type == llm.SEMessageStop {
			stopped = true
		}
	}
	cancel()
	if strings.TrimSpace(text.String()) != "PONG" || !stopped {
		return fmt.Errorf("stream: expected PONG and message_stop")
	}
	fmt.Println("stream=passed")
	tool := llm.ToolSchema{Name: "fixture_echo", Description: "Echo a synthetic marker locally. No external effects.", InputSchema: map[string]any{
		"type": "object", "properties": map[string]any{"marker": map[string]any{"type": "string", "enum": []string{"fixture-pong"}}},
		"required": []string{"marker"}, "additionalProperties": false,
	}}
	req = llm.CompletionRequest{System: []string{"Use fixture_echo exactly once with marker fixture-pong. After the tool result, reply PONG only."},
		Messages: []llm.Message{llm.UserText("Run the synthetic echo check.")}, Tools: []llm.ToolSchema{tool}, MaxTokens: 512}
	message, stop, err = complete(req)
	if err != nil {
		return fmt.Errorf("tool request: %w", err)
	}
	uses := message.ToolUses()
	if len(uses) != 1 || uses[0].Name != "fixture_echo" || uses[0].ID == "" || stop != "tool_use" {
		return fmt.Errorf("tool request: expected exactly one fixture_echo")
	}
	var input struct {
		Marker string `json:"marker"`
	}
	if err := json.Unmarshal(uses[0].Input, &input); err != nil || input.Marker != "fixture-pong" {
		return fmt.Errorf("tool request: unexpected synthetic input")
	}
	req.Messages = append(req.Messages, message, llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText(uses[0].ID, "fixture-pong", false)}})
	message, stop, err = complete(req)
	if err != nil {
		return fmt.Errorf("tool result: %w", err)
	}
	if len(message.ToolUses()) != 0 || strings.TrimSpace(message.Text()) != "PONG" || stop != "end_turn" {
		return fmt.Errorf("tool result: expected final PONG and end_turn")
	}
	fmt.Println("tool_roundtrip=passed")
	return nil
}
