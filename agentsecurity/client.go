// Package agentsecurity bridges ARTEX to the local, authenticated test sidecar.
// Target credentials and the tested Agent's tools never enter this bridge.
package agentsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var Tools = map[string]bool{
	"list_target_capabilities": true, "list_test_cases": true,
	"start_test_run": true, "get_test_run": true, "cancel_test_run": true,
	"get_evidence_manifest": true, "get_evidence_preview": true, "verify_candidate": true,
}

type Client struct {
	endpoint string
	token    string
	http     *http.Client
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func New(endpoint, token string) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid Agent test service URL")
	}
	host := u.Hostname()
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || u.Port() == "" || (u.Path != "/mcp" && u.Path != "/mcp/") {
		return nil, errors.New("Agent test service must use an explicit loopback port and /mcp path")
	}
	if len(token) < 32 || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("invalid Agent test service token")
	}
	u.Host = net.JoinHostPort(host, u.Port())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Client{u.String(), token, &http.Client{
		Timeout: 15 * time.Second, Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("redirects are disabled") },
	}}, nil
}

type envelope struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code int `json:"code"`
	} `json:"error"`
}

func (c *Client) request(ctx context.Context, method string, params any, id any) (json.RawMessage, error) {
	body := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
	if id != nil {
		body["id"] = id
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("invalid tool input")
	}
	if len(raw) > 65536 {
		return nil, errors.New("tool input exceeds limit")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("invalid service request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("Agent test service unavailable")
	}
	defer res.Body.Close()
	if id == nil && (res.StatusCode == 202 || res.StatusCode == 204) {
		return nil, nil
	}
	if res.StatusCode != 200 {
		return nil, errors.New("Agent test service rejected request")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 2*1024*1024+1))
	if err != nil || len(data) > 2*1024*1024 {
		return nil, errors.New("service response exceeds limit")
	}
	var response envelope
	if json.Unmarshal(data, &response) != nil || response.Error != nil || len(response.Result) == 0 {
		return nil, errors.New("invalid service response")
	}
	return response.Result, nil
}

func (c *Client) Call(ctx context.Context, tool string, args json.RawMessage) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if !Tools[tool] {
		return nil, errors.New("test tool is not allowed")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(args, &obj) != nil || obj == nil {
		return nil, errors.New("tool arguments must be an object")
	}
	if _, err := c.request(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]string{"name": "artex-agent-security", "version": "0.1.0"},
	}, 1); err != nil {
		return nil, err
	}
	if _, err := c.request(ctx, "notifications/initialized", map[string]any{}, nil); err != nil {
		return nil, err
	}
	result, err := c.request(ctx, "tools/call", map[string]any{"name": tool, "arguments": obj}, 2)
	if err != nil {
		return nil, err
	}
	var response struct {
		IsError    bool            `json:"isError"`
		Structured json.RawMessage `json:"structuredContent"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(result, &response) != nil || response.IsError {
		return nil, errors.New("test tool rejected input or could not complete")
	}
	if len(response.Structured) > 0 && string(response.Structured) != "null" {
		return response.Structured, nil
	}
	for _, block := range response.Content {
		if block.Type == "text" && json.Valid([]byte(block.Text)) {
			return json.RawMessage(block.Text), nil
		}
	}
	return nil, errors.New("test tool returned no structured result")
}
