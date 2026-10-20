package agentsecurity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientRejectsNonLoopbackAndUnknownTool(t *testing.T) {
	for _, endpoint := range []string{"https://example.com:443/mcp", "http://127.0.0.1:9/other", "http://u:p@127.0.0.1:9/mcp", "http://127.0.0.1:9/mcp?url=evil"} {
		if _, err := New(endpoint, strings.Repeat("x", 32)); err == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}
	c, err := New("http://127.0.0.1:9/mcp", strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(context.Background(), "execute_shell", json.RawMessage(`{}`)); err == nil {
		t.Fatal("arbitrary tool accepted")
	}
}

func TestClientMCPHandshakeAndStructuredResult(t *testing.T) {
	methods := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("x", 32) {
			t.Error("auth missing")
		}
		var req struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("invalid request")
		}
		methods = append(methods, req.Method)
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "notifications/initialized" {
			w.WriteHeader(202)
			return
		}
		result := any(map[string]any{"protocolVersion": "2025-06-18"})
		if req.Method == "tools/call" {
			result = map[string]any{"structuredContent": map[string]any{"runs": []any{}}, "content": []any{}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer server.Close()
	c, err := New(server.URL+"/mcp", strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Call(context.Background(), "get_test_run", json.RawMessage(`{}`))
	if err != nil || !json.Valid(result) {
		t.Fatalf("call: %s %v", result, err)
	}
	if len(methods) != 3 || methods[0] != "initialize" || methods[1] != "notifications/initialized" || methods[2] != "tools/call" {
		t.Fatalf("handshake %v", methods)
	}
}

func TestClientDoesNotFollowRedirectOrEchoServiceSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com", 302)
	}))
	defer server.Close()
	c, _ := New(server.URL+"/mcp", strings.Repeat("private", 6))
	_, err := c.Call(context.Background(), "get_test_run", json.RawMessage(`{}`))
	if err == nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("unsafe error %v", err)
	}
}
