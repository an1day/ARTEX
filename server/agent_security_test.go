package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentSecurityRoutesRequireJWTAndFailClosed(t *testing.T) {
	t.Setenv("ARTEX_AGENT_TEST_URL", "")
	t.Setenv("AGENT_TEST_SERVICE_TOKEN", "")
	s := &Server{jwtKey: []byte(strings.Repeat("x", 32))}
	mux := http.NewServeMux()
	s.registerAgentSecurityRoutes(mux)
	handler := s.requireAuth(mux)
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path  string
		authenticated bool
		code          int
	}{
		{"GET", "/api/agent-security/status", false, 401},
		{"GET", "/api/agent-security/status", true, 200},
		{"POST", "/api/agent-security/tools/execute_shell", true, 404},
		{"POST", "/api/agent-security/tools/start_test_run", true, 503},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
		if tc.authenticated {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("%s: got %d want %d", tc.path, w.Code, tc.code)
		}
	}
}
