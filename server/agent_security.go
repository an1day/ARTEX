package server

import (
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/Autumn-27/artex/agentsecurity"
)

// These routes inherit the application's JWT middleware. The service address
// and credential are operator settings, never supplied by model or browser.
func (s *Server) registerAgentSecurityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/agent-security/status", s.agentSecurityStatus)
	mux.HandleFunc("POST /api/agent-security/tools/{tool}", s.agentSecurityCall)
}

func (s *Server) agentSecurityStatus(w http.ResponseWriter, r *http.Request) {
	_, err := agentsecurity.New(os.Getenv("ARTEX_AGENT_TEST_URL"), os.Getenv("AGENT_TEST_SERVICE_TOKEN"))
	writeJSON(w, 200, map[string]any{"configured": err == nil, "milestone": "local-sidecar-mvp", "confirmed_finding_import": false})
}

func (s *Server) agentSecurityCall(w http.ResponseWriter, r *http.Request) {
	tool := r.PathValue("tool")
	if !agentsecurity.Tools[tool] {
		writeErr(w, 404, "unknown Agent test tool")
		return
	}
	client, err := agentsecurity.New(os.Getenv("ARTEX_AGENT_TEST_URL"), os.Getenv("AGENT_TEST_SERVICE_TOKEN"))
	if err != nil {
		writeErr(w, 503, "Agent 测试服务未配置；请配置本地服务地址与认证环境变量")
		return
	}
	defer client.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	body, err := io.ReadAll(r.Body)
	if err != nil || !json.Valid(body) {
		writeErr(w, 400, "invalid or oversized tool arguments")
		return
	}
	result, err := client.Call(r.Context(), tool, body)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
