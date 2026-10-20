package agentsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

// Enabled only by the synthetic Python integration harness. No PRE endpoint is
// read from this variable: New still restricts it to the loopback MCP service.
func TestLivePythonSidecar(t *testing.T) {
	endpoint := os.Getenv("ARTEX_AGENT_TEST_INTEGRATION_URL")
	if endpoint == "" {
		t.Skip("synthetic integration harness not running")
	}
	client, err := New(endpoint, os.Getenv("AGENT_TEST_SERVICE_TOKEN"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	call := func(tool string, args any) json.RawMessage {
		t.Helper()
		raw, _ := json.Marshal(args)
		result, err := client.Call(ctx, tool, raw)
		if err != nil {
			t.Fatalf("%s failed: %v", tool, err)
		}
		return result
	}
	var started struct {
		RunID string `json:"run_id"`
	}
	raw := call("start_test_run", map[string]any{
		"target_id": "synthetic-wesmart", "case_ids": []string{"T03"}, "scope_revision": "synthetic-v1",
		"idempotency_key": fmt.Sprintf("go-integration-%d", time.Now().UnixNano()),
	})
	if json.Unmarshal(raw, &started) != nil || started.RunID == "" {
		t.Fatal("missing run ID")
	}
	var state struct {
		Status     string `json:"status"`
		Simulation bool   `json:"simulation"`
		Results    []struct {
			Verdict struct {
				Outcome string `json:"outcome"`
				Status  string `json:"finding_status"`
			} `json:"verdict"`
		} `json:"results"`
	}
	for {
		if err := ctx.Err(); err != nil {
			t.Fatal(err)
		}
		raw = call("get_test_run", map[string]any{"run_id": started.RunID})
		if json.Unmarshal(raw, &state) != nil {
			t.Fatal("bad run response")
		}
		if state.Status == "completed" || state.Status == "failed" || state.Status == "timed_out" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if state.Status != "completed" || !state.Simulation || len(state.Results) != 1 || state.Results[0].Verdict.Outcome != "no_violation_observed" {
		t.Fatalf("unexpected synthetic run: %s", raw)
	}
	var manifest struct {
		Artifacts []struct {
			ID   string `json:"artifact_id"`
			Hash string `json:"sha256"`
		} `json:"artifacts"`
	}
	raw = call("get_evidence_manifest", map[string]any{"run_id": started.RunID})
	if json.Unmarshal(raw, &manifest) != nil || len(manifest.Artifacts) != 2 || len(manifest.Artifacts[0].Hash) != 64 {
		t.Fatal("missing evidence manifest")
	}
	call("get_evidence_preview", map[string]any{"run_id": started.RunID, "artifact_id": manifest.Artifacts[0].ID})
	call("verify_candidate", map[string]any{"run_id": started.RunID, "case_id": "T03"})
}
