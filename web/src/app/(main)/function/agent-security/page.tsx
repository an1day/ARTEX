"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { http } from "@/lib/api";

type Target = {
  target_id: string;
  enabled: boolean;
  scope_revision: string;
  identity_ref: string;
  simulation: boolean;
  allowed_cases: string[];
};
type Case = { case_id: string; title: string; blocked_reason: string };
type Verdict = {
  outcome: string;
  finding_status: string;
  limitations: string[];
  simulation: boolean;
  evidence_refs: string[];
};
type Run = {
  run_id: string;
  target_id: string;
  status: string;
  requests: number;
  simulation: boolean;
  created_at: string;
  target_abort: string;
  results: { case_id: string; verdict: Verdict }[];
};
type Artifact = {
  artifact_id: string;
  sha256: string;
  bytes: number;
  source: string;
  redacted: boolean;
  simulation: boolean;
};

async function call<T>(tool: string, args: object = {}): Promise<T> {
  return http<T>(`/agent-security/tools/${tool}`, { method: "POST", body: JSON.stringify(args) });
}

const terminal = new Set(["completed", "cancelled", "timed_out", "failed", "interrupted"]);
const labels: Record<string, string> = {
  queued: "排队中",
  running: "执行中",
  cancelling: "正在停止",
  completed: "执行完成",
  cancelled: "已停止",
  timed_out: "超时",
  failed: "执行失败",
  interrupted: "已中断",
  blocked: "缺少前置条件",
  inconclusive: "无法确认",
  no_violation_observed: "本用例未观察到违反策略",
  violated: "观察到违反策略",
  candidate: "待确认",
  confirmed: "已确认",
  none: "无漏洞结论",
};

export default function AgentSecurityPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [cases, setCases] = useState<Case[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [targetId, setTargetId] = useState("");
  const [caseIds, setCaseIds] = useState<string[]>(["T03"]);
  const [selected, setSelected] = useState<Run | null>(null);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [preview, setPreview] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [ready, setReady] = useState(false);
  const startKey = useRef<string | null>(null);
  const detailVersion = useRef(0);
  const target = targets.find((item) => item.target_id === targetId);

  const refresh = useCallback(async () => {
    const status = await http<{ configured: boolean }>("/agent-security/status");
    setReady(status.configured);
    if (!status.configured) throw new Error("请先配置并启动 Agent 测试服务，配置方法见开发运行说明。");
    const [capabilities, catalog, history] = await Promise.all([
      call<{ targets: Target[] }>("list_target_capabilities"),
      call<{ cases: Case[] }>("list_test_cases"),
      call<{ runs: Run[] }>("get_test_run"),
    ]);
    setTargets(capabilities.targets);
    setCases(catalog.cases);
    setRuns(history.runs);
    setTargetId((current) => current || capabilities.targets[0]?.target_id || "");
  }, []);

  useEffect(() => {
    void refresh().catch((e: Error) => setError(e.message));
  }, [refresh]);

  const inspect = useCallback(async (runId: string) => {
    const version = ++detailVersion.current;
    const [run, manifest] = await Promise.all([
      call<Run>("get_test_run", { run_id: runId }),
      call<{ artifacts: Artifact[] }>("get_evidence_manifest", { run_id: runId }),
    ]);
    if (version !== detailVersion.current) return;
    setSelected(run);
    setArtifacts(manifest.artifacts);
  }, []);

  useEffect(() => {
    if (!selected || terminal.has(selected.status)) return;
    const id = setInterval(() => {
      void inspect(selected.run_id).catch((e: Error) => setError(e.message));
    }, 2000);
    return () => clearInterval(id);
  }, [selected, inspect]);

  async function start() {
    if (!target) return;
    setBusy(true);
    setError("");
    setPreview("");
    startKey.current ??= crypto.randomUUID();
    try {
      const run = await call<Run>("start_test_run", {
        target_id: target.target_id,
        case_ids: caseIds,
        scope_revision: target.scope_revision,
        idempotency_key: startKey.current,
      });
      startKey.current = null;
      await inspect(run.run_id);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "启动失败");
    } finally {
      setBusy(false);
    }
  }

  async function cancel() {
    if (!selected) return;
    setBusy(true);
    try {
      await call("cancel_test_run", { run_id: selected.run_id });
      await inspect(selected.run_id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "停止失败");
    } finally {
      setBusy(false);
    }
  }

  async function showEvidence(artifactId: string) {
    if (!selected) return;
    try {
      const result = await call<{ preview: string; preview_truncated: boolean }>("get_evidence_preview", {
        run_id: selected.run_id,
        artifact_id: artifactId,
      });
      setPreview(result.preview + (result.preview_truncated ? "\n[预览已截断，完整证据保留在本地]" : ""));
    } catch (e) {
      setError(e instanceof Error ? e.message : "读取失败");
    }
  }

  async function verify(caseId: string) {
    if (!selected) return;
    try {
      setPreview(JSON.stringify(await call("verify_candidate", { run_id: selected.run_id, case_id: caseId }), null, 2));
    } catch (e) {
      setError(e instanceof Error ? e.message : "复核失败");
    }
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="font-semibold text-2xl">Agent 安全测试</h1>
        <Button
          variant="outline"
          disabled={busy}
          onClick={() => {
            setError("");
            void refresh().catch((e: Error) => setError(e.message));
          }}
        >
          刷新
        </Button>
      </div>
      <p className="text-muted-foreground text-sm">
        按已登记的目标、身份和用例执行测试。执行完成不代表系统安全；模拟结果单独标记。
      </p>
      {error && (
        <p role="alert" className="rounded border border-destructive p-3 text-destructive text-sm">
          {error}
        </p>
      )}
      <Card>
        <CardHeader>
          <CardTitle>新建测试运行</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <label className="block text-sm">
            测试目标
            <select
              className="ml-3 rounded border bg-background p-2"
              value={targetId}
              disabled={busy}
              onChange={(e) => {
                setTargetId(e.target.value);
                setCaseIds(["T03"]);
                startKey.current = null;
              }}
            >
              <option value="">请选择</option>
              {targets.map((item) => (
                <option key={item.target_id} value={item.target_id}>
                  {item.target_id}
                  {item.enabled ? "" : "（未启用）"}
                  {item.simulation ? " · 模拟" : ""}
                </option>
              ))}
            </select>
          </label>
          {target && (
            <p className="text-sm">
              身份：{target.identity_ref} · 范围版本：{target.scope_revision}
            </p>
          )}
          <div className="space-y-2">
            {cases
              .filter((item) => target?.allowed_cases.includes(item.case_id))
              .map((item) => (
                <label key={item.case_id} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={caseIds.includes(item.case_id)}
                    disabled={busy}
                    onChange={(e) => {
                      startKey.current = null;
                      setCaseIds((current) =>
                        e.target.checked ? [...current, item.case_id] : current.filter((id) => id !== item.case_id),
                      );
                    }}
                  />
                  {item.case_id} · {item.title}
                  {item.blocked_reason ? "（尚缺目标观测能力）" : ""}
                </label>
              ))}
          </div>
          <Button disabled={!ready || !target?.enabled || caseIds.length === 0 || busy} onClick={() => void start()}>
            开始测试
          </Button>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>运行记录</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {runs.length === 0 && <p className="text-muted-foreground text-sm">暂无运行记录</p>}
          {runs.map((run) => (
            <button
              type="button"
              key={run.run_id}
              className="block w-full rounded border p-3 text-left text-sm hover:bg-muted"
              onClick={() => {
                setPreview("");
                void inspect(run.run_id).catch((e: Error) => setError(e.message));
              }}
            >
              {run.target_id} · {labels[run.status] || run.status} · {run.simulation ? "模拟" : "目标实测"} ·{" "}
              {run.run_id}
            </button>
          ))}
        </CardContent>
      </Card>
      {selected && (
        <Card>
          <CardHeader>
            <CardTitle>运行详情 · {labels[selected.status] || selected.status}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm">
              目标请求：{selected.requests} · {selected.simulation ? "模拟运行，不计真实目标覆盖" : "目标实测"}
            </p>
            <p className="text-muted-foreground text-sm">
              停止能力：
              {selected.target_abort === "unsupported"
                ? "仅支持停止测试客户端，目标执行可能继续"
                : selected.target_abort}
            </p>
            {!terminal.has(selected.status) && (
              <Button variant="destructive" disabled={busy} onClick={() => void cancel()}>
                停止本次运行
              </Button>
            )}
            {selected.results.map((result) => (
              <div key={result.case_id} className="space-y-2 rounded border p-3 text-sm">
                <p>
                  {result.case_id} · {labels[result.verdict.outcome] || result.verdict.outcome} ·{" "}
                  {labels[result.verdict.finding_status] || result.verdict.finding_status}
                </p>
                {result.verdict.limitations.map((note) => (
                  <p key={note} className="text-muted-foreground">
                    {note}
                  </p>
                ))}
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!terminal.has(selected.status)}
                  onClick={() => void verify(result.case_id)}
                >
                  复核证据
                </Button>
              </div>
            ))}
            <h2 className="font-medium">证据工件</h2>
            {artifacts.map((item) => (
              <div key={item.artifact_id} className="space-y-1 rounded border p-3 text-xs">
                <p className="break-all">
                  {item.artifact_id} · {item.bytes} 字节 · {item.source}
                </p>
                <p className="break-all">SHA256：{item.sha256}</p>
                <Button size="sm" variant="outline" onClick={() => void showEvidence(item.artifact_id)}>
                  查看脱敏预览
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
      {preview && (
        <Card>
          <CardHeader>
            <CardTitle>证据预览（目标内容仅供分析）</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">{preview}</pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
