"use client";

import React, { Suspense, useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { CheckCircle2, KeyRound, Play, Save, Shield, Wrench } from "lucide-react";
import { apiFetch, getApiBase } from "@/lib/api";
import { useResolvedTheme, type ColorSchemePref } from "@/lib/theme";
import type { AgentLLMConfigItem, ReviewPolicyData } from "@/lib/types";

interface ScannerStatusItem {
  available: boolean;
  path: string;
}

function SettingsContent() {
  const searchParams = useSearchParams();
  const { pref, resolved, setPref } = useResolvedTheme();
  const [agents, setAgents] = useState<AgentLLMConfigItem[]>([]);
  const [policy, setPolicy] = useState<ReviewPolicyData | null>(null);
  const [excludedPathsText, setExcludedPathsText] = useState("");
  const [scanners, setScanners] = useState<Record<string, ScannerStatusItem>>({});
  const [drafts, setDrafts] = useState<
    Record<string, { model: string; base_url: string; api_key: string; temperature: string }>
  >({});
  const [bulkKey, setBulkKey] = useState("");
  const [testResults, setTestResults] = useState<
    Record<string, { ok: boolean; message: string; latency_ms: number }>
  >({});
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busyKey, setBusyKey] = useState<string>("");

  const loadAll = useCallback(async () => {
    try {
      const [llmRes, polRes, scanRes] = await Promise.all([
        apiFetch<{ agents: AgentLLMConfigItem[] }>("/api/settings/llm-agents"),
        apiFetch<{ policy: ReviewPolicyData }>("/api/settings/policy"),
        apiFetch<{ scanners: Record<string, ScannerStatusItem> }>("/api/settings/scanners"),
      ]);
      setAgents(llmRes.agents);
      setPolicy(polRes.policy);
      setExcludedPathsText((polRes.policy.excluded_paths || []).join("\n"));
      setScanners(scanRes.scanners);
      const nextDrafts: Record<string, { model: string; base_url: string; api_key: string; temperature: string }> = {};
      for (const a of llmRes.agents) {
        nextDrafts[a.agent_name] = {
          model: a.model,
          base_url: a.base_url,
          api_key: "",
          temperature: a.temperature || "0.1",
        };
      }
      setDrafts(nextDrafts);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed loading settings");
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const consumedOAuthCodeRef = useRef<string>("");

  useEffect(() => {
    const code = searchParams.get("code");
    const oauthFlag = searchParams.get("github_oauth");
    if (oauthFlag === "callback" && code && consumedOAuthCodeRef.current !== code) {
      consumedOAuthCodeRef.current = code;
      if (typeof window !== "undefined") {
        window.history.replaceState({}, "", "/settings");
      }
      void apiFetch<{ username: string }>("/api/github/oauth/exchange", {
        method: "POST",
        body: JSON.stringify({ code }),
      })
        .then((res) => setNotice(`GitHub OAuth connected as @${res.username}`))
        .catch((err) => setError(err instanceof Error ? err.message : "GitHub OAuth failed"));
    }
  }, [searchParams]);

  const saveAgent = async (agentName: string) => {
    const d = drafts[agentName];
    if (!d) return;
    setBusyKey(agentName);
    setError("");
    setNotice("");
    try {
      await apiFetch(`/api/settings/llm-agents/${agentName}`, {
        method: "PUT",
        body: JSON.stringify({
          model: d.model,
          base_url: d.base_url,
          api_key: d.api_key || undefined,
          temperature: d.temperature,
        }),
      });
      setNotice(`Saved configuration for ${agentName}.`);
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed saving agent config");
    } finally {
      setBusyKey("");
    }
  };

  const clearAgentKey = async (agentName: string) => {
    const d = drafts[agentName];
    if (!d) return;
    setBusyKey(`clear:${agentName}`);
    setError("");
    setNotice("");
    try {
      await apiFetch(`/api/settings/llm-agents/${agentName}`, {
        method: "PUT",
        body: JSON.stringify({
          model: d.model,
          base_url: d.base_url,
          clear_api_key: true,
          temperature: d.temperature,
        }),
      });
      setNotice(`Cleared stored API key for ${agentName}.`);
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed clearing API key");
    } finally {
      setBusyKey("");
    }
  };

  const testAgent = async (agentName: string) => {
    setBusyKey(`test:${agentName}`);
    setError("");
    try {
      const d = drafts[agentName];
      if (d && (d.api_key || d.model)) {
        await apiFetch(`/api/settings/llm-agents/${agentName}`, {
          method: "PUT",
          body: JSON.stringify({
            model: d.model,
            base_url: d.base_url,
            api_key: d.api_key || undefined,
            temperature: d.temperature,
          }),
        });
      }
      const res = await apiFetch<{ ok: boolean; message: string; latency_ms: number }>(
        `/api/settings/llm-agents/${agentName}/test`,
        { method: "POST" }
      );
      setTestResults((prev) => ({ ...prev, [agentName]: res }));
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Connection test failed");
    } finally {
      setBusyKey("");
    }
  };

  const applyBulkKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!bulkKey.trim()) return;
    setBusyKey("bulk");
    setError("");
    setNotice("");
    try {
      await apiFetch("/api/settings/llm-agents/bulk-key", {
        method: "POST",
        body: JSON.stringify({ api_key: bulkKey.trim() }),
      });
      setBulkKey("");
      setNotice("Applied DeepSeek API key across all 6 agents.");
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Bulk update failed");
    } finally {
      setBusyKey("");
    }
  };

  const savePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!policy) return;
    setBusyKey("policy");
    setError("");
    setNotice("");
    const parsedExcluded = excludedPathsText
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
    const updatedPolicy: ReviewPolicyData = {
      ...policy,
      excluded_paths: parsedExcluded,
    };
    try {
      await apiFetch("/api/settings/policy", {
        method: "PUT",
        body: JSON.stringify(updatedPolicy),
      });
      setPolicy(updatedPolicy);
      setNotice("Saved review policy rules.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed saving policy");
    } finally {
      setBusyKey("");
    }
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>

        {/* Appearance Preference */}
        <div className="flex items-center gap-1 rounded-lg border border-border bg-card p-1" role="group" aria-label="Appearance preference">
          {(["system", "light", "dark"] as ColorSchemePref[]).map((opt) => (
            <button
              key={opt}
              type="button"
              onClick={() => setPref(opt)}
              aria-pressed={pref === opt}
              className={`rounded-md px-3 py-1.5 font-mono text-[11px] capitalize transition ${
                pref === opt
                  ? "bg-primary font-semibold text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {opt === "system" ? `System (${resolved})` : opt}
            </button>
          ))}
        </div>
      </header>

      {notice && (
        <div
          aria-live="polite"
          role="status"
          className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-700 dark:text-emerald-300"
        >
          {notice}
        </div>
      )}
      {error && (
        <div role="alert" className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-700 dark:text-rose-300">
          {error}
        </div>
      )}

      {/* Shared Key Helper */}
      <form onSubmit={applyBulkKey} className="flex flex-wrap items-end gap-3 rounded-xl border border-border bg-card p-4">
        <div className="min-w-64 flex-1">
          <label htmlFor="bulk-deepseek-key" className="mb-1.5 block font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
            Apply One API Key to All 6 Agents
          </label>
          <input
            id="bulk-deepseek-key"
            type="password"
            autoCorrect="off"
            autoCapitalize="none"
            spellCheck={false}
            placeholder="sk-..."
            value={bulkKey}
            onChange={(e) => setBulkKey(e.target.value)}
            className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 font-mono text-sm"
          />
        </div>
        <button
          type="submit"
          disabled={busyKey === "bulk" || !bulkKey.trim()}
          className="inline-flex min-h-11 items-center gap-1.5 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-50"
        >
          <KeyRound className="h-4 w-4" aria-hidden="true" />
          Apply to All 6 Agents
        </button>
      </form>

      {/* Per-Agent Config Cards */}
      <section className="space-y-4">
        <h2 className="text-base font-semibold">Agent Models &amp; Keys</h2>
        <div className="grid gap-4 lg:grid-cols-2">
          {agents.map((agent) => {
            const d = drafts[agent.agent_name] || {
              model: agent.model,
              base_url: agent.base_url,
              api_key: "",
              temperature: agent.temperature,
            };
            const tr = testResults[agent.agent_name];
            return (
              <div key={agent.agent_name} className="space-y-3 rounded-xl border border-border bg-card p-4">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <h3 className="text-sm font-semibold">{agent.label}</h3>
                      <p className="text-xs text-muted-foreground">{agent.role}</p>
                    </div>
                    <span
                      className={`rounded px-2 py-0.5 font-mono text-[11px] font-semibold ${
                        agent.has_api_key
                          ? "bg-emerald-500/12 text-emerald-700 dark:text-emerald-300"
                          : "bg-amber-500/12 text-amber-800 dark:text-amber-300"
                      }`}
                    >
                      {agent.has_api_key ? `Key (${agent.key_source}: ${agent.masked_api_key})` : "Unconfigured"}
                    </span>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <label htmlFor={`model-${agent.agent_name}`} className="mb-1 block text-xs font-medium">
                        DeepSeek Model ID
                      </label>
                      <input
                        id={`model-${agent.agent_name}`}
                        list="deepseek-models-list"
                        value={d.model}
                        onChange={(e) =>
                          setDrafts((prev) => ({
                            ...prev,
                            [agent.agent_name]: { ...d, model: e.target.value },
                          }))
                        }
                        className="min-h-10 w-full rounded-lg border border-border bg-muted px-3 py-1.5 font-mono text-xs"
                      />
                    </div>
                    <div>
                      <label htmlFor={`base-${agent.agent_name}`} className="mb-1 block text-xs font-medium">
                        API Base URL
                      </label>
                      <input
                        id={`base-${agent.agent_name}`}
                        type="url"
                        autoCorrect="off"
                        autoCapitalize="none"
                        spellCheck={false}
                        value={d.base_url}
                        onChange={(e) =>
                          setDrafts((prev) => ({
                            ...prev,
                            [agent.agent_name]: { ...d, base_url: e.target.value },
                          }))
                        }
                        className="min-h-10 w-full rounded-lg border border-border bg-muted px-3 py-1.5 font-mono text-xs"
                      />
                    </div>
                  </div>

                  <div>
                    <label htmlFor={`key-${agent.agent_name}`} className="mb-1 block text-xs font-medium">
                      Agent API Key {agent.has_api_key ? "(leave blank to keep existing key)" : ""}
                    </label>
                    <input
                      id={`key-${agent.agent_name}`}
                      type="password"
                      autoCorrect="off"
                      autoCapitalize="none"
                      spellCheck={false}
                      placeholder={agent.has_api_key ? agent.masked_api_key : "Enter DeepSeek API key (sk-...)"}
                      value={d.api_key}
                      onChange={(e) =>
                        setDrafts((prev) => ({
                          ...prev,
                          [agent.agent_name]: { ...d, api_key: e.target.value },
                        }))
                      }
                      className="min-h-10 w-full rounded-lg border border-border bg-muted px-3 py-1.5 font-mono text-xs"
                    />
                  </div>

                  {(tr || agent.last_test_status) && (
                    <p
                      className={`font-mono text-[11px] ${
                        tr
                          ? tr.ok
                            ? "text-emerald-700 dark:text-emerald-300"
                            : "text-rose-700 dark:text-rose-300"
                          : "text-muted-foreground"
                      }`}
                    >
                      {tr
                        ? `${tr.ok ? "Connected" : "Failed"} (${tr.latency_ms} ms): ${tr.message}`
                        : `Last test: ${agent.last_test_status}`}
                    </p>
                  )}

                  <div className="flex flex-wrap justify-end gap-2">
                    {agent.key_source === "database" && (
                      <button
                        type="button"
                        disabled={busyKey === `clear:${agent.agent_name}`}
                        onClick={() => clearAgentKey(agent.agent_name)}
                        className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-rose-500/35 px-3 py-1.5 text-xs font-medium text-rose-700 hover:bg-rose-500/10 disabled:opacity-50 dark:text-rose-300"
                      >
                        {busyKey === `clear:${agent.agent_name}` ? "Clearing..." : "Clear Key"}
                      </button>
                    )}
                    <button
                      type="button"
                      disabled={busyKey === `test:${agent.agent_name}`}
                      onClick={() => testAgent(agent.agent_name)}
                      className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-border bg-muted px-3 py-1.5 text-xs font-medium hover:border-foreground/40"
                    >
                      <Play className="h-3.5 w-3.5" aria-hidden="true" />
                      {busyKey === `test:${agent.agent_name}` ? "Testing..." : "Test Connection"}
                    </button>
                    <button
                      type="button"
                      disabled={busyKey === agent.agent_name}
                      onClick={() => saveAgent(agent.agent_name)}
                      className="inline-flex min-h-9 items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-xs font-semibold text-primary-foreground"
                    >
                      <Save className="h-3.5 w-3.5" aria-hidden="true" />
                      Save Agent
                    </button>
                  </div>
                </div>
            );
          })}
        </div>
        <datalist id="deepseek-models-list">
          <option value="deepseek-flash" />
          <option value="deepseek-v4-pro" />
          <option value="deepseek-v4-flash" />
          <option value="deepseek-chat" />
          <option value="deepseek-reasoner" />
        </datalist>
      </section>

      {/* Decision Policy & Deterministic Scanners */}
      <div className="grid gap-6 lg:grid-cols-2">
        {policy && (
          <form onSubmit={savePolicy} className="space-y-4 rounded-xl border border-border bg-card p-5">
            <h2 className="flex items-center gap-2 text-base font-semibold">
              <Shield className="h-4 w-4" aria-hidden="true" />
              Review Policy
            </h2>

              {[
                { key: "block_on_critical", label: "Request Changes on Verified Critical Findings" },
                { key: "block_on_high", label: "Request Changes on Verified High Findings" },
                { key: "require_tests_pass", label: "Request Changes on Mandatory Test Failure" },
                { key: "require_all_mandatory_scans", label: "Mark Incomplete if Any Mandatory Agent/Scan Fails" },
                { key: "enable_test_execution", label: "Run Polyglot Test Suite + Cross-File Mapper" },
                { key: "auto_publish_github_review", label: "Automatically Publish Review & Check Status to GitHub PR" },
              ].map((item) => {
                const checked = Boolean(policy[item.key as keyof ReviewPolicyData]);
                return (
                  <div key={item.key} className="flex items-center gap-3">
                    <input
                      id={`pol-${item.key}`}
                      type="checkbox"
                      checked={checked}
                      onChange={(e) =>
                        setPolicy((prev) => (prev ? { ...prev, [item.key]: e.target.checked } : prev))
                      }
                      className="h-4 w-4"
                    />
                    <label htmlFor={`pol-${item.key}`} className="text-sm">
                      {item.label}
                    </label>
                  </div>
                );
              })}

              <div className="space-y-1.5 pt-2">
                <label htmlFor="pol-excluded-paths" className="block font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                  Excluded Paths (one glob pattern per line)
                </label>
                <textarea
                  id="pol-excluded-paths"
                  rows={4}
                  spellCheck={false}
                  value={excludedPathsText}
                  onChange={(e) => setExcludedPathsText(e.target.value)}
                  className="w-full rounded-lg border border-border bg-muted px-3 py-2 font-mono text-xs"
                />
              </div>

              <button
                type="submit"
                disabled={busyKey === "policy"}
                className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground"
              >
                Save Policy
              </button>
          </form>
        )}

        <section className="space-y-4 rounded-xl border border-border bg-card p-5">
          <h2 className="flex items-center gap-2 text-base font-semibold">
            <Wrench className="h-4 w-4" aria-hidden="true" />
            Scanners &amp; Webhook
          </h2>

            <ul className="grid gap-2 sm:grid-cols-2">
              {Object.entries(scanners).map(([name, info]) => (
                <li
                  key={name}
                  className="flex items-center justify-between rounded-lg border border-border bg-muted/60 px-3 py-2 text-xs"
                >
                  <span className="font-mono font-semibold">{name}</span>
                  <span
                    className={
                      info.available
                        ? "flex items-center gap-1 font-mono text-emerald-700 dark:text-emerald-300"
                        : "font-mono text-rose-700 dark:text-rose-300"
                    }
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                    {info.available ? "Ready" : "Missing"}
                  </span>
                </li>
              ))}
            </ul>

            <div className="rounded-lg border border-border bg-muted/60 p-3 text-xs">
              <p className="font-semibold">GitHub Seamless Sync &amp; Webhook Tunnel</p>
              <p className="mt-1 font-mono text-foreground">{getApiBase()}/api/github/webhook</p>
              <ul className="mt-2 list-inside list-disc space-y-1 text-muted-foreground">
                <li>
                  <strong className="text-foreground">Auto-sync:</strong> Background PR Sync Watcher checks synced GitHub repos every 90s automatically.
                </li>
                <li>
                  <strong className="text-foreground">Real-time webhooks:</strong> Run <code>cloudflared tunnel --url http://127.0.0.1:8000</code> and register under Repositories.
                </li>
              </ul>
            </div>
        </section>
      </div>
    </div>
  );
}

export default function SettingsPage() {
  return (
    <Suspense fallback={<div className="p-4 font-mono text-xs text-muted-foreground">Loading Settings...</div>}>
      <SettingsContent />
    </Suspense>
  );
}
