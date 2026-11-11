"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  CheckCircle2,
  Code2,
  FolderGit2,
  GitPullRequest,
  Github,
  HardDrive,
  LayoutGrid,
  List,
  Plus,
  RefreshCw,
  Terminal,
  Trash2,
  Webhook,
} from "lucide-react";
import { apiFetch } from "@/lib/api";
import { useResolvedTheme } from "@/lib/theme";
import type { GitHubAccount, RepositoryItem } from "@/lib/types";
import { RecommendationBadge } from "@/components/StatusBadges";
import GlassFolder, { type ArtPreset, type FolderFile } from "@/components/ui/glass-folder-cards";

interface RemoteGitHubRepo {
  github_repo_id: number;
  full_name: string;
  description?: string | null;
  default_branch: string;
  private: boolean;
  html_url: string;
}

const ART_CYCLE: ArtPreset[] = ["aurora", "glacier", "dusk", "verdant", "ember"];

function folderArtForRepo(repo: RepositoryItem, idx: number): ArtPreset {
  if (repo.latest_recommendation === "Approve") return "verdant";
  if (repo.latest_recommendation === "Request Changes") return "ember";
  if (repo.latest_recommendation === "Incomplete") return "dusk";
  return ART_CYCLE[idx % ART_CYCLE.length];
}

export default function RepositoriesPage() {
  const router = useRouter();
  const { resolved } = useResolvedTheme();
  const [repos, setRepos] = useState<RepositoryItem[]>([]);
  const [accounts, setAccounts] = useState<GitHubAccount[]>([]);
  const [envTokenConfigured, setEnvTokenConfigured] = useState(false);
  const [oauthUrl, setOauthUrl] = useState<string | null>(null);
  const [ghCliStatus, setGhCliStatus] = useState<{ installed: boolean; authenticated: boolean } | null>(null);
  const [remoteRepos, setRemoteRepos] = useState<RemoteGitHubRepo[]>([]);
  const [companionOnline, setCompanionOnline] = useState<boolean | null>(null);
  const [viewMode, setViewMode] = useState<"folders" | "table">("folders");
  const [loading, setLoading] = useState(true);
  const [statusMsg, setStatusMsg] = useState("");
  const [errorMsg, setErrorMsg] = useState("");

  const patDialogRef = useRef<HTMLDialogElement>(null);
  const localDialogRef = useRef<HTMLDialogElement>(null);
  const githubBrowserDialogRef = useRef<HTMLDialogElement>(null);
  const webhookDialogRef = useRef<HTMLDialogElement>(null);

  const [patInput, setPatInput] = useState("");
  const [manualRepoFullName, setManualRepoFullName] = useState("");
  const [localPathInput, setLocalPathInput] = useState("");
  const [localNameInput, setLocalNameInput] = useState("");
  const [webhookRepo, setWebhookRepo] = useState<RepositoryItem | null>(null);
  const [webhookUrlInput, setWebhookUrlInput] = useState("");
  const [busy, setBusy] = useState(false);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [repoRes, acctRes, compRes, ghCliRes, oauthRes] = await Promise.all([
        apiFetch<{ repositories: RepositoryItem[] }>("/api/repositories"),
        apiFetch<{ accounts: GitHubAccount[]; env_token_configured: boolean }>("/api/github/accounts"),
        apiFetch<{ online: boolean }>("/api/repositories/companion/status"),
        apiFetch<{ installed: boolean; authenticated: boolean }>("/api/github/gh-cli/status"),
        apiFetch<{ configured: boolean; url: string | null }>("/api/github/oauth/url"),
      ]);
      setRepos(repoRes.repositories);
      setAccounts(acctRes.accounts);
      setEnvTokenConfigured(acctRes.env_token_configured);
      setCompanionOnline(compRes.online);
      setGhCliStatus(ghCliRes);
      setOauthUrl(oauthRes.configured ? oauthRes.url : null);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed loading repositories");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const handleConnectPat = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErrorMsg("");
    try {
      await apiFetch("/api/github/connect/pat", {
        method: "POST",
        body: JSON.stringify({ token: patInput }),
      });
      setPatInput("");
      patDialogRef.current?.close();
      setStatusMsg("GitHub account verified and connected.");
      await loadAll();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed connecting GitHub PAT");
    } finally {
      setBusy(false);
    }
  };

  const handleConnectGhCli = async () => {
    setBusy(true);
    setErrorMsg("");
    setStatusMsg("");
    try {
      const res = await apiFetch<{ account: GitHubAccount }>("/api/github/connect/gh-cli", {
        method: "POST",
      });
      setStatusMsg(`Connected GitHub CLI account @${res.account.username} cleanly.`);
      await loadAll();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed connecting via GitHub CLI");
    } finally {
      setBusy(false);
    }
  };

  const handleBrowseRemoteRepos = async () => {
    setBusy(true);
    setErrorMsg("");
    try {
      const res = await apiFetch<{ repositories: RemoteGitHubRepo[] }>("/api/github/remote-repos");
      setRemoteRepos(res.repositories);
      githubBrowserDialogRef.current?.showModal();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed fetching GitHub repositories");
    } finally {
      setBusy(false);
    }
  };

  const handleSyncGitHubRepo = async (fullNameOrUrl: string) => {
    setBusy(true);
    setErrorMsg("");
    setStatusMsg("");
    try {
      const res = await apiFetch<{
        repository: { id: string; full_name: string };
        detected_pr_number?: number | null;
        detected_commit_sha?: string | null;
      }>("/api/github/sync-repo", {
        method: "POST",
        body: JSON.stringify({ full_name: fullNameOrUrl, auto_review_webhooks: true }),
      });
      setManualRepoFullName("");
      githubBrowserDialogRef.current?.close();
      await loadAll();
      if (res.detected_pr_number) {
        router.push(`/reviews/submit?repo=${res.repository.id}&pr=${res.detected_pr_number}`);
        return;
      }
      if (res.detected_commit_sha) {
        router.push(`/reviews/submit?repo=${res.repository.id}&commit=${res.detected_commit_sha}`);
        return;
      }
      setStatusMsg(`Synced GitHub repository ${res.repository.full_name}.`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed syncing GitHub repository");
    } finally {
      setBusy(false);
    }
  };

  const handleSyncOpenPRs = async (repo: RepositoryItem) => {
    setBusy(true);
    setErrorMsg("");
    setStatusMsg("");
    try {
      const res = await apiFetch<{
        open_prs: number;
        triggered_reviews: string[];
        already_reviewed: number;
      }>(`/api/github/repos/${repo.id}/sync-prs?auto_review=true`, { method: "POST" });
      setStatusMsg(
        `Synced ${repo.full_name}: ${res.open_prs} open PR(s), ${res.triggered_reviews.length} new review(s) launched, ${res.already_reviewed} already up to date.`
      );
      await loadAll();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed syncing open PRs");
    } finally {
      setBusy(false);
    }
  };

  const handleRegisterWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!webhookRepo) return;
    setBusy(true);
    setErrorMsg("");
    try {
      await apiFetch(`/api/github/repos/${webhookRepo.id}/register-webhook`, {
        method: "POST",
        body: JSON.stringify({ webhook_url: webhookUrlInput }),
      });
      webhookDialogRef.current?.close();
      setWebhookUrlInput("");
      setStatusMsg(`Webhook registered on GitHub for ${webhookRepo.full_name}.`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Webhook registration failed");
    } finally {
      setBusy(false);
    }
  };

  const handleConnectLocal = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErrorMsg("");
    try {
      const res = await apiFetch<{
        repository: { full_name: string };
        detected_github_repo?: string | null;
      }>("/api/repositories/local", {
        method: "POST",
        body: JSON.stringify({
          local_path: localPathInput,
          name: localNameInput || undefined,
        }),
      });
      setLocalPathInput("");
      setLocalNameInput("");
      localDialogRef.current?.close();
      setStatusMsg(
        res.detected_github_repo
          ? `Connected local repository (${res.repository.full_name}). Detected GitHub origin: ${res.detected_github_repo}.`
          : "Local Git repository connected."
      );
      await loadAll();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed connecting local repository");
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteRepo = async (id: string, name: string) => {
    setErrorMsg("");
    try {
      await apiFetch(`/api/repositories/${id}`, { method: "DELETE" });
      setStatusMsg(`Removed ${name}.`);
      await loadAll();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Delete failed");
    }
  };

  const handleDisconnectAccount = async (account: GitHubAccount) => {
    setBusy(true);
    setErrorMsg("");
    setStatusMsg("");
    try {
      await apiFetch(`/api/github/accounts/${account.id}`, { method: "DELETE" });
      setStatusMsg(`Disconnected GitHub account @${account.username}.`);
      await loadAll();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed disconnecting GitHub account");
    } finally {
      setBusy(false);
    }
  };

  const handleToggleAutoSync = async (repo: RepositoryItem) => {
    setBusy(true);
    setErrorMsg("");
    setStatusMsg("");
    try {
      const next = !repo.auto_review_webhooks;
      await apiFetch(`/api/repositories/${repo.id}`, {
        method: "PATCH",
        body: JSON.stringify({ auto_review_webhooks: next }),
      });
      setStatusMsg(
        `Background PR auto-sync ${next ? "enabled" : "paused"} for ${repo.full_name}.`
      );
      await loadAll();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed updating repository auto-sync");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <h1 className="text-2xl font-semibold tracking-tight">Repositories</h1>

        <div className="flex flex-wrap gap-2">
          {ghCliStatus?.installed && (
            <button
              type="button"
              onClick={handleConnectGhCli}
              disabled={busy}
              className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/12 px-3.5 py-2 text-xs font-semibold text-emerald-700 hover:bg-emerald-500/20 disabled:opacity-60 dark:text-emerald-300"
            >
              <Terminal className="h-4 w-4" aria-hidden="true" />
              Connect GitHub CLI
            </button>
          )}
          <button
            type="button"
            onClick={() => patDialogRef.current?.showModal()}
            className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-border bg-card px-3.5 py-2 text-xs font-medium hover:border-foreground/40"
          >
            <Github className="h-4 w-4" aria-hidden="true" />
            Connect Token
          </button>
          {oauthUrl && (
            <a
              href={oauthUrl}
              className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-border bg-card px-3.5 py-2 text-xs font-medium hover:border-foreground/40"
            >
              <Github className="h-4 w-4" aria-hidden="true" />
              Connect GitHub OAuth
            </a>
          )}
          <button
            type="button"
            onClick={handleBrowseRemoteRepos}
            disabled={busy}
            className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60"
          >
            <RefreshCw className="h-4 w-4" aria-hidden="true" />
            Import from GitHub
          </button>
          <button
            type="button"
            onClick={() => localDialogRef.current?.showModal()}
            className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-border bg-card px-3.5 py-2 text-xs font-medium hover:border-foreground/40"
          >
            <HardDrive className="h-4 w-4" aria-hidden="true" />
            Add Local Repo
          </button>
        </div>
      </header>

      {statusMsg && (
        <div
          aria-live="polite"
          role="status"
          className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-700 dark:text-emerald-300"
        >
          {statusMsg}
        </div>
      )}
      {errorMsg && (
        <div role="alert" className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-700 dark:text-rose-300">
          {errorMsg}
        </div>
      )}

      {/* Sync Channels + Quick URL Bar */}
      <div className="grid gap-4 md:grid-cols-2">
        <section className="rounded-xl border border-border bg-card p-4">
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <Github className="h-4 w-4" aria-hidden="true" />
            GitHub Connection
          </h2>
          {accounts.length > 0 ? (
            <ul className="mt-3 space-y-2">
              {accounts.map((a) => (
                <li key={a.id} className="flex flex-wrap items-center justify-between gap-2 font-mono text-xs">
                  <span className="flex items-center gap-2 font-medium">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                    @{a.username} ({a.auth_mode.toUpperCase()})
                  </span>
                  <div className="flex items-center gap-3">
                    <span className="text-muted-foreground">{a.scopes || "repo"}</span>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void handleDisconnectAccount(a)}
                      className="text-[11px] font-medium text-rose-600 hover:underline disabled:opacity-50 dark:text-rose-400"
                    >
                      Disconnect
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          ) : envTokenConfigured ? (
            <p className="mt-2 font-mono text-xs text-emerald-700 dark:text-emerald-300">
              Using GITHUB_TOKEN from environment
            </p>
          ) : (
            <p className="mt-2 text-xs text-muted-foreground">
              Public repos sync via URL below. Add GitHub CLI or a token for private repos and PR comments.
            </p>
          )}
        </section>

        <section className="rounded-xl border border-border bg-card p-4">
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <HardDrive className="h-4 w-4" aria-hidden="true" />
            Local Companion (127.0.0.1:8765)
          </h2>
          <p className="mt-2 text-xs text-muted-foreground">
            Status:{" "}
            <strong className={companionOnline ? "text-emerald-600 dark:text-emerald-400" : "text-foreground"}>
              {companionOnline === null
                ? "Checking..."
                : companionOnline
                ? "Online"
                : "Offline"}
            </strong>
          </p>
          <p className="mt-1 font-mono text-[11px] text-muted-foreground">
            backend/.venv/bin/python local-companion/cli.py serve
          </p>
        </section>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (manualRepoFullName.trim()) void handleSyncGitHubRepo(manualRepoFullName.trim());
        }}
        className="flex flex-wrap items-end gap-3 rounded-xl border border-border bg-card p-4"
      >
        <div className="min-w-64 flex-1">
          <label htmlFor="manual-gh-repo" className="mb-1.5 block font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
            Sync GitHub Repository (URL, PR, Commit, or owner/repo)
          </label>
          <input
            id="manual-gh-repo"
            name="full_name"
            type="text"
            placeholder="https://github.com/owner/repo  or  owner/repo"
            autoCorrect="off"
            autoCapitalize="none"
            spellCheck={false}
            value={manualRepoFullName}
            onChange={(e) => setManualRepoFullName(e.target.value)}
            className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 font-mono text-xs"
          />
        </div>
        <button
          type="submit"
          disabled={busy || !manualRepoFullName.trim()}
          className="inline-flex min-h-11 items-center gap-1.5 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-50"
        >
          <Plus className="h-4 w-4" aria-hidden="true" />
          Sync Repository
        </button>
      </form>

      {/* Repository Glass Folder Deck OR Responsive Table */}
      <section className="rounded-xl border border-border bg-card p-5">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-base font-semibold">Connected Repositories ({repos.length})</h2>
            <div className="inline-flex rounded-lg border border-border bg-muted p-0.5">
              <button
                type="button"
                onClick={() => setViewMode("folders")}
                className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 font-mono text-[11px] font-medium transition ${
                  viewMode === "folders"
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                <LayoutGrid className="h-3.5 w-3.5" aria-hidden="true" />
                Glass Folders
              </button>
              <button
                type="button"
                onClick={() => setViewMode("table")}
                className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 font-mono text-[11px] font-medium transition ${
                  viewMode === "table"
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                <List className="h-3.5 w-3.5" aria-hidden="true" />
                Table
              </button>
            </div>
          </div>

          {loading ? (
            <p className="text-sm text-muted-foreground">Loading connected repositories...</p>
          ) : repos.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border p-10 text-center">
              <FolderGit2 className="mx-auto mb-2 h-6 w-6 text-muted-foreground" aria-hidden="true" />
              <p className="text-sm font-medium">No repositories connected</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Paste a GitHub URL above, import from GitHub, or register a local Git repository.
              </p>
            </div>
          ) : viewMode === "folders" ? (
            <div className="rb-dotted-desk relative rounded-xl border border-border bg-muted/40 px-4 py-10">
              <div className="grid grid-cols-1 items-end justify-items-center gap-x-10 gap-y-12 md:grid-cols-2 xl:grid-cols-3">
                {repos.map((repo, idx) => {
                  const preset = folderArtForRepo(repo, idx);
                  const folderFiles: FolderFile[] = [
                    {
                      name: "Browse Full Codebase",
                      meta: `${repo.source_type.toUpperCase()} · ${repo.default_branch}`,
                      art: preset,
                      href: `/repositories/${repo.id}`,
                    },
                    {
                      name: "Submit PR / Commit Review",
                      meta: `${repo.review_count} total runs`,
                      href: `/reviews/submit?repo=${repo.id}`,
                    },
                    ...(repo.latest_review_id
                      ? [
                          {
                            name: `Latest: ${repo.latest_recommendation || "Completed"}`,
                            meta: "Inspect Review Report",
                            art: ART_CYCLE[(idx + 2) % ART_CYCLE.length],
                            href: `/reviews/${repo.latest_review_id}`,
                          },
                        ]
                      : []),
                  ];
                  const menuItems = [
                    {
                      label: "Open Codebase Explorer",
                      onSelect: () => router.push(`/repositories/${repo.id}`),
                    },
                    {
                      label: "Submit PR / Commit Review",
                      onSelect: () => router.push(`/reviews/submit?repo=${repo.id}`),
                    },
                    ...(repo.source_type === "github"
                      ? [
                          {
                            label: "Sync Open PRs",
                            onSelect: () => void handleSyncOpenPRs(repo),
                          },
                          {
                            label: repo.auto_review_webhooks ? "Pause Auto-Sync PRs" : "Enable Auto-Sync PRs",
                            onSelect: () => void handleToggleAutoSync(repo),
                          },
                          {
                            label: "Configure Webhook…",
                            onSelect: () => {
                              setWebhookRepo(repo);
                              webhookDialogRef.current?.showModal();
                            },
                          },
                        ]
                      : []),
                    {
                      label: "Remove Repository",
                      danger: true,
                      onSelect: () => void handleDeleteRepo(repo.id, repo.full_name),
                    },
                  ];

                  return (
                    <div key={repo.id} className="flex flex-col items-center gap-3">
                      <GlassFolder
                        label={repo.name}
                        meta={`${repo.default_branch} · ${repo.review_count} review${repo.review_count === 1 ? "" : "s"}`}
                        tone={resolved}
                        art={preset}
                        seed={idx * 7 + 3}
                        action="more"
                        width={310}
                        appearDelay={Math.min(idx * 90, 360)}
                        files={folderFiles}
                        menu={menuItems}
                      />
                      <div className="flex flex-wrap items-center justify-center gap-2 text-xs">
                        <span className="font-mono text-[11px] text-muted-foreground">{repo.full_name}</span>
                        {repo.latest_recommendation && (
                          <RecommendationBadge recommendation={repo.latest_recommendation} />
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            <div tabIndex={0} role="region" aria-labelledby="repos-table-cap" className="table-wrapper">
              <table className="rb-table rb-table--responsive text-left text-sm">
                <caption id="repos-table-cap" className="visually-hidden">
                  Connected GitHub and local repositories
                </caption>
                <thead>
                  <tr className="border-b border-border font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                    <th scope="col" className="px-3 py-2">Repository</th>
                    <th scope="col" className="px-3 py-2">Source</th>
                    <th scope="col" className="px-3 py-2">Branch</th>
                    <th scope="col" className="px-3 py-2">Reviews</th>
                    <th scope="col" className="px-3 py-2">Latest Decision</th>
                    <th scope="col" className="px-3 py-2">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {repos.map((repo) => (
                    <tr key={repo.id} className="border-b border-border last:border-b-0">
                      <th scope="row" className="px-3 py-3 font-medium">
                        <Link href={`/repositories/${repo.id}`} className="font-semibold hover:underline">
                          {repo.full_name}
                        </Link>
                        <div className="font-mono text-[11px] font-normal text-muted-foreground">
                          {repo.source_type === "local" ? repo.local_path : repo.html_url}
                        </div>
                      </th>
                      <td data-label="Source" className="px-3 py-3 font-mono text-xs uppercase">
                        {repo.source_type}
                      </td>
                      <td data-label="Branch" className="px-3 py-3 font-mono text-xs">
                        {repo.default_branch}
                      </td>
                      <td data-label="Reviews" className="px-3 py-3 font-mono text-xs">
                        {repo.review_count}
                      </td>
                      <td data-label="Latest Decision" className="px-3 py-3">
                        {repo.latest_recommendation ? (
                          <RecommendationBadge recommendation={repo.latest_recommendation} />
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>
                      <td data-label="Actions" className="px-3 py-3">
                        <div className="flex flex-wrap items-center gap-3">
                          <Link
                            href={`/repositories/${repo.id}`}
                            className="inline-flex items-center gap-1 text-xs font-semibold hover:underline"
                          >
                            <Code2 className="h-3.5 w-3.5" aria-hidden="true" />
                            Browse Files
                          </Link>
                          <Link
                            href={`/reviews/submit?repo=${repo.id}`}
                            className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground hover:underline"
                          >
                            <GitPullRequest className="h-3.5 w-3.5" aria-hidden="true" />
                            Review
                          </Link>
                          {repo.source_type === "github" && (
                            <>
                              <button
                                type="button"
                                disabled={busy}
                                onClick={() => handleSyncOpenPRs(repo)}
                                className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700 hover:underline dark:text-emerald-300"
                              >
                                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                                Sync PRs
                              </button>
                              <button
                                type="button"
                                disabled={busy}
                                onClick={() => handleToggleAutoSync(repo)}
                                className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground hover:underline"
                              >
                                Auto-Sync: {repo.auto_review_webhooks ? "On" : "Off"}
                              </button>
                              <button
                                type="button"
                                onClick={() => {
                                  setWebhookRepo(repo);
                                  webhookDialogRef.current?.showModal();
                                }}
                                className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground hover:underline"
                              >
                                <Webhook className="h-3.5 w-3.5" aria-hidden="true" />
                                Webhook
                              </button>
                            </>
                          )}
                          <button
                            type="button"
                            onClick={() => handleDeleteRepo(repo.id, repo.full_name)}
                            aria-label={`Remove ${repo.full_name}`}
                            className="text-xs text-rose-600 hover:underline dark:text-rose-400"
                          >
                            <Trash2 className="h-4 w-4" aria-hidden="true" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

      {/* Dialog: Connect GitHub PAT */}
      <dialog ref={patDialogRef} aria-labelledby="pat-dialog-title">
        <h2 id="pat-dialog-title" className="text-lg font-semibold">
          Connect GitHub Personal Access Token
        </h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Token is verified live against GitHub API and encrypted at rest using Fernet.
        </p>
        <form onSubmit={handleConnectPat} className="mt-4 space-y-4">
          <div>
            <label htmlFor="gh-pat-input" className="mb-1 block text-xs font-semibold">
              GitHub Token (`repo` / Pull requests + Contents)
            </label>
            <input
              id="gh-pat-input"
              name="token"
              type="password"
              required
              autoFocus
              autoCorrect="off"
              autoCapitalize="none"
              spellCheck={false}
              value={patInput}
              onChange={(e) => setPatInput(e.target.value)}
              className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 font-mono text-sm"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => patDialogRef.current?.close()}
              className="min-h-10 rounded-lg border border-border px-4 py-2 text-xs font-medium"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className="min-h-10 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground"
            >
              {busy ? "Verifying..." : "Verify & Save"}
            </button>
          </div>
        </form>
      </dialog>

      {/* Dialog: Connect Local Git Repo */}
      <dialog ref={localDialogRef} aria-labelledby="local-dialog-title">
        <h2 id="local-dialog-title" className="text-lg font-semibold">
          Connect Local Git Repository
        </h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Enter the absolute path to any Git repository on disk.
        </p>
        <form onSubmit={handleConnectLocal} className="mt-4 space-y-4">
          <div>
            <label htmlFor="local-path-input" className="mb-1 block text-xs font-semibold">
              Repository Directory Path
            </label>
            <input
              id="local-path-input"
              name="local_path"
              type="text"
              required
              autoFocus
              autoCorrect="off"
              autoCapitalize="none"
              spellCheck={false}
              placeholder="/Users/you/projects/my-repo"
              value={localPathInput}
              onChange={(e) => setLocalPathInput(e.target.value)}
              className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 font-mono text-xs"
            />
          </div>
          <div>
            <label htmlFor="local-name-input" className="mb-1 block text-xs font-semibold">
              Display Name (optional)
            </label>
            <input
              id="local-name-input"
              name="name"
              type="text"
              value={localNameInput}
              onChange={(e) => setLocalNameInput(e.target.value)}
              className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 text-xs"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => localDialogRef.current?.close()}
              className="min-h-10 rounded-lg border border-border px-4 py-2 text-xs font-medium"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className="min-h-10 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground"
            >
              {busy ? "Connecting..." : "Connect Repository"}
            </button>
          </div>
        </form>
      </dialog>

      {/* Dialog: Import GitHub Repo */}
      <dialog ref={githubBrowserDialogRef} aria-labelledby="gh-browser-title">
        <div className="flex items-center justify-between">
          <h2 id="gh-browser-title" className="text-lg font-semibold">
            Import GitHub Repository
          </h2>
          <button
            type="button"
            onClick={() => githubBrowserDialogRef.current?.close()}
            className="rounded-lg border border-border px-3 py-1 text-xs"
          >
            Close
          </button>
        </div>
        <div className="rb-scroll mt-4 max-h-96 space-y-2">
          {remoteRepos.map((rr) => (
            <div
              key={rr.github_repo_id}
              className="flex items-center justify-between rounded-lg border border-border bg-muted p-3"
            >
              <div className="min-w-0 pr-3">
                <p className="truncate text-sm font-semibold">{rr.full_name}</p>
                <p className="truncate font-mono text-[11px] text-muted-foreground">
                  {rr.description || rr.default_branch} · {rr.private ? "Private" : "Public"}
                </p>
              </div>
              <button
                type="button"
                disabled={busy}
                onClick={() => handleSyncGitHubRepo(rr.full_name)}
                className="shrink-0 rounded-lg bg-primary px-3 py-1.5 text-xs font-semibold text-primary-foreground"
              >
                Import
              </button>
            </div>
          ))}
        </div>
      </dialog>

      {/* Dialog: Register Webhook */}
      <dialog ref={webhookDialogRef} aria-labelledby="webhook-dialog-title">
        <h2 id="webhook-dialog-title" className="text-lg font-semibold">
          Install Webhook on {webhookRepo?.full_name}
        </h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Run <code>cloudflared tunnel --url http://127.0.0.1:8000</code> and paste the HTTPS webhook URL below.
        </p>
        <form onSubmit={handleRegisterWebhook} className="mt-4 space-y-4">
          <div>
            <label htmlFor="webhook-url-input" className="mb-1 block text-xs font-semibold">
              Public Webhook Endpoint URL
            </label>
            <input
              id="webhook-url-input"
              type="url"
              required
              autoFocus
              autoCorrect="off"
              autoCapitalize="none"
              spellCheck={false}
              placeholder="https://your-tunnel.trycloudflare.com/api/github/webhook"
              value={webhookUrlInput}
              onChange={(e) => setWebhookUrlInput(e.target.value)}
              className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 font-mono text-xs"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => webhookDialogRef.current?.close()}
              className="min-h-10 rounded-lg border border-border px-4 py-2 text-xs font-medium"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className="min-h-10 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground"
            >
              {busy ? "Installing..." : "Register Webhook"}
            </button>
          </div>
        </form>
      </dialog>
    </div>
  );
}
