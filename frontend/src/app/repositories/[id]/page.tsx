"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import Editor from "@monaco-editor/react";
import {
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  Copy,
  ExternalLink,
  FileCode2,
  Folder,
  FolderOpen,
  GitBranch,
  GitPullRequest,
  Play,
  X,
} from "lucide-react";
import { apiFetch } from "@/lib/api";
import { useResolvedTheme } from "@/lib/theme";
import GlassFolder, { type ArtPreset, type FolderFile } from "@/components/ui/glass-folder-cards";

interface TreeItem {
  path: string;
  type: "dir" | "file";
  size: number;
  sha: string;
}

interface TreeResponse {
  repository: {
    id: string;
    full_name: string;
    source_type: "github" | "local";
    default_branch: string;
    html_url?: string | null;
  };
  ref: string;
  branches: string[];
  truncated: boolean;
  items: TreeItem[];
}

interface FileContentResponse {
  path: string;
  ref: string;
  sha: string;
  size: number;
  is_binary: boolean;
  content: string;
}

interface TreeNode {
  name: string;
  path: string;
  type: "dir" | "file";
  size: number;
  children: TreeNode[];
}

const FOLDER_ART_PRESETS: ArtPreset[] = ["aurora", "glacier", "dusk", "verdant", "ember"];

function buildTree(items: TreeItem[]): TreeNode[] {
  const root: TreeNode[] = [];
  const dirMap = new Map<string, TreeNode>();

  const ensureDir = (dirPath: string): TreeNode => {
    const existing = dirMap.get(dirPath);
    if (existing) return existing;
    const parts = dirPath.split("/");
    const name = parts[parts.length - 1];
    const node: TreeNode = { name, path: dirPath, type: "dir", size: 0, children: [] };
    dirMap.set(dirPath, node);
    if (parts.length === 1) {
      root.push(node);
    } else {
      const parent = ensureDir(parts.slice(0, -1).join("/"));
      parent.children.push(node);
    }
    return node;
  };

  for (const item of items) {
    if (item.type === "dir") {
      ensureDir(item.path);
    } else {
      const parts = item.path.split("/");
      const name = parts[parts.length - 1];
      const fileNode: TreeNode = {
        name,
        path: item.path,
        type: "file",
        size: item.size,
        children: [],
      };
      if (parts.length === 1) {
        root.push(fileNode);
      } else {
        const parent = ensureDir(parts.slice(0, -1).join("/"));
        parent.children.push(fileNode);
      }
    }
  }

  const sortNodes = (nodes: TreeNode[]) => {
    nodes.sort((a, b) => {
      if (a.type !== b.type) return a.type === "dir" ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    for (const n of nodes) {
      if (n.children.length > 0) sortNodes(n.children);
    }
  };
  sortNodes(root);
  return root;
}

function detectLanguage(path: string): string {
  const lower = path.toLowerCase();
  if (lower.endsWith(".py")) return "python";
  if (lower.endsWith(".ts") || lower.endsWith(".tsx")) return "typescript";
  if (lower.endsWith(".js") || lower.endsWith(".jsx") || lower.endsWith(".mjs")) return "javascript";
  if (lower.endsWith(".json")) return "json";
  if (lower.endsWith(".yml") || lower.endsWith(".yaml")) return "yaml";
  if (lower.endsWith(".md")) return "markdown";
  if (lower.endsWith(".css")) return "css";
  if (lower.endsWith(".html")) return "html";
  if (lower.endsWith(".sql")) return "sql";
  if (lower.endsWith(".sh") || lower.endsWith(".bash")) return "shell";
  if (lower.endsWith(".go")) return "go";
  if (lower.endsWith(".rs")) return "rust";
  if (lower.endsWith(".java")) return "java";
  if (lower.endsWith(".xml")) return "xml";
  if (lower.endsWith(".toml") || lower.endsWith(".ini")) return "ini";
  return "plaintext";
}

export default function RepositoryExplorerPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const repoId = params.id;
  const { resolved } = useResolvedTheme();

  const [treeData, setTreeData] = useState<TreeResponse | null>(null);
  const [selectedRef, setSelectedRef] = useState<string>("");
  const [expandedDirs, setExpandedDirs] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState("");
  const [activeFolderScope, setActiveFolderScope] = useState<string>("");

  const [selectedFile, setSelectedFile] = useState<string>("");
  const [fileData, setFileData] = useState<FileContentResponse | null>(null);
  const [loadingTree, setLoadingTree] = useState(true);
  const [loadingFile, setLoadingFile] = useState(false);
  const [startingAudit, setStartingAudit] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");

  const loadFile = useCallback(
    async (path: string, ref: string) => {
      setSelectedFile(path);
      setLoadingFile(true);
      setError("");
      try {
        const res = await apiFetch<FileContentResponse>(
          `/api/repositories/${repoId}/file?path=${encodeURIComponent(path)}&ref=${encodeURIComponent(ref)}`
        );
        setFileData(res);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed loading file");
      } finally {
        setLoadingFile(false);
      }
    },
    [repoId]
  );

  const loadTree = useCallback(
    async (refOverride?: string) => {
      setLoadingTree(true);
      setError("");
      try {
        const q = refOverride ? `?ref=${encodeURIComponent(refOverride)}` : "";
        const res = await apiFetch<TreeResponse>(`/api/repositories/${repoId}/tree${q}`);
        setTreeData(res);
        setSelectedRef(res.ref);

        const topDirs = new Set(
          res.items
            .filter((i) => i.type === "dir" && !i.path.includes("/"))
            .map((i) => i.path)
        );
        setExpandedDirs(topDirs);

        const filesOnly = res.items.filter((i) => i.type === "file");
        const readme = filesOnly.find((f) => f.path.toLowerCase() === "readme.md");
        const initialFile = readme?.path || filesOnly[0]?.path || "";
        if (initialFile) {
          void loadFile(initialFile, res.ref);
        } else {
          setSelectedFile("");
          setFileData(null);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed loading repository tree");
      } finally {
        setLoadingTree(false);
      }
    },
    [repoId, loadFile]
  );

  useEffect(() => {
    void loadTree();
  }, [loadTree]);

  // Real folder decks grouped by top-level directory (with exact full paths preserved for clicking)
  const directoryDecks = useMemo(() => {
    if (!treeData) return [];
    const grouped = new Map<string, { label: string; fullPaths: TreeItem[] }>();
    for (const item of treeData.items) {
      if (item.type !== "file") continue;
      const top = item.path.includes("/") ? item.path.split("/")[0] : "/";
      const entry = grouped.get(top) || {
        label: top === "/" ? "Root Files" : `${top}/`,
        fullPaths: [],
      };
      entry.fullPaths.push(item);
      grouped.set(top, entry);
    }

    const sortedGroups = Array.from(grouped.entries()).sort((a, b) => {
      if (a[0] === "/") return 1;
      if (b[0] === "/") return -1;
      return b[1].fullPaths.length - a[1].fullPaths.length;
    });

    return sortedGroups.slice(0, 6).map(([key, group], idx) => {
      // Pick up to 4 priority files from this folder
      const rankedFiles = [...group.fullPaths].sort((a, b) => {
        const aScore = a.path.endsWith(".ts") || a.path.endsWith(".py") ? 0 : 1;
        const bScore = b.path.endsWith(".ts") || b.path.endsWith(".py") ? 0 : 1;
        return aScore - bScore || a.path.localeCompare(b.path);
      });
      const visibleFiles = rankedFiles.slice(0, 4);
      const art = FOLDER_ART_PRESETS[idx % FOLDER_ART_PRESETS.length];
      const sheets: FolderFile[] = visibleFiles.map((f, fIdx) => {
        const shortName = f.path.split("/").pop() || f.path;
        return {
          name: shortName,
          meta: `${(Math.max(1, f.size) / 1024).toFixed(1)} KB`,
          art: fIdx === 0 ? art : undefined,
        };
      });
      return {
        key,
        label: group.label,
        totalCount: group.fullPaths.length,
        art,
        sheets,
        resolvedPaths: visibleFiles.map((f) => f.path),
      };
    });
  }, [treeData]);

  const filteredItems = useMemo(() => {
    if (!treeData) return [];
    const q = searchQuery.trim().toLowerCase();
    return treeData.items.filter((item) => {
      if (activeFolderScope) {
        if (activeFolderScope === "/") {
          if (item.path.includes("/")) return false;
        } else if (!item.path.startsWith(activeFolderScope + "/") && item.path !== activeFolderScope) {
          return false;
        }
      }
      if (!q) return true;
      return item.type === "file" && item.path.toLowerCase().includes(q);
    });
  }, [treeData, searchQuery, activeFolderScope]);

  const treeNodes = useMemo(() => buildTree(filteredItems), [filteredItems]);

  const toggleDir = (dirPath: string) => {
    setExpandedDirs((prev) => {
      const next = new Set(prev);
      if (next.has(dirPath)) next.delete(dirPath);
      else next.add(dirPath);
      return next;
    });
  };

  const handleCopy = async () => {
    if (!fileData?.content) return;
    await navigator.clipboard.writeText(fileData.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handleFullCodebaseAudit = async () => {
    if (!treeData) return;
    setStartingAudit(true);
    setError("");
    try {
      const res = await apiFetch<{ review_id: string }>("/api/reviews", {
        method: "POST",
        body: JSON.stringify({
          repository_id: repoId,
          full_codebase: true,
          target_ref: selectedRef,
        }),
      });
      router.push(`/reviews/${res.review_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed starting full codebase review");
      setStartingAudit(false);
    }
  };

  const renderTree = (nodes: TreeNode[], depth = 0): React.ReactNode => {
    return nodes.map((node) => {
      if (node.type === "dir") {
        const isOpen = Boolean(searchQuery.trim() || activeFolderScope || expandedDirs.has(node.path));
        return (
          <li key={node.path}>
            <button
              type="button"
              onClick={() => toggleDir(node.path)}
              className="flex w-full items-center gap-1.5 rounded px-2 py-1 text-left text-xs hover:bg-muted"
              style={{ paddingInlineStart: `${depth * 14 + 8}px` }}
            >
              {isOpen ? (
                <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
              ) : (
                <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
              )}
              {isOpen ? (
                <FolderOpen className="h-3.5 w-3.5 shrink-0 text-amber-500" aria-hidden="true" />
              ) : (
                <Folder className="h-3.5 w-3.5 shrink-0 text-amber-500" aria-hidden="true" />
              )}
              <span className="truncate font-medium">{node.name}</span>
            </button>
            {isOpen && node.children.length > 0 && (
              <ul>{renderTree(node.children, depth + 1)}</ul>
            )}
          </li>
        );
      }

      const active = selectedFile === node.path;
      return (
        <li key={node.path}>
          <button
            type="button"
            onClick={() => loadFile(node.path, selectedRef)}
            className={`flex w-full items-center justify-between gap-2 rounded px-2 py-1 text-left font-mono text-[11px] ${
              active
                ? "bg-primary font-semibold text-primary-foreground"
                : "text-muted-foreground hover:bg-muted hover:text-foreground"
            }`}
            style={{ paddingInlineStart: `${depth * 14 + 22}px` }}
          >
            <span className="flex min-w-0 items-center gap-1.5">
              <FileCode2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span className="truncate">{node.name}</span>
            </span>
          </button>
        </li>
      );
    });
  };

  const fileCount = treeData?.items.filter((i) => i.type === "file").length ?? 0;

  return (
    <div className="space-y-5">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-border bg-card p-5">
        <div className="space-y-1">
          <Link
            href="/repositories"
            className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground hover:text-foreground hover:underline"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            Repositories
          </Link>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-semibold tracking-tight sm:text-2xl">
              {treeData?.repository.full_name || "Repository Codebase"}
            </h1>
            {treeData && (
              <span className="rounded border border-border bg-muted px-2 py-0.5 font-mono text-[10px] uppercase text-muted-foreground">
                {treeData.repository.source_type}
              </span>
            )}
            {treeData?.repository.html_url && (
              <a
                href={treeData.repository.html_url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground hover:text-foreground hover:underline"
              >
                GitHub <ExternalLink className="h-3 w-3" aria-hidden="true" />
              </a>
            )}
          </div>
        </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {treeData && (
              <div className="flex items-center gap-1.5">
                <GitBranch className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
                <label htmlFor="branch-ref-select" className="visually-hidden">
                  Branch or Ref
                </label>
                <select
                  id="branch-ref-select"
                  value={selectedRef}
                  onChange={(e) => void loadTree(e.target.value)}
                  className="min-h-10 rounded-lg border border-border bg-muted px-3 py-1.5 font-mono text-xs"
                >
                  {treeData.branches.map((b) => (
                    <option key={b} value={b}>
                      {b}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <Link
              href={`/reviews/submit?repo=${repoId}`}
              className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-border bg-muted px-3 py-1.5 text-xs font-medium hover:border-foreground/40"
            >
              <GitPullRequest className="h-3.5 w-3.5" aria-hidden="true" />
              Review PR / Commit
            </Link>

            {treeData?.repository.source_type === "github" && (
              <button
                type="button"
                disabled={startingAudit || loadingTree}
                onClick={handleFullCodebaseAudit}
                className="inline-flex min-h-10 items-center gap-1.5 rounded-lg bg-primary px-3.5 py-1.5 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-50"
              >
                <Play className="h-3.5 w-3.5" aria-hidden="true" />
                {startingAudit ? "Launching 6-Agent Audit..." : "Review Full Codebase"}
              </button>
            )}
          </div>
        </header>

      {error && (
        <div role="alert" className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-700 dark:text-rose-300">
          {error}
        </div>
      )}

      {/* Interactive Directory Glass Folders */}
      {!loadingTree && directoryDecks.length > 0 && (
        <section className="rounded-xl border border-border bg-card p-5">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold">Folders</h2>
            {activeFolderScope && (
              <button
                type="button"
                onClick={() => setActiveFolderScope("")}
                className="inline-flex items-center gap-1 rounded border border-border bg-muted px-2.5 py-1 font-mono text-[11px] hover:border-foreground/40"
              >
                <X className="h-3 w-3" aria-hidden="true" />
                Clear Scope ({activeFolderScope === "/" ? "Root" : activeFolderScope})
              </button>
            )}
          </div>
          <div className="rb-dotted-desk rounded-xl border border-border bg-muted/40 px-4 py-8">
            <div className="flex flex-wrap items-end justify-center gap-x-8 gap-y-10">
              {directoryDecks.map((deck, idx) => (
                <GlassFolder
                  key={deck.key}
                  label={deck.label}
                  meta={`${deck.totalCount} file${deck.totalCount === 1 ? "" : "s"}`}
                  tone={resolved}
                  art={deck.art}
                  seed={idx * 11 + 5}
                  action="more"
                  width={220}
                  appearDelay={idx * 70}
                  files={deck.sheets}
                  onFileSelect={(_, fileIdx) => {
                    const targetPath = deck.resolvedPaths[fileIdx];
                    if (targetPath) void loadFile(targetPath, selectedRef);
                  }}
                  menu={[
                    {
                      label: `Filter tree to ${deck.label}`,
                      onSelect: () => setActiveFolderScope(deck.key),
                    },
                    ...(activeFolderScope
                      ? [{ label: "Show full repo tree", onSelect: () => setActiveFolderScope("") }]
                      : []),
                  ]}
                />
              ))}
            </div>
          </div>
        </section>
      )}

      {/* IDE Split Explorer */}
      <div className="grid gap-4 lg:grid-cols-12">
        <aside
          aria-label="Repository file tree"
          className="flex flex-col rounded-xl border border-border bg-card p-3 lg:col-span-4 xl:col-span-3"
        >
          <div className="mb-2 flex items-center justify-between">
            <h2 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              Files ({fileCount})
            </h2>
            {treeData?.truncated && (
              <span className="font-mono text-[11px] text-amber-600 dark:text-amber-400">Truncated</span>
            )}
          </div>

          <input
            type="search"
            aria-label="Filter repository files"
            placeholder="Filter files by path..."
            autoCorrect="off"
            autoCapitalize="none"
            spellCheck={false}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="mb-3 min-h-9 w-full rounded-lg border border-border bg-muted px-2.5 py-1 font-mono text-xs"
          />

          {loadingTree ? (
            <p className="p-2 text-xs text-muted-foreground">Loading repository tree...</p>
          ) : treeNodes.length === 0 ? (
            <p className="p-2 text-xs text-muted-foreground">No matching files found.</p>
          ) : (
            <ul className="rb-scroll max-h-[38rem] space-y-0.5 pr-1">
              {renderTree(treeNodes)}
            </ul>
          )}
        </aside>

        <section
          aria-label="File source viewer"
          className="flex min-w-0 flex-col overflow-hidden rounded-xl border border-border bg-card lg:col-span-8 xl:col-span-9"
        >
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border bg-muted px-4 py-2.5">
            <div className="min-w-0">
              <p className="truncate font-mono text-xs font-semibold">
                {selectedFile || "Select a file from the explorer or folder deck"}
              </p>
              {fileData && (
                <p className="font-mono text-[11px] text-muted-foreground">
                  {(fileData.size / 1024).toFixed(1)} KB · {fileData.content.split("\n").length} lines · ref:{" "}
                  <code>{fileData.ref}</code>
                </p>
              )}
            </div>
            {fileData && !fileData.is_binary && (
              <button
                type="button"
                onClick={handleCopy}
                className="inline-flex min-h-8 items-center gap-1.5 rounded border border-border bg-card px-2.5 py-1 font-mono text-xs hover:border-foreground/40"
              >
                <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                {copied ? "Copied" : "Copy"}
              </button>
            )}
          </div>

          <div className="h-[38rem] w-full">
            {loadingFile ? (
              <div className="flex h-full items-center justify-center font-mono text-xs text-muted-foreground">
                Loading file contents...
              </div>
            ) : fileData?.is_binary ? (
              <div className="flex h-full items-center justify-center font-mono text-xs text-muted-foreground">
                Binary file preview is not supported ({selectedFile}).
              </div>
            ) : (
              <Editor
                height="100%"
                theme={resolved === "dark" ? "vs-dark" : "light"}
                language={detectLanguage(selectedFile)}
                value={fileData?.content || ""}
                options={{
                  readOnly: true,
                  minimap: { enabled: false },
                  fontSize: 13,
                  scrollBeyondLastLine: false,
                  wordWrap: "off",
                }}
              />
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
