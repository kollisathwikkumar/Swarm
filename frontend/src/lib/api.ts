const DEFAULT_API_BASE = "http://127.0.0.1:8000";

export function getApiBase(): string {
  if (typeof window !== "undefined") {
    return process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_BASE;
  }
  return process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_BASE;
}

export function getWsBase(): string {
  const api = getApiBase();
  return api.replace(/^http/, "ws");
}

export function connectResilientWebSocket(
  path: string,
  handlers: {
    onMessage: (evt: MessageEvent) => void;
    onOpen?: () => void;
    onClose?: () => void;
  }
): () => void {
  let ws: WebSocket | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let attempt = 0;
  let disposed = false;

  const connect = () => {
    if (disposed) return;
    ws = new WebSocket(`${getWsBase()}${path}`);
    ws.onopen = () => {
      attempt = 0;
      handlers.onOpen?.();
    };
    ws.onmessage = (evt) => handlers.onMessage(evt);
    ws.onclose = () => {
      handlers.onClose?.();
      if (disposed) return;
      const delay = Math.min(10000, 1000 * 2 ** Math.min(attempt, 4));
      attempt += 1;
      timer = setTimeout(connect, delay);
    };
  };

  connect();
  return () => {
    disposed = true;
    if (timer) clearTimeout(timer);
    ws?.close();
  };
}

export function getStoredToken(): string | null {
  return null;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const resp = await fetch(`${getApiBase()}${path}`, {
    ...options,
    headers,
  });

  if (!resp.ok) {
    let msg = `Request failed (${resp.status})`;
    try {
      const errJson = await resp.json();
      msg = errJson.detail || errJson.message || msg;
    } catch {
      const txt = await resp.text();
      if (txt) msg = txt;
    }
    throw new ApiError(resp.status, msg);
  }

  if (resp.status === 204) {
    return {} as T;
  }
  return (await resp.json()) as T;
}

export interface BatchCommitGitHubResponse {
  committed_count: number;
  skipped_count: number;
  failed_count: number;
  committed: Array<{
    patch_id: string;
    title: string;
    file_path: string;
    repository_name: string;
    branch: string;
    commit_sha?: string | null;
  }>;
  skipped: Array<{
    patch_id: string;
    title: string;
    file_path: string;
    reason: string;
  }>;
  errors: Array<{
    patch_id: string;
    title: string;
    file_path: string;
    detail: string;
  }>;
}

export async function commitAllPatchesToGithub(payload: {
  patch_ids?: string[];
  review_id?: string;
}): Promise<{ noticeMsg: string; errorMsg: string; res: BatchCommitGitHubResponse }> {
  const res = await apiFetch<BatchCommitGitHubResponse>("/api/patches/commit-all-github", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  const noticeParts: string[] = [];
  if (res.committed_count > 0) {
    noticeParts.push(
      `Approved and committed ${res.committed_count} patch${res.committed_count === 1 ? "" : "es"} to GitHub.`
    );
  }
  if (res.skipped_count > 0) {
    noticeParts.push(`${res.skipped_count} duplicate file patch skipped.`);
  }
  const errorMsg =
    res.failed_count > 0
      ? `Failed committing ${res.failed_count} patch${res.failed_count === 1 ? "" : "es"}: ${res.errors
          .map((e) => `${e.file_path} (${e.detail})`)
          .join("; ")}`
      : "";
  return { noticeMsg: noticeParts.join(" "), errorMsg, res };
}
