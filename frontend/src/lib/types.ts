export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: string;
  created_at?: string | null;
}

export interface GitHubAccount {
  id: string;
  provider: string;
  auth_mode: string;
  username: string;
  avatar_url?: string | null;
  scopes: string;
  created_at?: string | null;
}

export interface RepositoryItem {
  id: string;
  source_type: "github" | "local";
  full_name: string;
  owner: string;
  name: string;
  description?: string | null;
  default_branch: string;
  html_url?: string | null;
  local_path?: string | null;
  is_private: boolean;
  auto_review_webhooks: boolean;
  last_synced_at?: string | null;
  review_count: number;
  latest_recommendation?: string | null;
  latest_review_id?: string | null;
}

export interface ChangedFileItem {
  path: string;
  status: string;
  additions: number;
  deletions: number;
  changed_lines: number[];
  patch: string;
}

export interface AgentRunItem {
  id: string;
  review_id?: string;
  repository_name?: string;
  agent_name: string;
  agent_label: string;
  model_used: string;
  status: "queued" | "running" | "completed" | "incomplete" | "failed" | string;
  summary: string;
  tool_results?: Record<string, unknown>;
  error_message?: string | null;
  duration_ms: number;
  started_at?: string | null;
  completed_at?: string | null;
}

export interface FindingItem {
  id: string;
  agent: string;
  category: string;
  severity: "Critical" | "High" | "Medium" | "Low" | string;
  title: string;
  description: string;
  file_path: string;
  line_number?: number | null;
  end_line?: number | null;
  evidence: string;
  tool_name?: string | null;
  rule_id?: string | null;
  recommendation: string;
  verification_status: "Verified" | "Needs Verification" | "Unverified" | string;
  deduplicated_sources: string[];
  priority_rank: number;
  is_blocking: boolean;
  evidence_ids?: string[];
  confidence?: number;
}

export interface PatchSuggestionItem {
  id: string;
  review_id: string;
  repository_id?: string;
  repository_name?: string;
  source_type?: string;
  finding_id?: string | null;
  file_path: string;
  title: string;
  original_code: string;
  proposed_code: string;
  unified_diff: string;
  explanation: string;
  applicability_verified: boolean;
  validation_output: string;
  approval_status: "pending_approval" | "approved" | "rejected" | "applied" | string;
  applied_ref?: string | null;
  decided_by?: string | null;
  decided_at?: string | null;
  created_at?: string | null;
}

export interface ReviewSummaryItem {
  id: string;
  repository_id: string;
  repository_name: string;
  source_type: string;
  triggered_by: string;
  base_commit: string;
  target_commit: string;
  base_branch: string;
  target_branch: string;
  pr_number?: number | null;
  pr_title?: string | null;
  review_status: string;
  recommendation: "Approve" | "Request Changes" | "Incomplete" | "Pending" | string;
  recommendation_reason: string;
  diff_summary: string;
  github_review_id?: number | null;
  github_published_at?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  findings_count?: number;
  severity_counts?: Record<string, number>;
}

export interface ReviewDetailResponse {
  review: ReviewSummaryItem;
  code_change: {
    id: string;
    source_mode: string;
    pr_number?: number | null;
    pr_title?: string | null;
    pr_url?: string | null;
    base_branch: string;
    target_branch: string;
    base_commit: string;
    target_commit: string;
    diff_text: string;
    changed_files: ChangedFileItem[];
    file_snapshots: Record<string, string>;
  };
  agent_runs: AgentRunItem[];
  findings: FindingItem[];
  patch_suggestions: PatchSuggestionItem[];
  artifacts: {
    id: string;
    artifact_type: string;
    title: string;
    content_type: string;
    content: string;
  }[];
  shared_state: Record<string, unknown>;
}

export interface AgentLLMConfigItem {
  agent_name: string;
  label: string;
  role: string;
  default_model: string;
  model: string;
  base_url: string;
  temperature: string;
  has_api_key: boolean;
  masked_api_key: string;
  key_source: "database" | "env" | "unconfigured" | string;
  last_tested_at?: string | null;
  last_test_status?: string | null;
}

export interface ReviewPolicyData {
  block_on_critical: boolean;
  block_on_high: boolean;
  require_tests_pass: boolean;
  require_all_mandatory_scans: boolean;
  enable_test_execution: boolean;
  auto_publish_github_review: boolean;
  excluded_paths: string[];
}

export interface AnalyticsSummary {
  totals: {
    repositories: number;
    reviews: number;
    findings: number;
    patches: number;
    approved_reviews: number;
    request_changes_reviews: number;
    incomplete_reviews: number;
  };
  severity_breakdown: Record<string, number>;
  verification_breakdown: Record<string, number>;
  findings_by_agent: Record<string, number>;
  findings_by_tool: Record<string, number>;
  patch_status_breakdown: Record<string, number>;
  top_affected_files: { file_path: string; count: number }[];
  daily_timeline: {
    date: string;
    reviews: number;
    approve: number;
    request_changes: number;
    incomplete: number;
  }[];
  agent_avg_latency_ms: Record<string, number>;
}
