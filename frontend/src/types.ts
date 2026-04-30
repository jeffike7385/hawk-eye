export interface ScanSummary {
  id: string;
  target_host: string;
  status: string;
  transport: string | null;
  scan_user: string;
  entra_user: string;
  files_found: number | null;
  files_scanned: number | null;
  files_skipped: number | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface Finding {
  id: string;
  file_path: string;
  pattern_name: string;
  category: string;
  severity: string;
  matches: string[];
  match_count: number;
  sample_text: string | null;
  file_owner: string | null;
  file_modified: string | null;
}

export interface SkippedFile {
  id: string;
  file_path: string;
  reason: string;
}

export interface ScanDetail extends ScanSummary {
  paths: string[];
  exclude_patterns: string[];
  redacted: boolean;
  error_message: string | null;
  findings: Finding[];
  skipped_files: SkippedFile[];
}

export interface ScanListResponse {
  items: ScanSummary[];
  total: number;
  page: number;
  per_page: number;
}

export interface DashboardStats {
  total_scans: number;
  active_scans: number;
  total_findings: number;
  high_severity_findings: number;
}

export interface ProgressMessage {
  phase: string;
  files_found?: number;
  current?: number;
  total?: number;
  filename?: string;
  findings_count?: number;
  skipped_count?: number;
  error?: string;
}

export interface UserInfo {
  email: string;
  name: string;
}
