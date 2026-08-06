const API_BASE = "http://127.0.0.1:8000/api/v1";

export interface ScanResponse {
  scan_id: string;
  target: string;
  scan_mode: string;
  status: string;
  files_scanned: number;
  duration_seconds: number;
  total_findings: number;
  funnel_metrics: Record<string, number>;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
}

export interface Finding {
  finding_id: string;
  rule_id: string;
  category: string;
  severity: string;
  file_path: string;
  line_number: number;
  snippet: string;
  recommendation: string;
  cwe: string;
  is_exploitable: boolean;
}

export interface SeverityAnalytics {
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
}

export interface TrendAnalytics {
  trends: Array<{
    scan_id: string;
    security_score: number;
    risk_score: number;
    timestamp: string;
  }>;
}

export interface RequirementPolicy {
  policy_id: string;
  action: string;
  required_control: string;
  source_text: string;
  plain_english: string;
  negative: boolean;
}

export interface RequirementVerdict {
  policy_id: string;
  policy: string;
  requirement: string;
  verdict: string;
  source: string;
  implementations: any[];
  missing_control_in: string[];
  satisfied_in: string[];
}

export interface RequirementCoverage {
  status: string;
  alignment_score: number;
  policies: Record<string, RequirementPolicy>;
  verdicts: RequirementVerdict[];
  documents: string[];
}

export interface ScanOptions {
  target_path?: string;
  repo_url?: string;
  enable_ai?: boolean;
  scan_mode?: string;
  requirements?: string[];
}

export const apiClient = {
  async triggerScan(options: ScanOptions): Promise<ScanResponse> {
    const res = await fetch(`${API_BASE}/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_path: options.target_path || undefined,
        repo_url: options.repo_url || undefined,
        enable_ai: options.enable_ai ?? false,
        scan_mode: options.scan_mode || "precision",
        requirements: options.requirements?.length ? options.requirements : undefined,
      }),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || "Failed to trigger scan");
    }
    const data = await res.json();
    return data.result || data;
  },

  async listScans(): Promise<ScanResponse[]> {
    const res = await fetch(`${API_BASE}/scans`);
    if (!res.ok) throw new Error("Failed to list scans");
    return res.json();
  },

  async listFindings(): Promise<Finding[]> {
    const res = await fetch(`${API_BASE}/findings`);
    if (!res.ok) throw new Error("Failed to list findings");
    return res.json();
  },

  async getFindingDetail(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/findings/${id}`);
    if (!res.ok) throw new Error("Failed to get finding details");
    return res.json();
  },

  async getSeverityAnalytics(): Promise<SeverityAnalytics> {
    const res = await fetch(`${API_BASE}/analytics/severity`);
    if (!res.ok) throw new Error("Failed to get severity analytics");
    return res.json();
  },

  async getTrendAnalytics(): Promise<TrendAnalytics> {
    const res = await fetch(`${API_BASE}/analytics/trends`);
    if (!res.ok) throw new Error("Failed to get trend analytics");
    return res.json();
  },

  async getRequirementCoverage(scanId?: string): Promise<RequirementCoverage> {
    const url = scanId ? `${API_BASE}/requirements/${scanId}` : `${API_BASE}/requirements`;
    const res = await fetch(url);
    if (!res.ok) throw new Error("Failed to get requirement coverage");
    return res.json();
  },
};
