/**
 * OpenSecX API Client — Phase 1
 *
 * Single source of truth for all API calls to the backend.
 * All response types are strictly typed — no `any` escape hatches.
 * All callers must handle the loading and error states returned here.
 */
import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000/api/v1';

export const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
});

// ─── Types ───────────────────────────────────────────────────────────────────

export interface Asset {
  id: number;
  domain: string | null;
  hostname: string | null;
  ip_address: string | null;
  ports: number[] | null;
  protocol: string | null;
  service: string | null;
  technologies: string[] | null;
  dns_records: Record<string, string[]> | null;
  certificate: {
    subject?: string;
    issuer?: string;
    not_before?: string;
    not_after?: string;
    serial?: string;
    tls_version?: string;
    days_left?: number;
    san?: string[];
    cipher?: string;
    expired?: boolean;
  } | null;
  source: string | null;
  asn: string | null;
  org: string | null;
  country: string | null;
  status: 'Active' | 'Warning' | 'Critical' | 'Inactive';
  notes: string | null;
  first_seen: string | null;
  last_seen: string | null;
}

export interface ScanJob {
  id: number;
  target: string;
  status: 'pending' | 'running' | 'done' | 'error';
  tools: string[] | null;
  started_at: string | null;
  completed_at: string | null;
  assets_found: number;
  findings_count: number;
  error: string | null;
}

export interface Finding {
  id: number;
  scan_id: number;
  asset_id: number | null;
  title: string;
  description: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string | null;
  evidence: Record<string, unknown> | null;
  grade: 'confirmed' | 'supported' | 'possible';
  remediation: string | null;
  cve_id: string | null;
  cvss: number | null;
  epss: number | null;
  in_kev: boolean;
  priority: string | null;
  triage_status: 'open' | 'confirmed_real' | 'false_positive' | 'accepted_risk';
  triage_note: string | null;
  triaged_at: string | null;
  created_at: string | null;
}

export interface FindingSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  open: number;
  triaged: number;
  in_kev: number;
}

export interface PlatformStats {
  total_assets: number;
  active_assets: number;
  warning_assets: number;
  critical_assets: number;
  inactive_assets: number;
  internet_facing_assets: number;
  unique_domains: number;
  unique_ips: number;
  unique_ports: number;
  total_scans: number;
  running_scans: number;
  completed_scans: number;
  failed_scans: number;
  last_scan_at: string | null;
  assets_added_today: number;
  assets_added_last_7_days: number;
}

export interface ApiError {
  message: string;
  status?: number;
}

// ─── Assets API ───────────────────────────────────────────────────────────────

export async function fetchAssets(params?: {
  search?: string;
  status?: string;
  skip?: number;
  limit?: number;
}): Promise<Asset[]> {
  const { data } = await api.get<Asset[]>('/assets/', { params });
  return data;
}

export async function fetchAsset(id: number): Promise<Asset> {
  const { data } = await api.get<Asset>(`/assets/${id}`);
  return data;
}

export interface AssetCreatePayload {
  domain?: string;
  hostname?: string;
  ip_address?: string;
  ports?: number[];
  protocol?: string;
  service?: string;
  technologies?: string[];
  source?: string;
  status?: string;
  notes?: string;
}

export async function createAsset(payload: AssetCreatePayload): Promise<Asset> {
  const { data } = await api.post<Asset>('/assets/', payload);
  return data;
}

export async function deleteAsset(id: number): Promise<void> {
  await api.delete(`/assets/${id}`);
}

// ─── Scans API ────────────────────────────────────────────────────────────────

export interface ScanStartPayload {
  target: string;
  tools?: string[];
  notes?: string;
}

export async function startScan(payload: ScanStartPayload): Promise<ScanJob> {
  const { data } = await api.post<ScanJob>('/scans/start', payload);
  return data;
}

export async function fetchScans(params?: {
  skip?: number;
  limit?: number;
}): Promise<ScanJob[]> {
  const { data } = await api.get<ScanJob[]>('/scans/', { params });
  return data;
}

export async function fetchScan(id: number): Promise<ScanJob> {
  const { data } = await api.get<ScanJob>(`/scans/${id}`);
  return data;
}

// ─── Findings API ───────────────────────────────────────────────────────────────────────

export async function fetchFindings(params?: {
  scan_id?: number;
  severity?: string;
  triage_status?: string;
  in_kev?: boolean;
  skip?: number;
  limit?: number;
}): Promise<Finding[]> {
  const { data } = await api.get<Finding[]>('/findings/', { params });
  return data;
}

export async function fetchFindingsForScan(scanId: number): Promise<Finding[]> {
  const { data } = await api.get<Finding[]>(`/findings/scan/${scanId}`);
  return data;
}

export async function fetchFindingsSummary(scanId?: number): Promise<FindingSummary> {
  const params = scanId ? { scan_id: scanId } : {};
  const { data } = await api.get<FindingSummary>('/findings/summary', { params });
  return data;
}

export async function triageFinding(
  findingId: number,
  status: 'open' | 'confirmed_real' | 'false_positive' | 'accepted_risk',
  note?: string,
): Promise<Finding> {
  const { data } = await api.patch<Finding>(`/findings/${findingId}/triage`, { status, note });
  return data;
}

export async function deleteFinding(findingId: number): Promise<void> {
  await api.delete(`/findings/${findingId}`);
}

// ─── Phase 3: Reports & Attack Paths ─────────────────────────────────────────

export interface AttackPathStep {
  label: string;
  type: 'entry' | 'service' | 'technology' | 'vulnerability' | 'technique' | 'impact';
  grade: 'confirmed' | 'supported' | 'possible';
  detail: string;
  finding_id?: number;
  severity?: string;
  cvss?: number;
  epss?: number;
  in_kev?: boolean;
}

export interface AttackPath {
  id: string;
  target: string;
  asset: string;
  severity: string;
  in_kev: boolean;
  priority: string | null;
  steps: AttackPathStep[];
}

export interface ScanReport {
  meta: {
    scan_id: number;
    target: string;
    generated_at: string;
    status: string;
    started_at: string | null;
    completed_at: string | null;
    tools: string[];
  };
  summary: {
    assets_found: number;
    findings_total: number;
    findings_by_severity: Record<string, number>;
    findings_in_kev: number;
    attack_paths: number;
  };
  assets: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  attack_paths: AttackPath[];
}

export async function fetchScanReport(scanId: number): Promise<ScanReport> {
  const { data } = await api.get<ScanReport>(`/scans/${scanId}/report`);
  return data;
}

export async function fetchAttackPaths(scanId: number): Promise<{ count: number; paths: AttackPath[] }> {
  const { data } = await api.get<{ count: number; paths: AttackPath[] }>(`/scans/${scanId}/attack-paths`);
  return data;
}

export function getScanReportHtmlUrl(scanId: number): string {
  return `${api.defaults.baseURL}/scans/${scanId}/report.html`;
}


// ─── Risk & Compliance API ────────────────────────────────────────────────────

export interface RiskScore {
  scan_id: number;
  target: string;
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  components: {
    vulnerability: number;
    kev_penalty: number;
    exposure: number;
    hygiene: number;
  };
  owasp_coverage: Record<string, { findings: number; critical: number; high: number; status: string }>;
  cis_coverage: Record<string, { findings: number; status: string }>;
  nist_coverage: Record<string, { findings: number; status: string }>;
  breakdown: {
    vuln_score: number;
    kev_score: number;
    exposure_score: number;
    hygiene_score: number;
    findings_total: number;
    findings_critical: number;
    findings_high: number;
    findings_medium: number;
    findings_kev: number;
    assets_total: number;
    open_ports: number[];
    high_risk_ports_open: number[];
    owasp_categories_affected: number;
  };
  calculated_at: string | null;
}

export interface RiskSummary {
  total_scans_scored: number;
  average_score: number | null;
  worst_score: { scan_id: number; target: string; score: number; grade: string } | null;
  best_score: { scan_id: number; target: string; score: number; grade: string } | null;
  grade_distribution: Record<string, number>;
  latest_scores: Array<{ scan_id: number; target: string; score: number; grade: string }>;
}

export async function fetchRiskScore(scanId: number): Promise<RiskScore> {
  const { data } = await api.get<RiskScore>(`/risk/${scanId}`);
  return data;
}

export async function fetchRiskSummary(): Promise<RiskSummary> {
  const { data } = await api.get<RiskSummary>('/risk/summary');
  return data;
}

export async function recalculateRisk(scanId: number): Promise<{ score: number; grade: string }> {
  const { data } = await api.post(`/risk/${scanId}/recalculate`);
  return data;
}

// ─── Stats API ────────────────────────────────────────────────────────────────

export async function fetchStats(): Promise<PlatformStats> {
  const { data } = await api.get<PlatformStats>('/stats/');
  return data;
}

// ─── Health ───────────────────────────────────────────────────────────────────

export async function checkHealth(): Promise<boolean> {
  try {
    await api.get('/health', { baseURL: 'http://localhost:8000', timeout: 3000 });
    return true;
  } catch {
    return false;
  }
}

// ─── Error helper ─────────────────────────────────────────────────────────────

export function getApiError(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) return detail.map((d) => d.msg).join(', ');
    return err.message;
  }
  if (err instanceof Error) return err.message;
  return 'An unexpected error occurred';
}
