import { useState, useEffect, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import AppLayout from '../components/AppLayout';
import {
  ArrowLeft, Download, RefreshCw, Loader2,
  Globe, Shield, AlertTriangle, ChevronRight,
  ExternalLink, Lock, CheckCircle, Clock,
} from 'lucide-react';
import {
  fetchScan, fetchAssets, fetchFindingsForScan, fetchAttackPaths, getScanReportHtmlUrl,
  type ScanJob, type Asset, type Finding, type AttackPath, type AttackPathStep,
  triageFinding, getApiError,
} from '../api/client';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: '#F28B82', high: '#FFAB40', medium: '#FDD663', low: '#81C995', info: '#A8C7FA',
};
const SEV_BG: Record<string, string> = {
  critical: 'rgba(242,139,130,0.1)', high: 'rgba(255,171,64,0.1)',
  medium: 'rgba(253,214,99,0.1)', low: 'rgba(129,201,149,0.1)', info: 'rgba(168,199,250,0.1)',
};
const STEP_COLOR: Record<string, string> = {
  entry: '#A8C7FA', service: '#81C995', technology: '#FDD663',
  vulnerability: '#F28B82', technique: '#FFAB40', impact: '#CF6679',
};
const GRADE_COLOR: Record<string, string> = {
  confirmed: '#81C995', supported: '#FDD663', possible: '#94a3b8',
};

// ─── Tab Bar ──────────────────────────────────────────────────────────────────

function TabBar({ tabs, active, onChange }: { tabs: { id: string; label: string; count?: number }[]; active: string; onChange: (id: string) => void }) {
  return (
    <div className="flex gap-1 px-6 shrink-0" style={{ borderBottom: '1px solid var(--border-light)' }}>
      {tabs.map(t => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          className="flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium transition-all relative"
          style={{
            color: active === t.id ? 'var(--text-primary)' : 'var(--text-tertiary)',
            borderBottom: active === t.id ? '2px solid #A8C7FA' : '2px solid transparent',
            marginBottom: -1,
          }}
        >
          {t.label}
          {t.count !== undefined && (
            <span
              className="text-[10px] px-1.5 py-0.5 rounded-full"
              style={{
                background: active === t.id ? 'rgba(168,199,250,0.15)' : 'var(--border-light)',
                color: active === t.id ? '#A8C7FA' : 'var(--text-tertiary)',
              }}
            >
              {t.count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

// ─── DNS Grid ─────────────────────────────────────────────────────────────────

function DnsGrid({ records }: { records: Record<string, string[]> }) {
  const types = Object.keys(records);
  if (!types.length) return <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>No DNS records</p>;
  return (
    <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))' }}>
      {types.map(type => (
        <div key={type} className="p-3 rounded-lg" style={{ background: 'var(--bg-main)', border: '1px solid var(--border-light)' }}>
          <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded mb-2 inline-block"
            style={{ background: 'rgba(168,199,250,0.1)', color: '#A8C7FA', border: '1px solid rgba(168,199,250,0.2)' }}>
            {type}
          </span>
          {records[type].map((v, i) => (
            <p key={i} className="text-xs font-mono mt-1 break-all" style={{ color: 'var(--text-secondary)' }}>{v}</p>
          ))}
        </div>
      ))}
    </div>
  );
}

// ─── Asset Row ────────────────────────────────────────────────────────────────

function AssetRow({ asset }: { asset: Asset }) {
  const [expanded, setExpanded] = useState(false);
  const dnsRecords = asset.dns_records as Record<string, string[]> | null;
  const cert = asset.certificate as Record<string, unknown> | null;

  return (
    <>
      <tr
        className="cursor-pointer transition-colors"
        onClick={() => setExpanded(!expanded)}
        style={{ borderBottom: '1px solid var(--border-light)' }}
        onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-panel-hover, rgba(255,255,255,0.02))')}
        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
      >
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <Globe className="w-3 h-3 shrink-0" style={{ color: '#A8C7FA' }} />
            <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{asset.domain}</span>
          </div>
        </td>
        <td className="px-4 py-3">
          <span className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{asset.ip_address || '—'}</span>
        </td>
        <td className="px-4 py-3">
          <div className="flex flex-wrap gap-1">
            {(asset.technologies || []).slice(0, 3).map(t => (
              <span key={t} className="text-[10px] px-1.5 py-0.5 rounded"
                style={{ background: 'rgba(253,214,99,0.08)', color: '#FDD663', border: '1px solid rgba(253,214,99,0.15)' }}>
                {t}
              </span>
            ))}
            {(asset.technologies || []).length > 3 && (
              <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>+{(asset.technologies || []).length - 3}</span>
            )}
          </div>
        </td>
        <td className="px-4 py-3">
          {(asset.ports || []).length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {(asset.ports || []).slice(0, 5).map(p => (
                <span key={p} className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                  style={{ background: 'rgba(129,201,149,0.08)', color: '#81C995', border: '1px solid rgba(129,201,149,0.15)' }}>
                  {p}
                </span>
              ))}
            </div>
          ) : <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>}
        </td>
        <td className="px-4 py-3">
          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
            {asset.org || asset.country || '—'}
          </span>
        </td>
      </tr>
      {expanded && (
        <tr style={{ borderBottom: '1px solid var(--border-light)', background: 'var(--bg-main)' }}>
          <td colSpan={5} className="px-6 py-4">
            <div className="grid gap-4" style={{ gridTemplateColumns: cert ? '1fr 1fr' : '1fr' }}>
              {dnsRecords && Object.keys(dnsRecords).length > 0 && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider mb-2" style={{ color: 'var(--text-tertiary)' }}>DNS Records</p>
                  <DnsGrid records={dnsRecords} />
                </div>
              )}
              {cert && Object.keys(cert).length > 0 && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider mb-2" style={{ color: 'var(--text-tertiary)' }}>TLS Certificate</p>
                  <div className="p-3 rounded-lg space-y-1.5" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-light)' }}>
                    {cert.subject && <p className="text-xs"><span style={{ color: 'var(--text-tertiary)' }}>Subject: </span><span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{String(cert.subject)}</span></p>}
                    {cert.issuer && <p className="text-xs"><span style={{ color: 'var(--text-tertiary)' }}>Issuer: </span><span style={{ color: 'var(--text-secondary)' }}>{String(cert.issuer)}</span></p>}
                    {cert.days_left !== undefined && (
                      <p className="text-xs"><span style={{ color: 'var(--text-tertiary)' }}>Expiry: </span>
                        <span style={{ color: Number(cert.days_left) < 30 ? '#F28B82' : '#81C995' }}>
                          {Number(cert.days_left) < 0 ? 'EXPIRED' : `${cert.days_left} days remaining`}
                        </span>
                      </p>
                    )}
                    {cert.tls_version && <p className="text-xs"><span style={{ color: 'var(--text-tertiary)' }}>TLS: </span><span className="font-mono" style={{ color: ['TLSv1', 'TLSv1.1'].includes(String(cert.tls_version)) ? '#F28B82' : '#81C995' }}>{String(cert.tls_version)}</span></p>}
                  </div>
                </div>
              )}
            </div>
            {asset.notes && (
              <p className="text-xs mt-3 px-2 py-1.5 rounded" style={{ background: 'rgba(255,171,64,0.05)', color: '#FFAB40', border: '1px solid rgba(255,171,64,0.15)' }}>
                {asset.notes}
              </p>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Finding Card (compact for ScanReport) ────────────────────────────────────

function FindingCard({ finding, onTriage }: { finding: Finding; onTriage?: (f: Finding) => void }) {
  const [expanded, setExpanded] = useState(false);
  const sev = finding.severity;
  const c = SEV_COLOR[sev] || '#aaa';
  const bg = SEV_BG[sev] || 'rgba(170,170,170,0.08)';

  return (
    <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-panel)', border: `1px solid ${c}30` }}>
      <div className="flex items-center gap-3 px-4 py-3 cursor-pointer" style={{ borderLeft: `3px solid ${c}` }} onClick={() => setExpanded(!expanded)}>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded shrink-0" style={{ background: bg, color: c }}>
          {sev?.toUpperCase()}
        </span>
        {finding.in_kev && <span className="text-[9px] px-1.5 py-0.5 rounded animate-pulse shrink-0" style={{ background: 'rgba(242,139,130,0.15)', color: '#F28B82' }}>⚠ KEV</span>}
        <span className="flex-1 text-sm truncate" style={{ color: 'var(--text-primary)' }}>{finding.title}</span>
        {finding.cve_id && <span className="text-[10px] font-mono shrink-0" style={{ color: '#A8C7FA' }}>{finding.cve_id}</span>}
        <span className="text-[10px] shrink-0" style={{ color: GRADE_COLOR[finding.grade] || '#aaa' }}>{finding.grade}</span>
      </div>
      {expanded && (
        <div className="px-5 py-4 space-y-3" style={{ borderTop: '1px solid var(--border-light)' }}>
          {finding.description && <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{finding.description}</p>}
          {finding.remediation && (
            <div className="p-3 rounded-lg" style={{ background: 'rgba(129,201,149,0.05)', border: '1px solid rgba(129,201,149,0.15)' }}>
              <p className="text-[10px] mb-1" style={{ color: '#81C995' }}>REMEDIATION</p>
              <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{finding.remediation}</p>
            </div>
          )}
          {onTriage && finding.triage_status === 'open' && (
            <div className="flex gap-2">
              {(['false_positive', 'accepted_risk', 'confirmed_real'] as const).map(s => (
                <button key={s} onClick={() => onTriage({ ...finding, triage_status: s })}
                  className="text-[10px] px-2.5 py-1 rounded capitalize"
                  style={{ background: 'var(--border-light)', color: 'var(--text-tertiary)', border: '1px solid var(--border-light)' }}>
                  {s.replace(/_/g, ' ')}
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Attack Path Diagram ──────────────────────────────────────────────────────

function AttackPathCard({ path }: { path: AttackPath }) {
  const sev = path.severity;
  const c = SEV_COLOR[sev] || '#aaa';

  return (
    <div className="p-4 rounded-xl" style={{ background: 'var(--bg-panel)', border: `1px solid ${c}25` }}>
      {/* Header */}
      <div className="flex items-center gap-2 mb-3">
        <span className="text-[10px] font-mono px-2 py-0.5 rounded" style={{ background: SEV_BG[sev] || '', color: c }}>{sev?.toUpperCase()}</span>
        {path.in_kev && <span className="text-[9px] px-1.5 py-0.5 rounded animate-pulse" style={{ background: 'rgba(242,139,130,0.15)', color: '#F28B82' }}>⚠ KEV</span>}
        {path.priority && <span className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(255,171,64,0.08)', color: '#FFAB40' }}>{path.priority}</span>}
        <span className="text-xs font-mono ml-auto" style={{ color: 'var(--text-tertiary)' }}>{path.asset}</span>
      </div>

      {/* Steps chain */}
      <div className="flex items-center flex-wrap gap-1">
        {path.steps.map((step, i) => (
          <div key={i} className="flex items-center gap-1">
            <div
              className="group relative flex flex-col px-2.5 py-1.5 rounded-lg text-center cursor-default"
              title={step.detail}
              style={{
                background: `${STEP_COLOR[step.type] || '#aaa'}10`,
                border: `1px solid ${STEP_COLOR[step.type] || '#aaa'}30`,
                minWidth: 80,
              }}
            >
              <span className="text-[9px] uppercase tracking-wider" style={{ color: STEP_COLOR[step.type] || '#aaa', opacity: 0.7 }}>{step.type}</span>
              <span className="text-[11px] font-medium leading-tight mt-0.5" style={{ color: 'var(--text-primary)' }}>
                {step.label.length > 22 ? step.label.slice(0, 22) + '…' : step.label}
              </span>
              <span className="text-[9px] mt-0.5" style={{ color: GRADE_COLOR[step.grade] || '#aaa' }}>{step.grade}</span>
            </div>
            {i < path.steps.length - 1 && (
              <ChevronRight className="w-3 h-3 shrink-0" style={{ color: 'var(--text-tertiary)' }} />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ScanReport() {
  const { id } = useParams<{ id: string }>();
  const scanId = Number(id);

  const [scan, setScan] = useState<ScanJob | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'assets' | 'vulnerabilities' | 'attack-paths'>('assets');
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!scanId) return;
    setLoading(true);
    try {
      const [scanData, assetsData, findingsData, pathsData] = await Promise.allSettled([
        fetchScan(scanId),
        fetchAssets({ limit: 200 }),
        fetchFindingsForScan(scanId),
        fetchAttackPaths(scanId),
      ]);

      if (scanData.status === 'fulfilled') setScan(scanData.value);
      if (assetsData.status === 'fulfilled') {
        const target = scanData.status === 'fulfilled' ? scanData.value.target : '';
        setAssets(assetsData.value.filter(a => a.domain === target || a.domain?.endsWith(`.${target}`)));
      }
      if (findingsData.status === 'fulfilled') setFindings(findingsData.value);
      if (pathsData.status === 'fulfilled') setAttackPaths(pathsData.value.paths);
      setError(null);
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => { load(); }, [load]);

  // Poll while running
  useEffect(() => {
    if (scan?.status !== 'running' && scan?.status !== 'pending') return;
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [scan?.status, load]);

  const handleTriage = async (finding: Finding) => {
    try {
      const updated = await triageFinding(finding.id, finding.triage_status);
      setFindings(prev => prev.map(f => f.id === updated.id ? updated : f));
    } catch (e) { console.error(e); }
  };

  const tabs = [
    { id: 'assets', label: 'Assets & DNS', count: assets.length },
    { id: 'vulnerabilities', label: 'Vulnerabilities', count: findings.length },
    { id: 'attack-paths', label: 'Attack Paths', count: attackPaths.length },
  ] as const;

  const isRunning = scan?.status === 'running' || scan?.status === 'pending';

  return (
    <AppLayout>
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

        {/* Header */}
        <header className="h-14 shrink-0 flex items-center gap-3 px-6" style={{ borderBottom: '1px solid var(--border-light)', background: 'var(--bg-header)' }}>
          <Link to="/scans" className="flex items-center gap-1.5 text-xs transition-colors"
            style={{ color: 'var(--text-tertiary)' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-primary)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-tertiary)')}>
            <ArrowLeft className="w-3.5 h-3.5" /> Scans
          </Link>
          <span style={{ color: 'var(--border-medium)' }}>/</span>

          <div className="flex-1 min-w-0">
            <h1 className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
              {scan?.target || 'Loading...'}
            </h1>
            <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
              Scan #{scanId}
              {scan?.status && <span className={`ml-2 px-1.5 py-0.5 rounded font-mono ${scan.status === 'done' ? 'text-green-400' : scan.status === 'error' ? 'text-red-400' : 'text-yellow-400'}`} style={{ fontSize: 9 }}>{scan.status.toUpperCase()}</span>}
              {isRunning && <span className="ml-2 text-yellow-400 animate-pulse">· Scanning…</span>}
            </p>
          </div>

          <div className="flex items-center gap-2">
            {/* Risk & Compliance */}
            {scan?.status === 'done' && (
              <Link
                to={`/scans/${scanId}/risk`}
                className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg transition-all"
                style={{ background: 'rgba(255,171,64,0.08)', color: '#FFAB40', border: '1px solid rgba(255,171,64,0.2)' }}
              >
                <Shield className="w-3 h-3" /> Risk & Compliance
              </Link>
            )}
            {/* Export HTML */}
            {scan?.status === 'done' && (
              <a
                href={getScanReportHtmlUrl(scanId)}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg transition-all"
                style={{ background: 'rgba(129,201,149,0.08)', color: '#81C995', border: '1px solid rgba(129,201,149,0.2)' }}
              >
                <Download className="w-3 h-3" /> Export HTML
              </a>
            )}
            <button onClick={load} className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg"
              style={{ color: 'var(--text-tertiary)', border: '1px solid var(--border-light)' }}>
              {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
            </button>
          </div>
        </header>

        {/* Summary stats */}
        {scan && (
          <div className="shrink-0 grid gap-px" style={{
            gridTemplateColumns: 'repeat(5, 1fr)',
            background: 'var(--border-light)',
            borderBottom: '1px solid var(--border-light)',
          }}>
            {[
              { label: 'Assets', value: assets.length, color: '#A8C7FA' },
              { label: 'Findings', value: findings.length, color: findings.length > 0 ? '#FFAB40' : '#81C995' },
              { label: 'Critical', value: findings.filter(f => f.severity === 'critical').length, color: '#F28B82' },
              { label: 'In KEV', value: findings.filter(f => f.in_kev).length, color: '#F28B82' },
              { label: 'Attack Paths', value: attackPaths.length, color: '#FFAB40' },
            ].map(({ label, value, color }) => (
              <div key={label} className="px-4 py-3 text-center" style={{ background: 'var(--bg-main)' }}>
                <p className="text-lg font-mono" style={{ color }}>{value}</p>
                <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{label}</p>
              </div>
            ))}
          </div>
        )}

        {/* Tabs */}
        <TabBar tabs={tabs as any} active={activeTab} onChange={id => setActiveTab(id as any)} />

        {/* Tab content */}
        <div className="flex-1 overflow-y-auto">
          {loading && !scan ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="w-6 h-6 animate-spin" style={{ color: 'var(--text-tertiary)' }} />
            </div>
          ) : error ? (
            <div className="m-6 p-4 rounded-lg text-sm" style={{ background: 'rgba(242,139,130,0.06)', border: '1px solid rgba(242,139,130,0.2)', color: '#F28B82' }}>
              {error}
            </div>
          ) : (
            <>
              {/* ── Assets Tab ──────────────────────────────────────────── */}
              {activeTab === 'assets' && (
                <div>
                  {assets.length === 0 ? (
                    <div className="empty-state">
                      <Globe className="w-10 h-10 mb-3" style={{ color: 'var(--border-medium)' }} />
                      <h3>No assets recorded</h3>
                      <p>This scan has not found any assets yet.</p>
                    </div>
                  ) : (
                    <table className="w-full">
                      <thead>
                        <tr style={{ borderBottom: '1px solid var(--border-light)', background: 'var(--bg-header)' }}>
                          {['Domain / Hostname', 'IP Address', 'Technologies', 'Open Ports', 'Org / Country'].map(h => (
                            <th key={h} className="px-4 py-2.5 text-left text-[10px] uppercase tracking-wider font-medium"
                              style={{ color: 'var(--text-tertiary)' }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {assets.map(a => <AssetRow key={a.id} asset={a} />)}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {/* ── Vulnerabilities Tab ─────────────────────────────────── */}
              {activeTab === 'vulnerabilities' && (
                <div className="p-5 space-y-2">
                  {findings.length === 0 ? (
                    <div className="empty-state">
                      <Shield className="w-10 h-10 mb-3" style={{ color: 'var(--border-medium)' }} />
                      <h3>No vulnerabilities</h3>
                      <p>{isRunning ? 'Vuln scan is still running…' : 'No security issues found for this scan.'}</p>
                    </div>
                  ) : (
                    <>
                      <div className="flex flex-wrap gap-2 pb-2">
                        {['critical', 'high', 'medium', 'low'].map(s => {
                          const cnt = findings.filter(f => f.severity === s).length;
                          if (!cnt) return null;
                          return (
                            <span key={s} className="text-xs px-3 py-1 rounded-full"
                              style={{ background: SEV_BG[s], color: SEV_COLOR[s], border: `1px solid ${SEV_COLOR[s]}30` }}>
                              {cnt} {s}
                            </span>
                          );
                        })}
                        {findings.filter(f => f.in_kev).length > 0 && (
                          <span className="text-xs px-3 py-1 rounded-full animate-pulse"
                            style={{ background: 'rgba(242,139,130,0.1)', color: '#F28B82', border: '1px solid rgba(242,139,130,0.3)' }}>
                            ⚠ {findings.filter(f => f.in_kev).length} in CISA KEV
                          </span>
                        )}
                      </div>
                      {findings.map(f => <FindingCard key={f.id} finding={f} onTriage={handleTriage} />)}
                    </>
                  )}
                </div>
              )}

              {/* ── Attack Paths Tab ────────────────────────────────────── */}
              {activeTab === 'attack-paths' && (
                <div className="p-5 space-y-3">
                  {attackPaths.length === 0 ? (
                    <div className="empty-state">
                      <AlertTriangle className="w-10 h-10 mb-3" style={{ color: 'var(--border-medium)' }} />
                      <h3>No attack paths</h3>
                      <p>Attack paths are generated from findings. Run a full scan to see correlated attack chains.</p>
                    </div>
                  ) : (
                    <>
                      <p className="text-xs pb-1" style={{ color: 'var(--text-tertiary)' }}>
                        {attackPaths.length} potential attack chain{attackPaths.length !== 1 ? 's' : ''} identified. KEV = confirmed global exploitation. Technique/impact steps are marked <span style={{ color: GRADE_COLOR.possible }}>possible</span>.
                      </p>
                      {attackPaths.map(path => <AttackPathCard key={path.id} path={path} />)}
                    </>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
