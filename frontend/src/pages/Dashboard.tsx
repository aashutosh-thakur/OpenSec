import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import AppLayout from '../components/AppLayout';
import {
  Globe, Shield, AlertTriangle, BarChart2,
  TrendingUp, Clock, CheckCircle, XCircle,
  Loader2, RefreshCw, ChevronRight, Zap
} from 'lucide-react';
import {
  fetchStats, fetchScans, fetchRiskSummary,
  type PlatformStats, type ScanJob, type RiskSummary,
  getApiError
} from '../api/client';

const SEV_COLOR: Record<string, string> = {
  critical: '#F28B82', high: '#FFAB40', medium: '#FDD663', low: '#81C995', info: '#A8C7FA',
};

const GRADE_COLOR: Record<string, string> = {
  A: '#81C995', B: '#A8C7FA', C: '#FDD663', D: '#FFAB40', F: '#F28B82',
};

function statusDot(s: string) {
  const c = s === 'done' ? '#81C995' : s === 'error' ? '#F28B82' : s === 'running' ? '#FDD663' : '#64748b';
  return <span className="inline-block w-1.5 h-1.5 rounded-full mr-1.5" style={{ background: c, boxShadow: s === 'running' ? `0 0 5px ${c}` : 'none' }} />;
}

function duration(scan: ScanJob) {
  if (!scan.started_at) return '—';
  const end = scan.completed_at ? new Date(scan.completed_at) : new Date();
  const sec = Math.round((end.getTime() - new Date(scan.started_at).getTime()) / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

// ─── Risk Gauge Mini ──────────────────────────────────────────────────────────

function MiniGauge({ score, grade }: { score: number; grade: string }) {
  const color = GRADE_COLOR[grade] ?? '#aaa';
  const r = 30, cx = 40, cy = 40;
  const pct = Math.min(100, score);
  const circumference = Math.PI * r;
  const offset = circumference - (pct / 100) * circumference;

  return (
    <svg width="80" height="45" viewBox="0 0 80 45">
      <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
        fill="none" stroke="var(--border-medium)" strokeWidth="6" strokeLinecap="round" />
      <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
        fill="none" stroke={color} strokeWidth="6" strokeLinecap="round"
        strokeDasharray={circumference} strokeDashoffset={offset}
        style={{ filter: `drop-shadow(0 0 4px ${color}50)` }} />
      <text x={cx} y={cy - 4} textAnchor="middle" fill={color} fontSize="14" fontWeight="600" fontFamily="monospace">
        {grade}
      </text>
    </svg>
  );
}

// ─── Stat Card ────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, icon: Icon, color, href }: {
  label: string; value: number | string; sub?: string;
  icon: typeof Globe; color: string; href?: string;
}) {
  const inner = (
    <div className="p-5 rounded-2xl flex items-start justify-between group"
      style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-light)', transition: 'border-color 0.2s' }}
      onMouseEnter={e => href && (e.currentTarget.style.borderColor = `${color}40`)}
      onMouseLeave={e => href && (e.currentTarget.style.borderColor = 'var(--border-light)')}>
      <div>
        <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>{label}</p>
        <p className="text-3xl font-mono font-light" style={{ color }}>{value}</p>
        {sub && <p className="text-[11px] mt-1" style={{ color: 'var(--text-muted)' }}>{sub}</p>}
      </div>
      <div className="p-2.5 rounded-xl" style={{ background: `${color}12` }}>
        <Icon className="w-4 h-4" style={{ color }} />
      </div>
    </div>
  );
  return href ? <Link to={href} className="block">{inner}</Link> : <div>{inner}</div>;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const [stats, setStats] = useState<PlatformStats | null>(null);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [riskSummary, setRiskSummary] = useState<RiskSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const load = async () => {
    try {
      const [statsData, scansData, riskData] = await Promise.allSettled([
        fetchStats(),
        fetchScans({ limit: 8 }),
        fetchRiskSummary(),
      ]);
      if (statsData.status === 'fulfilled') setStats(statsData.value);
      if (scansData.status === 'fulfilled') setScans(scansData.value);
      if (riskData.status === 'fulfilled') setRiskSummary(riskData.value);
      setError(null);
      setLastUpdated(new Date());
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  // Auto-refresh if any scan is running
  useEffect(() => {
    const hasRunning = scans.some(s => s.status === 'running' || s.status === 'pending');
    if (!hasRunning) return;
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [scans]);

  const hasRunning = scans.some(s => s.status === 'running' || s.status === 'pending');

  return (
    <AppLayout>
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

        {/* Header */}
        <header className="h-14 shrink-0 flex items-center justify-between px-6"
          style={{ borderBottom: '1px solid var(--border-light)', background: 'var(--bg-header)' }}>
          <div>
            <h1 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Dashboard</h1>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              Platform overview{lastUpdated && ` · Updated ${lastUpdated.toLocaleTimeString()}`}
              {hasRunning && <span className="ml-2 text-yellow-400 animate-pulse">· Scan running…</span>}
            </p>
          </div>
          <button onClick={load} className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg"
            style={{ color: 'var(--text-tertiary)', border: '1px solid var(--border-light)' }}>
            {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
            Refresh
          </button>
        </header>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">

          {error && (
            <div className="p-3 rounded-lg text-sm" style={{ background: 'rgba(242,139,130,0.06)', border: '1px solid rgba(242,139,130,0.2)', color: '#F28B82' }}>
              {error}
            </div>
          )}

          {/* ── Main stats grid ──────────────────────────────────────── */}
          <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
            <StatCard label="Total Assets"  value={stats?.total_assets ?? '—'}    sub={`${stats?.internet_facing_assets ?? 0} internet-facing`} icon={Globe}          color="#A8C7FA" href="/attack-surface" />
            <StatCard label="Total Scans"   value={stats?.total_scans ?? '—'}      sub={`${stats?.running_scans ?? 0} running`}          icon={BarChart2}       color="#81C995" href="/scans" />
            <StatCard label="Domains"       value={stats?.unique_domains ?? '—'}   sub={`${stats?.unique_ips ?? 0} unique IPs`}          icon={Globe}           color="#FDD663" href="/attack-surface" />
            <StatCard label="Open Ports"    value={stats?.unique_ports ?? '—'}     sub="across all assets"                                icon={Zap}             color="#FFAB40" href="/attack-surface" />
          </div>

          {/* ── Risk Overview + Recent Scans ─────────────────────────── */}
          <div className="grid gap-4" style={{ gridTemplateColumns: '320px 1fr' }}>

            {/* Risk Overview */}
            <div className="rounded-2xl overflow-hidden" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-light)' }}>
              <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border-light)' }}>
                <p className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>Risk Overview</p>
                <Shield className="w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />
              </div>

              {!riskSummary || riskSummary.total_scans_scored === 0 ? (
                <div className="p-6 text-center">
                  <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>No risk scores yet.</p>
                  <p className="text-[10px] mt-1" style={{ color: 'var(--text-muted)' }}>Complete a full scan to generate risk scores.</p>
                </div>
              ) : (
                <div className="p-4 space-y-4">
                  {/* Avg + grade distribution */}
                  <div className="flex items-center gap-3">
                    <div className="text-center">
                      <p className="text-3xl font-mono font-light" style={{ color: GRADE_COLOR[riskSummary.latest_scores?.[0]?.grade ?? 'F'] ?? '#aaa' }}>
                        {riskSummary.average_score?.toFixed(0) ?? '—'}
                      </p>
                      <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>Avg Risk Score</p>
                    </div>
                    <div className="flex-1 space-y-1.5">
                      {Object.entries(riskSummary.grade_distribution)
                        .sort(([a], [b]) => a.localeCompare(b))
                        .map(([grade, count]) => (
                          <div key={grade} className="flex items-center gap-2">
                            <span className="text-[10px] font-mono w-4" style={{ color: GRADE_COLOR[grade] }}>{grade}</span>
                            <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border-light)' }}>
                              <div className="h-full rounded-full" style={{
                                width: `${(count / riskSummary.total_scans_scored) * 100}%`,
                                background: GRADE_COLOR[grade],
                              }} />
                            </div>
                            <span className="text-[10px] font-mono" style={{ color: 'var(--text-tertiary)' }}>{count}</span>
                          </div>
                        ))}
                    </div>
                  </div>

                  {/* Worst / Best */}
                  {riskSummary.worst_score && (
                    <div className="p-2.5 rounded-lg" style={{ background: 'rgba(242,139,130,0.05)', border: '1px solid rgba(242,139,130,0.15)' }}>
                      <p className="text-[9px] uppercase tracking-wider mb-1" style={{ color: '#F28B82' }}>Highest Risk</p>
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium truncate" style={{ color: 'var(--text-primary)' }}>{riskSummary.worst_score.target}</span>
                        <span className="font-mono text-sm ml-2 shrink-0" style={{ color: '#F28B82' }}>
                          {riskSummary.worst_score.score} ({riskSummary.worst_score.grade})
                        </span>
                      </div>
                    </div>
                  )}
                  {riskSummary.best_score && riskSummary.best_score.scan_id !== riskSummary.worst_score?.scan_id && (
                    <div className="p-2.5 rounded-lg" style={{ background: 'rgba(129,201,149,0.05)', border: '1px solid rgba(129,201,149,0.15)' }}>
                      <p className="text-[9px] uppercase tracking-wider mb-1" style={{ color: '#81C995' }}>Lowest Risk</p>
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium truncate" style={{ color: 'var(--text-primary)' }}>{riskSummary.best_score.target}</span>
                        <span className="font-mono text-sm ml-2 shrink-0" style={{ color: '#81C995' }}>
                          {riskSummary.best_score.score} ({riskSummary.best_score.grade})
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Latest scores */}
                  <div className="space-y-1.5">
                    <p className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>Recent Scans</p>
                    {riskSummary.latest_scores.map(s => (
                      <Link key={s.scan_id} to={`/scans/${s.scan_id}/risk`}
                        className="flex items-center gap-2 px-2 py-1.5 rounded-lg transition-colors"
                        style={{ color: 'var(--text-secondary)' }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'var(--border-light)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                        <MiniGauge score={s.score} grade={s.grade} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs truncate" style={{ color: 'var(--text-primary)' }}>{s.target}</p>
                          <p className="text-[10px] font-mono" style={{ color: GRADE_COLOR[s.grade] }}>Score: {s.score}</p>
                        </div>
                        <ChevronRight className="w-3 h-3 shrink-0" style={{ color: 'var(--text-tertiary)' }} />
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Recent Scans */}
            <div className="rounded-2xl overflow-hidden" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-light)' }}>
              <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border-light)' }}>
                <p className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>Recent Scans</p>
                <Link to="/scans" className="text-[10px]" style={{ color: '#A8C7FA' }}>View all</Link>
              </div>
              <div className="divide-y" style={{ borderColor: 'var(--border-light)' }}>
                {scans.length === 0 ? (
                  <div className="p-6 text-center">
                    <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>No scans yet.</p>
                    <Link to="/attack-surface" className="text-xs mt-1 block" style={{ color: '#A8C7FA' }}>Start a scan →</Link>
                  </div>
                ) : (
                  scans.map(scan => (
                    <Link key={scan.id} to={`/scans/${scan.id}`}
                      className="flex items-center gap-3 px-4 py-3 transition-colors"
                      onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.02)')}
                      onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5 mb-0.5">
                          {statusDot(scan.status)}
                          <span className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>{scan.target}</span>
                          <span className="text-[10px] font-mono ml-auto shrink-0" style={{ color: 'var(--text-muted)' }}>#{scan.id}</span>
                        </div>
                        <div className="flex items-center gap-3 text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
                          <span>{scan.started_at ? new Date(scan.started_at).toLocaleDateString() : '—'}</span>
                          <span>{duration(scan)}</span>
                          {scan.assets_found > 0 && <span className="flex items-center gap-1"><Globe className="w-2.5 h-2.5" />{scan.assets_found} assets</span>}
                          {scan.findings_count > 0 && <span className="flex items-center gap-1" style={{ color: '#FFAB40' }}><Shield className="w-2.5 h-2.5" />{scan.findings_count} findings</span>}
                        </div>
                      </div>
                      <ChevronRight className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--text-tertiary)' }} />
                    </Link>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* ── Quick Actions ────────────────────────────────────────── */}
          <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
            {[
              { label: 'New Scan',          desc: 'Discover assets & vulnerabilities', href: '/attack-surface', color: '#A8C7FA', icon: Zap },
              { label: 'Vulnerabilities',   desc: 'Review & triage findings',          href: '/vulnerabilities', color: '#FFAB40', icon: AlertTriangle },
              { label: 'Attack Surfaces',   desc: 'View all monitored assets',         href: '/attack-surface',  color: '#81C995', icon: Globe },
              { label: 'Reports',           desc: 'Export & download scan reports',    href: '/reports',         color: '#FDD663', icon: BarChart2 },
            ].map(({ label, desc, href, color, icon: Icon }) => (
              <Link key={label} to={href}
                className="p-4 rounded-2xl flex items-start gap-3 transition-all"
                style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-light)' }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = `${color}40`; e.currentTarget.style.background = `${color}06`; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-light)'; e.currentTarget.style.background = 'var(--bg-panel)'; }}>
                <div className="p-2 rounded-lg shrink-0" style={{ background: `${color}12` }}>
                  <Icon className="w-4 h-4" style={{ color }} />
                </div>
                <div>
                  <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{label}</p>
                  <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{desc}</p>
                </div>
              </Link>
            ))}
          </div>

        </div>
      </div>
    </AppLayout>
  );
}
