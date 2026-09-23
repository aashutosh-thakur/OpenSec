import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import AppLayout from '../components/AppLayout';
import {
  ArrowLeft, RefreshCw, Loader2, Shield,
  AlertTriangle, CheckCircle, XCircle, Target,
  BarChart2, ChevronRight, RotateCcw
} from 'lucide-react';
import {
  fetchRiskScore, recalculateRisk,
  type RiskScore, getApiError
} from '../api/client';

// ─── Constants ────────────────────────────────────────────────────────────────

const GRADE_CONFIG = {
  A: { color: '#81C995', bg: 'rgba(129,201,149,0.1)', label: 'Excellent', desc: 'Low risk. Strong security posture.' },
  B: { color: '#A8C7FA', bg: 'rgba(168,199,250,0.1)', label: 'Good',      desc: 'Minor issues found. Some attention needed.' },
  C: { color: '#FDD663', bg: 'rgba(253,214,99,0.1)',  label: 'Fair',      desc: 'Moderate risk. Issues require remediation.' },
  D: { color: '#FFAB40', bg: 'rgba(255,171,64,0.1)',  label: 'Poor',      desc: 'High risk. Significant vulnerabilities present.' },
  F: { color: '#F28B82', bg: 'rgba(242,139,130,0.1)', label: 'Critical',  desc: 'Critical risk. Immediate action required.' },
} as const;

const OWASP_SHORT: Record<string, string> = {
  'A01:Broken Access Control':               'A01 · Broken Access Control',
  'A02:Cryptographic Failures':              'A02 · Cryptographic Failures',
  'A03:Injection':                           'A03 · Injection',
  'A04:Insecure Design':                     'A04 · Insecure Design',
  'A05:Security Misconfiguration':           'A05 · Security Misconfiguration',
  'A06:Vulnerable and Outdated Components':  'A06 · Vulnerable Components',
  'A07:Identification and Authentication Failures': 'A07 · Auth Failures',
  'A08:Software and Data Integrity Failures':'A08 · Data Integrity Failures',
  'A09:Security Logging and Monitoring Failures':   'A09 · Logging Failures',
  'A10:Server-Side Request Forgery':         'A10 · SSRF',
};

// ─── Risk Gauge ───────────────────────────────────────────────────────────────

function RiskGauge({ score, grade }: { score: number; grade: string }) {
  const cfg = GRADE_CONFIG[grade as keyof typeof GRADE_CONFIG] ?? GRADE_CONFIG.F;
  const pct = Math.min(100, score);
  // SVG arc gauge
  const r = 70, cx = 90, cy = 90;
  const circumference = Math.PI * r; // half circle
  const strokeDasharray = circumference;
  const strokeDashoffset = circumference - (pct / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <svg width="180" height="100" viewBox="0 0 180 100">
        {/* Background track */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none" stroke="var(--border-medium)" strokeWidth="12" strokeLinecap="round"
        />
        {/* Score arc */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke={cfg.color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={strokeDasharray}
          strokeDashoffset={strokeDashoffset}
          style={{ transition: 'stroke-dashoffset 1s ease', filter: `drop-shadow(0 0 6px ${cfg.color}60)` }}
        />
        {/* Score text */}
        <text x={cx} y={cy - 12} textAnchor="middle" fill={cfg.color} fontSize="32" fontWeight="200" fontFamily="monospace">
          {Math.round(score)}
        </text>
        <text x={cx} y={cy + 4} textAnchor="middle" fill="var(--text-tertiary)" fontSize="9">
          / 100
        </text>
        {/* Grade badge */}
        <text x={cx} y={cy + 20} textAnchor="middle" fill={cfg.color} fontSize="22" fontWeight="600">
          {grade}
        </text>
      </svg>
      <p className="text-xs font-medium mt-1" style={{ color: cfg.color }}>{cfg.label}</p>
      <p className="text-[10px] text-center mt-0.5 max-w-[160px]" style={{ color: 'var(--text-tertiary)' }}>{cfg.desc}</p>
    </div>
  );
}

// ─── Score Bar ────────────────────────────────────────────────────────────────

function ScoreBar({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  return (
    <div className="space-y-1">
      <div className="flex justify-between items-center">
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{label}</span>
        <span className="text-xs font-mono" style={{ color }}>{value.toFixed(1)} / {max}</span>
      </div>
      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border-light)' }}>
        <div
          className="h-full rounded-full transition-all duration-1000"
          style={{ width: `${(value / max) * 100}%`, background: color, boxShadow: `0 0 6px ${color}60` }}
        />
      </div>
    </div>
  );
}

// ─── OWASP Row ────────────────────────────────────────────────────────────────

function OwaspRow({ cat, data }: { cat: string; data: { findings: number; critical: number; high: number; status: string } }) {
  const label = OWASP_SHORT[cat] ?? cat;
  const isVuln = data.status === 'vulnerable';
  return (
    <div className="flex items-center gap-3 py-2.5 px-3 rounded-lg" style={{
      background: isVuln ? `rgba(242,139,130,0.04)` : 'transparent',
      border: `1px solid ${isVuln ? 'rgba(242,139,130,0.12)' : 'var(--border-light)'}`,
    }}>
      <div className="w-5 h-5 rounded flex items-center justify-center shrink-0"
        style={{ background: isVuln ? 'rgba(242,139,130,0.15)' : 'rgba(129,201,149,0.1)' }}>
        {isVuln
          ? <XCircle className="w-3 h-3" style={{ color: '#F28B82' }} />
          : <CheckCircle className="w-3 h-3" style={{ color: '#81C995' }} />}
      </div>
      <span className="flex-1 text-xs" style={{ color: isVuln ? 'var(--text-primary)' : 'var(--text-tertiary)' }}>{label}</span>
      {isVuln && (
        <div className="flex items-center gap-1.5 shrink-0">
          {data.critical > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(242,139,130,0.1)', color: '#F28B82' }}>{data.critical} crit</span>}
          {data.high > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(255,171,64,0.1)', color: '#FFAB40' }}>{data.high} high</span>}
          <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{data.findings} total</span>
        </div>
      )}
      {!isVuln && <span className="text-[10px] shrink-0" style={{ color: 'var(--text-muted)' }}>Not Detected</span>}
    </div>
  );
}

// ─── Compliance Table ─────────────────────────────────────────────────────────

function ComplianceTable({ title, data, color }: {
  title: string;
  data: Record<string, { findings: number; status: string }>;
  color: string;
}) {
  const entries = Object.entries(data);
  if (!entries.length) {
    return (
      <div className="p-4 rounded-xl" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-light)' }}>
        <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{title}</p>
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>No gaps identified ✓</p>
      </div>
    );
  }
  return (
    <div className="p-4 rounded-xl" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-light)' }}>
      <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{title}</p>
      <div className="space-y-2">
        {entries.map(([ctrl, d]) => (
          <div key={ctrl} className="flex items-center gap-2 text-xs">
            <div className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: color }} />
            <span className="flex-1" style={{ color: 'var(--text-secondary)' }}>{ctrl}</span>
            <span className="shrink-0 font-mono" style={{ color }}>{d.findings}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Port Exposure ────────────────────────────────────────────────────────────

const HIGH_RISK_PORTS: Record<number, string> = {
  3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB',
  6379: 'Redis', 9200: 'Elasticsearch', 11211: 'Memcached',
  5984: 'CouchDB', 1433: 'MSSQL', 1521: 'Oracle',
  2181: 'Zookeeper', 5900: 'VNC', 23: 'Telnet',
  3389: 'RDP', 61616: 'ActiveMQ', 8161: 'ActiveMQ Admin',
};

function PortExposure({ ports, highRisk }: { ports: number[]; highRisk: number[] }) {
  if (!ports.length) return <p className="text-xs" style={{ color: 'var(--text-muted)' }}>No open ports detected</p>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {ports.map(p => {
        const isRisk = highRisk.includes(p);
        const svc = HIGH_RISK_PORTS[p];
        return (
          <div key={p} className="flex items-center gap-1 px-2 py-1 rounded text-[11px] font-mono"
            style={{
              background: isRisk ? 'rgba(242,139,130,0.08)' : 'var(--border-light)',
              border: `1px solid ${isRisk ? 'rgba(242,139,130,0.25)' : 'var(--border-light)'}`,
              color: isRisk ? '#F28B82' : 'var(--text-secondary)',
            }}>
            {p}{svc ? ` (${svc})` : ''}
            {isRisk && <AlertTriangle className="w-2.5 h-2.5 ml-0.5" />}
          </div>
        );
      })}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function RiskPage() {
  const { id } = useParams<{ id: string }>();
  const scanId = id ? Number(id) : null;

  const [risk, setRisk] = useState<RiskScore | null>(null);
  const [loading, setLoading] = useState(true);
  const [recalculating, setRecalculating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'overview' | 'owasp' | 'cis_nist' | 'exposure'>('overview');

  const load = async () => {
    if (!scanId) return;
    setLoading(true);
    try {
      const data = await fetchRiskScore(scanId);
      setRisk(data);
      setError(null);
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [scanId]);

  const handleRecalculate = async () => {
    if (!scanId) return;
    setRecalculating(true);
    try {
      await recalculateRisk(scanId);
      await load();
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setRecalculating(false);
    }
  };

  const tabs = [
    { id: 'overview',  label: 'Score Overview' },
    { id: 'owasp',     label: 'OWASP Top 10' },
    { id: 'cis_nist',  label: 'CIS / NIST' },
    { id: 'exposure',  label: 'Exposure' },
  ] as const;

  return (
    <AppLayout>
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

        {/* Header */}
        <header className="h-14 shrink-0 flex items-center gap-3 px-6"
          style={{ borderBottom: '1px solid var(--border-light)', background: 'var(--bg-header)' }}>
          <Link to={`/scans/${scanId}`} className="flex items-center gap-1.5 text-xs transition-colors"
            style={{ color: 'var(--text-tertiary)' }}>
            <ArrowLeft className="w-3.5 h-3.5" /> Scan Report
          </Link>
          <span style={{ color: 'var(--border-medium)' }}>/</span>
          <div className="flex-1">
            <h1 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
              Risk & Compliance
            </h1>
            <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
              OWASP Top 10 · CIS Controls · NIST CSF · Exposure Analysis
            </p>
          </div>
          <div className="flex gap-2">
            <button onClick={handleRecalculate} disabled={recalculating}
              className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg"
              style={{ background: 'rgba(168,199,250,0.08)', color: '#A8C7FA', border: '1px solid rgba(168,199,250,0.15)' }}>
              {recalculating ? <Loader2 className="w-3 h-3 animate-spin" /> : <RotateCcw className="w-3 h-3" />}
              Recalculate
            </button>
            <button onClick={load} className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg"
              style={{ color: 'var(--text-tertiary)', border: '1px solid var(--border-light)' }}>
              <RefreshCw className="w-3 h-3" />
            </button>
          </div>
        </header>

        {/* Tabs */}
        <div className="flex gap-1 px-6 shrink-0" style={{ borderBottom: '1px solid var(--border-light)' }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className="px-3 py-2.5 text-xs font-medium transition-all"
              style={{
                color: tab === t.id ? 'var(--text-primary)' : 'var(--text-tertiary)',
                borderBottom: tab === t.id ? '2px solid #A8C7FA' : '2px solid transparent',
                marginBottom: -1,
              }}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {loading ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="w-6 h-6 animate-spin" style={{ color: 'var(--text-tertiary)' }} />
            </div>
          ) : error ? (
            <div className="p-4 rounded-lg text-sm" style={{ background: 'rgba(242,139,130,0.06)', border: '1px solid rgba(242,139,130,0.2)', color: '#F28B82' }}>
              {error}
            </div>
          ) : !risk || !risk.score ? (
            <div className="empty-state">
              <Shield className="w-10 h-10 mb-3" style={{ color: 'var(--border-medium)' }} />
              <h3>No risk score yet</h3>
              <p>Complete a full scan to generate a risk score and compliance report.</p>
            </div>
          ) : (
            <>
              {/* ── Overview ───────────────────────────────────────────── */}
              {tab === 'overview' && (
                <div className="grid gap-6" style={{ gridTemplateColumns: '280px 1fr' }}>
                  {/* Gauge */}
                  <div className="p-6 rounded-2xl flex flex-col items-center gap-4"
                    style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-light)' }}>
                    <RiskGauge score={risk.score} grade={risk.grade} />
                    <div className="w-full space-y-3 pt-2" style={{ borderTop: '1px solid var(--border-light)' }}>
                      <p className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>Score Components</p>
                      <ScoreBar label="Vulnerability" value={risk.components.vulnerability} max={50} color="#F28B82" />
                      <ScoreBar label="KEV Penalty"   value={risk.components.kev_penalty}    max={20} color="#FFAB40" />
                      <ScoreBar label="Exposure"      value={risk.components.exposure}        max={15} color="#FDD663" />
                      <ScoreBar label="Hygiene"       value={risk.components.hygiene}         max={15} color="#A8C7FA" />
                    </div>
                  </div>

                  {/* Stats grid */}
                  <div className="space-y-4">
                    {/* Quick stats */}
                    <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
                      {[
                        { label: 'Total Findings',  value: risk.breakdown.findings_total,    color: 'var(--text-primary)' },
                        { label: 'Critical',         value: risk.breakdown.findings_critical,  color: '#F28B82' },
                        { label: 'High',             value: risk.breakdown.findings_high,      color: '#FFAB40' },
                        { label: 'Medium',           value: risk.breakdown.findings_medium,    color: '#FDD663' },
                        { label: 'In CISA KEV',      value: risk.breakdown.findings_kev,       color: '#F28B82' },
                        { label: 'OWASP Categories', value: risk.breakdown.owasp_categories_affected, color: '#A8C7FA' },
                      ].map(({ label, value, color }) => (
                        <div key={label} className="p-4 rounded-xl"
                          style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-light)' }}>
                          <p className="text-2xl font-mono font-light" style={{ color }}>{value}</p>
                          <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{label}</p>
                        </div>
                      ))}
                    </div>

                    {/* High-risk ports alert */}
                    {risk.breakdown.high_risk_ports_open?.length > 0 && (
                      <div className="p-4 rounded-xl" style={{ background: 'rgba(242,139,130,0.04)', border: '1px solid rgba(242,139,130,0.2)' }}>
                        <div className="flex items-center gap-2 mb-2">
                          <AlertTriangle className="w-4 h-4" style={{ color: '#F28B82' }} />
                          <p className="text-sm font-medium" style={{ color: '#F28B82' }}>High-Risk Ports Exposed to Internet</p>
                        </div>
                        <p className="text-xs mb-3" style={{ color: 'var(--text-secondary)' }}>
                          These services should NOT be publicly accessible. Restrict with firewall rules immediately.
                        </p>
                        <PortExposure ports={risk.breakdown.high_risk_ports_open} highRisk={risk.breakdown.high_risk_ports_open} />
                      </div>
                    )}

                    {/* Calculated at */}
                    {risk.calculated_at && (
                      <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
                        Score calculated: {new Date(risk.calculated_at).toLocaleString()}
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* ── OWASP Top 10 ───────────────────────────────────────── */}
              {tab === 'owasp' && (
                <div className="space-y-2 max-w-3xl">
                  <p className="text-xs mb-4" style={{ color: 'var(--text-tertiary)' }}>
                    OWASP Top 10 2021 coverage based on detected findings.
                    {' '}<span style={{ color: '#F28B82' }}>Red</span> = vulnerable, <span style={{ color: '#81C995' }}>Green</span> = not detected.
                  </p>
                  {Object.entries(risk.owasp_coverage).map(([cat, data]) => (
                    <OwaspRow key={cat} cat={cat} data={data} />
                  ))}
                </div>
              )}

              {/* ── CIS / NIST ─────────────────────────────────────────── */}
              {tab === 'cis_nist' && (
                <div className="grid gap-6 max-w-4xl" style={{ gridTemplateColumns: '1fr 1fr' }}>
                  <ComplianceTable title="CIS Controls — Gaps Identified" data={risk.cis_coverage} color="#FFAB40" />
                  <ComplianceTable title="NIST CSF — Functions Affected" data={risk.nist_coverage} color="#A8C7FA" />
                </div>
              )}

              {/* ── Exposure ───────────────────────────────────────────── */}
              {tab === 'exposure' && (
                <div className="space-y-6 max-w-3xl">
                  <div className="p-4 rounded-xl" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-light)' }}>
                    <p className="text-xs font-semibold mb-3 uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>All Open Ports</p>
                    <PortExposure ports={risk.breakdown.open_ports} highRisk={risk.breakdown.high_risk_ports_open} />
                  </div>
                  <div className="p-4 rounded-xl" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-light)' }}>
                    <p className="text-xs font-semibold mb-3 uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>Exposure Scoring Explanation</p>
                    <div className="space-y-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
                      <p>· <strong style={{ color: 'var(--text-primary)' }}>+4 pts</strong> per high-risk database/service port exposed (Redis, MongoDB, RDP, etc.)</p>
                      <p>· <strong style={{ color: 'var(--text-primary)' }}>+0.5 pts</strong> per non-standard port open (not 80/443/22)</p>
                      <p>· Exposure score is capped at <strong style={{ color: 'var(--text-primary)' }}>15 points</strong> (contributes to overall risk score)</p>
                      <p>· <strong style={{ color: '#F28B82' }}>Your exposure score: {risk.components.exposure.toFixed(1)} / 15</strong></p>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
