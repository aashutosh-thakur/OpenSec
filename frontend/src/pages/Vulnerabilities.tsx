import { useState, useEffect, useCallback } from 'react';
import AppLayout from '../components/AppLayout';
import {
  AlertTriangle, Shield, CheckCircle, XCircle,
  Clock, Loader2, RefreshCw, Filter, ExternalLink,
  ChevronDown, ChevronUp, Flag, Eye
} from 'lucide-react';
import {
  fetchFindings, fetchFindingsSummary, triageFinding,
  type Finding, type FindingSummary, getApiError
} from '../api/client';

// ─── Severity Config ──────────────────────────────────────────────────────────

const SEV_CONFIG = {
  critical: { color: '#F28B82', bg: 'rgba(242,139,130,0.1)', border: 'rgba(242,139,130,0.2)', label: 'Critical' },
  high:     { color: '#FFAB40', bg: 'rgba(255,171,64,0.1)',  border: 'rgba(255,171,64,0.2)',  label: 'High' },
  medium:   { color: '#FDD663', bg: 'rgba(253,214,99,0.1)',  border: 'rgba(253,214,99,0.2)',  label: 'Medium' },
  low:      { color: '#81C995', bg: 'rgba(129,201,149,0.1)', border: 'rgba(129,201,149,0.2)', label: 'Low' },
  info:     { color: '#A8C7FA', bg: 'rgba(168,199,250,0.1)', border: 'rgba(168,199,250,0.2)', label: 'Info' },
} as const;

const GRADE_CONFIG = {
  confirmed: { color: '#81C995', label: 'Confirmed' },
  supported: { color: '#FDD663', label: 'Supported' },
  possible:  { color: '#A8C7FA', label: 'Possible' },
} as const;

const TRIAGE_CONFIG = {
  open:           { color: 'var(--text-tertiary)', label: 'Open' },
  confirmed_real: { color: '#F28B82', label: 'Confirmed Real' },
  false_positive: { color: '#81C995', label: 'False Positive' },
  accepted_risk:  { color: '#FDD663', label: 'Accepted Risk' },
} as const;

// ─── Summary Bar ──────────────────────────────────────────────────────────────

function SummaryBar({ summary }: { summary: FindingSummary }) {
  const stats = [
    { label: 'Total', value: summary.total, color: 'var(--text-primary)' },
    { label: 'Critical', value: summary.critical, color: SEV_CONFIG.critical.color },
    { label: 'High', value: summary.high, color: SEV_CONFIG.high.color },
    { label: 'Medium', value: summary.medium, color: SEV_CONFIG.medium.color },
    { label: 'Low', value: summary.low, color: SEV_CONFIG.low.color },
    { label: 'In KEV', value: summary.in_kev, color: '#F28B82' },
    { label: 'Triaged', value: summary.triaged, color: '#81C995' },
  ];
  return (
    <div
      className="grid gap-px shrink-0"
      style={{
        gridTemplateColumns: `repeat(${stats.length}, 1fr)`,
        background: 'var(--border-light)',
        borderBottom: '1px solid var(--border-light)',
      }}
    >
      {stats.map(({ label, value, color }) => (
        <div key={label} className="flex flex-col px-4 py-3" style={{ background: 'var(--bg-main)' }}>
          <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{label}</p>
          <p className="text-xl font-mono font-light leading-tight" style={{ color }}>
            {value}
          </p>
        </div>
      ))}
    </div>
  );
}

// ─── Finding Card ─────────────────────────────────────────────────────────────

function FindingCard({
  finding,
  onTriage,
}: {
  finding: Finding;
  onTriage: (f: Finding) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const sev = SEV_CONFIG[finding.severity] ?? SEV_CONFIG.info;
  const grade = GRADE_CONFIG[finding.grade] ?? GRADE_CONFIG.possible;
  const triage = TRIAGE_CONFIG[finding.triage_status] ?? TRIAGE_CONFIG.open;

  return (
    <div
      className="rounded-xl overflow-hidden"
      style={{ background: 'var(--bg-panel)', border: `1px solid ${sev.border}` }}
    >
      {/* Header */}
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
        style={{ borderLeft: `3px solid ${sev.color}` }}
      >
        {/* Severity */}
        <span
          className="text-[10px] font-mono px-2 py-1 rounded font-semibold shrink-0"
          style={{ background: sev.bg, color: sev.color, border: `1px solid ${sev.border}` }}
        >
          {sev.label.toUpperCase()}
        </span>

        {/* KEV badge */}
        {finding.in_kev && (
          <span
            className="text-[9px] font-mono px-1.5 py-0.5 rounded shrink-0 animate-pulse"
            style={{ background: 'rgba(242,139,130,0.15)', color: '#F28B82', border: '1px solid rgba(242,139,130,0.3)' }}
          >
            ⚠ KEV
          </span>
        )}

        {/* Priority */}
        {finding.priority && finding.priority !== 'STANDARD' && (
          <span
            className="text-[9px] font-mono px-1.5 py-0.5 rounded shrink-0"
            style={{
              background: finding.priority === 'URGENT' ? 'rgba(242,139,130,0.15)' : 'rgba(255,171,64,0.1)',
              color: finding.priority === 'URGENT' ? '#F28B82' : '#FFAB40',
              border: `1px solid ${finding.priority === 'URGENT' ? 'rgba(242,139,130,0.3)' : 'rgba(255,171,64,0.2)'}`,
            }}
          >
            {finding.priority}
          </span>
        )}

        {/* Title */}
        <p className="flex-1 text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
          {finding.title}
        </p>

        {/* Category */}
        {finding.category && (
          <span className="text-[10px] font-mono hidden lg:block shrink-0" style={{ color: 'var(--text-muted)' }}>
            {finding.category.split(':')[0]}
          </span>
        )}

        {/* Grade */}
        <span
          className="text-[10px] px-1.5 py-0.5 rounded shrink-0"
          style={{
            background: `${grade.color}15`,
            color: grade.color,
            border: `1px solid ${grade.color}25`,
          }}
        >
          {grade.label}
        </span>

        {/* Triage status */}
        <span className="text-[10px] shrink-0" style={{ color: triage.color }}>
          {triage.label}
        </span>

        {expanded ? (
          <ChevronUp className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--text-tertiary)' }} />
        ) : (
          <ChevronDown className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--text-tertiary)' }} />
        )}
      </div>

      {/* Expanded body */}
      {expanded && (
        <div className="px-5 pb-5 pt-3 space-y-4" style={{ borderTop: '1px solid var(--border-light)' }}>
          {/* Description */}
          {finding.description && (
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              {finding.description}
            </p>
          )}

          {/* CVE info row */}
          {finding.cve_id && (
            <div className="flex flex-wrap gap-3">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg"
                style={{
                  background: 'rgba(168,199,250,0.08)',
                  border: '1px solid rgba(168,199,250,0.2)',
                  color: '#A8C7FA',
                }}
              >
                <ExternalLink className="w-3 h-3" />
                {finding.cve_id}
              </a>
              {finding.cvss !== null && finding.cvss !== undefined && (
                <span className="flex items-center text-xs px-2 py-1 rounded"
                  style={{ background: 'var(--border-light)', color: 'var(--text-secondary)' }}>
                  CVSS: <span className="font-mono ml-1" style={{ color: finding.cvss >= 9 ? '#F28B82' : finding.cvss >= 7 ? '#FFAB40' : '#FDD663' }}>{finding.cvss.toFixed(1)}</span>
                </span>
              )}
              {finding.epss !== null && finding.epss !== undefined && (
                <span className="flex items-center text-xs px-2 py-1 rounded"
                  style={{ background: 'var(--border-light)', color: 'var(--text-secondary)' }}>
                  EPSS: <span className="font-mono ml-1" style={{ color: finding.epss >= 0.5 ? '#F28B82' : '#FDD663' }}>{(finding.epss * 100).toFixed(1)}%</span>
                </span>
              )}
              {finding.in_kev && (
                <a
                  href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-xs px-2 py-1 rounded"
                  style={{ background: 'rgba(242,139,130,0.1)', color: '#F28B82', border: '1px solid rgba(242,139,130,0.2)' }}
                >
                  <ExternalLink className="w-3 h-3" />
                  CISA KEV
                </a>
              )}
            </div>
          )}

          {/* Evidence */}
          {finding.evidence && Object.keys(finding.evidence).length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider mb-2" style={{ color: 'var(--text-tertiary)' }}>Evidence</p>
              <div
                className="p-3 rounded-lg text-[11px] font-mono leading-relaxed overflow-x-auto"
                style={{ background: 'var(--bg-main)', border: '1px solid var(--border-light)', color: 'var(--text-secondary)' }}
              >
                {JSON.stringify(finding.evidence, null, 2)}
              </div>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div
              className="p-3 rounded-lg"
              style={{ background: 'rgba(129,201,149,0.05)', border: '1px solid rgba(129,201,149,0.15)' }}
            >
              <p className="text-[10px] uppercase tracking-wider mb-1.5" style={{ color: '#81C995' }}>Remediation</p>
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{finding.remediation}</p>
            </div>
          )}

          {/* Triage note */}
          {finding.triage_note && (
            <div className="p-3 rounded-lg" style={{ background: 'var(--border-light)', border: '1px solid var(--border-medium)' }}>
              <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Triage Note</p>
              <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{finding.triage_note}</p>
            </div>
          )}

          {/* Triage actions */}
          <div className="flex items-center gap-2 pt-1">
            <p className="text-[10px] uppercase tracking-wider mr-1" style={{ color: 'var(--text-tertiary)' }}>Mark as:</p>
            {(['confirmed_real', 'false_positive', 'accepted_risk', 'open'] as const).map(status => (
              <button
                key={status}
                onClick={() => onTriage({ ...finding, triage_status: status })}
                className="text-[10px] px-2.5 py-1 rounded transition-all"
                style={{
                  background: finding.triage_status === status
                    ? `${TRIAGE_CONFIG[status].color}20`
                    : 'var(--border-light)',
                  color: finding.triage_status === status
                    ? TRIAGE_CONFIG[status].color
                    : 'var(--text-tertiary)',
                  border: `1px solid ${finding.triage_status === status ? TRIAGE_CONFIG[status].color + '40' : 'var(--border-light)'}`,
                  fontWeight: finding.triage_status === status ? 600 : 400,
                }}
              >
                {TRIAGE_CONFIG[status].label}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Triage Modal ─────────────────────────────────────────────────────────────

function TriageModal({
  finding,
  onClose,
  onConfirm,
}: {
  finding: Finding;
  onClose: () => void;
  onConfirm: (note: string) => void;
}) {
  const [note, setNote] = useState(finding.triage_note || '');
  const status = finding.triage_status;
  const cfg = TRIAGE_CONFIG[status];

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-md p-6 rounded-2xl"
        style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-medium)' }}
        onClick={e => e.stopPropagation()}
      >
        <h3 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>
          Triage Finding
        </h3>
        <p className="text-xs mb-4" style={{ color: 'var(--text-tertiary)' }}>
          Marking as <span style={{ color: cfg.color }}>{cfg.label}</span>: "{finding.title}"
        </p>
        <textarea
          className="w-full text-sm p-3 rounded-lg resize-none"
          rows={4}
          placeholder="Add a note explaining your decision (required for audit trail)..."
          value={note}
          onChange={e => setNote(e.target.value)}
          style={{
            background: 'var(--bg-main)',
            border: '1px solid var(--border-medium)',
            color: 'var(--text-primary)',
            outline: 'none',
          }}
          autoFocus
        />
        <div className="flex gap-2 mt-4">
          <button
            onClick={() => onConfirm(note)}
            className="flex-1 py-2 rounded-lg text-sm font-medium"
            style={{ background: cfg.color + '20', color: cfg.color, border: `1px solid ${cfg.color}40` }}
          >
            Confirm Triage
          </button>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm"
            style={{ background: 'var(--border-light)', color: 'var(--text-secondary)' }}
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function Vulnerabilities() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<FindingSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [triageFilter, setTriageFilter] = useState<string>('all');
  const [kevOnly, setKevOnly] = useState(false);
  const [pendingTriage, setPendingTriage] = useState<Finding | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const load = useCallback(async () => {
    try {
      const [findingsData, summaryData] = await Promise.all([
        fetchFindings({
          severity: severityFilter !== 'all' ? severityFilter : undefined,
          triage_status: triageFilter !== 'all' ? triageFilter : undefined,
          in_kev: kevOnly || undefined,
          limit: 200,
        }),
        fetchFindingsSummary(),
      ]);
      setFindings(findingsData);
      setSummary(summaryData);
      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      setError(getApiError(err));
    } finally {
      setLoading(false);
    }
  }, [severityFilter, triageFilter, kevOnly]);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  const handleTriage = (finding: Finding) => {
    setPendingTriage(finding);
  };

  const confirmTriage = async (note: string) => {
    if (!pendingTriage) return;
    try {
      const updated = await triageFinding(pendingTriage.id, pendingTriage.triage_status, note);
      setFindings(prev => prev.map(f => f.id === updated.id ? updated : f));
      if (summary) {
        setSummary({ ...summary });
      }
    } catch (e) {
      console.error('Triage failed:', e);
    }
    setPendingTriage(null);
  };

  return (
    <AppLayout>
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

        {/* Header */}
        <header
          className="h-14 shrink-0 flex items-center justify-between px-6"
          style={{ borderBottom: '1px solid var(--border-light)', background: 'var(--bg-header)' }}
        >
          <div>
            <h1 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
              Vulnerabilities
            </h1>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              VAPT findings across all scans · NVD + CISA KEV + EPSS
              {lastUpdated && ` · ${lastUpdated.toLocaleTimeString()}`}
            </p>
          </div>
          <button
            onClick={load}
            className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-md"
            style={{ color: 'var(--text-tertiary)', border: '1px solid var(--border-light)' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-primary)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-tertiary)')}
          >
            {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
            Refresh
          </button>
        </header>

        {/* Summary bar */}
        {summary && <SummaryBar summary={summary} />}

        {/* Filters */}
        <div
          className="shrink-0 flex items-center gap-3 px-6 py-3"
          style={{ borderBottom: '1px solid var(--border-light)', background: 'var(--bg-header)' }}
        >
          <Filter className="w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />

          {/* Severity filter */}
          <div className="flex gap-1">
            {['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className="text-[11px] px-2.5 py-1 rounded capitalize transition-all"
                style={{
                  background: severityFilter === s
                    ? (s === 'all' ? 'rgba(168,199,250,0.1)' : SEV_CONFIG[s as keyof typeof SEV_CONFIG]?.bg || 'rgba(168,199,250,0.1)')
                    : 'transparent',
                  color: severityFilter === s
                    ? (s === 'all' ? '#A8C7FA' : SEV_CONFIG[s as keyof typeof SEV_CONFIG]?.color || '#A8C7FA')
                    : 'var(--text-tertiary)',
                  border: `1px solid ${severityFilter === s ? 'rgba(168,199,250,0.2)' : 'transparent'}`,
                }}
              >
                {s}
              </button>
            ))}
          </div>

          <div className="w-px h-4 shrink-0" style={{ background: 'var(--border-light)' }} />

          {/* Triage filter */}
          <select
            value={triageFilter}
            onChange={e => setTriageFilter(e.target.value)}
            className="text-xs px-2 py-1 rounded"
            style={{
              background: 'var(--border-light)',
              border: '1px solid var(--border-medium)',
              color: 'var(--text-secondary)',
              outline: 'none',
            }}
          >
            <option value="all">All triage</option>
            <option value="open">Open</option>
            <option value="confirmed_real">Confirmed Real</option>
            <option value="false_positive">False Positive</option>
            <option value="accepted_risk">Accepted Risk</option>
          </select>

          {/* KEV filter */}
          <button
            onClick={() => setKevOnly(!kevOnly)}
            className="flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded transition-all"
            style={{
              background: kevOnly ? 'rgba(242,139,130,0.1)' : 'transparent',
              color: kevOnly ? '#F28B82' : 'var(--text-tertiary)',
              border: `1px solid ${kevOnly ? 'rgba(242,139,130,0.25)' : 'transparent'}`,
            }}
          >
            ⚠ KEV Only
          </button>

          <span className="ml-auto text-xs" style={{ color: 'var(--text-muted)' }}>
            {findings.length} finding{findings.length !== 1 ? 's' : ''}
          </span>
        </div>

        {/* Findings list */}
        <div className="flex-1 overflow-y-auto p-5 space-y-2">
          {loading && findings.length === 0 ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="w-6 h-6 animate-spin" style={{ color: 'var(--text-tertiary)' }} />
            </div>
          ) : error ? (
            <div className="p-4 rounded-lg text-sm" style={{ background: 'rgba(242,139,130,0.06)', border: '1px solid rgba(242,139,130,0.2)', color: '#F28B82' }}>
              {error}
            </div>
          ) : findings.length === 0 ? (
            <div className="empty-state">
              <Shield className="w-10 h-10 mb-3" style={{ color: 'var(--border-medium)' }} />
              <h3>No vulnerabilities found</h3>
              <p>
                {severityFilter !== 'all' || triageFilter !== 'all' || kevOnly
                  ? 'No findings match the current filters.'
                  : 'Run a full scan from the Scans page to start detecting vulnerabilities.'}
              </p>
            </div>
          ) : (
            findings.map(finding => (
              <FindingCard key={finding.id} finding={finding} onTriage={handleTriage} />
            ))
          )}
        </div>
      </div>

      {/* Triage modal */}
      {pendingTriage && (
        <TriageModal
          finding={pendingTriage}
          onClose={() => setPendingTriage(null)}
          onConfirm={confirmTriage}
        />
      )}
    </AppLayout>
  );
}
