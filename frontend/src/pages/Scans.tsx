import { useState, useEffect, useCallback } from 'react';
import AppLayout from '../components/AppLayout';
import {
  RefreshCw, Loader2, AlertTriangle, CheckCircle,
  Clock, Globe, X, Plus, ChevronRight
} from 'lucide-react';
import { fetchScans, type ScanJob, getApiError } from '../api/client';
import { Link } from 'react-router-dom';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ScanStatusBadge({ status }: { status: ScanJob['status'] }) {
  const styles: Record<ScanJob['status'], { cls: string; icon: typeof CheckCircle }> = {
    done:    { cls: 'badge badge-low',      icon: CheckCircle },
    running: { cls: 'badge badge-info',     icon: Loader2 },
    pending: { cls: 'badge badge-inactive', icon: Clock },
    error:   { cls: 'badge badge-critical', icon: AlertTriangle },
  };
  const { cls, icon: Icon } = styles[status];
  return (
    <span className={cls}>
      <Icon className={`w-2.5 h-2.5 ${status === 'running' ? 'animate-spin' : ''}`} />
      {status}
    </span>
  );
}

function parseTool(entry: string): { name: string; status: string } {
  const parts = entry.split(':');
  return { name: parts[0], status: parts[1] ?? 'ok' };
}

const TOOL_STATUS_COLOR: Record<string, string> = {
  ok:          '#81C995',
  unavailable: 'var(--text-tertiary)',
  error:       '#F28B82',
  timeout:     '#FDD663',
};

// ─── Scan Detail Panel ────────────────────────────────────────────────────────

function ScanDetailPanel({ scan, onClose }: { scan: ScanJob; onClose: () => void }) {
  const tools = (scan.tools ?? []).map(parseTool);
  const duration =
    scan.started_at && scan.completed_at
      ? Math.round(
          (new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000
        )
      : null;

  return (
    <div
      className="w-80 shrink-0 flex flex-col overflow-hidden"
      style={{
        borderLeft: '1px solid var(--border-light)',
        background: 'var(--bg-panel)',
      }}
    >
      <div
        className="flex items-center justify-between px-5 py-4"
        style={{ borderBottom: '1px solid var(--border-light)' }}
      >
        <h4 className="text-sm font-medium">Scan Details</h4>
        <button
          onClick={onClose}
          className="w-6 h-6 rounded flex items-center justify-center"
          style={{ color: 'var(--text-tertiary)' }}
          onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--border-light)')}
          onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        <div>
          <p className="text-xs mb-1" style={{ color: 'var(--text-tertiary)' }}>Target</p>
          <p className="text-sm font-mono">{scan.target}</p>
        </div>
        <div>
          <p className="text-xs mb-1" style={{ color: 'var(--text-tertiary)' }}>Status</p>
          <ScanStatusBadge status={scan.status} />
        </div>
        <div>
          <p className="text-xs mb-1" style={{ color: 'var(--text-tertiary)' }}>Assets Found</p>
          <p className="text-xl font-mono" style={{ color: '#81C995' }}>
            {scan.assets_found}
          </p>
        </div>

        {tools.length > 0 && (
          <div>
            <p className="text-xs mb-2" style={{ color: 'var(--text-tertiary)' }}>Tool Statuses</p>
            <div className="space-y-1.5">
              {tools.map(({ name, status }) => (
                <div key={name} className="flex items-center justify-between text-xs">
                  <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{name}</span>
                  <span className="font-medium" style={{ color: TOOL_STATUS_COLOR[status] ?? '#888' }}>
                    {status}
                  </span>
                </div>
              ))}
            </div>
            <p className="text-[10px] mt-2" style={{ color: 'var(--text-muted)' }}>
              "unavailable" = binary not installed. Install the tool and re-run the scan.
            </p>
          </div>
        )}

        {scan.error && (
          <div
            className="p-3 rounded-lg text-xs"
            style={{
              background: 'rgba(242,139,130,0.06)',
              border: '1px solid rgba(242,139,130,0.15)',
              color: '#F28B82',
            }}
          >
            <p className="font-medium mb-1">Error</p>
            <p style={{ color: 'rgba(242,139,130,0.75)', fontFamily: 'monospace' }}>{scan.error}</p>
          </div>
        )}

        <div
          className="space-y-1.5 text-xs pt-4"
          style={{ borderTop: '1px solid var(--border-light)', color: 'var(--text-tertiary)' }}
        >
          <div className="flex justify-between">
            <span>Scan ID</span>
            <span className="font-mono">#{scan.id}</span>
          </div>
          <div className="flex justify-between">
            <span>Started</span>
            <span className="font-mono">
              {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}
            </span>
          </div>
          {scan.completed_at && (
            <div className="flex justify-between">
              <span>Completed</span>
              <span className="font-mono">{new Date(scan.completed_at).toLocaleString()}</span>
            </div>
          )}
          {duration !== null && (
            <div className="flex justify-between">
              <span>Duration</span>
              <span className="font-mono">{duration}s</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function Scans() {
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<ScanJob | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchScans({ limit: 100 });
      setScans(data);
      setLastUpdated(new Date());
    } catch (err) {
      setError(getApiError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 10_000);
    return () => clearInterval(interval);
  }, [load]);

  const runningScans = scans.filter((s) => s.status === 'running' || s.status === 'pending');
  const doneScans = scans.filter((s) => s.status === 'done');
  const errorScans = scans.filter((s) => s.status === 'error');

  return (
    <AppLayout>
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Header */}
        <header
          className="h-14 shrink-0 flex items-center justify-between px-6"
          style={{ borderBottom: '1px solid var(--border-light)', background: 'var(--bg-header)' }}
        >
          <div>
            <h1 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Scan History</h1>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              All asset discovery scans · Auto-refreshes every 10s
              {lastUpdated && ` · Updated ${lastUpdated.toLocaleTimeString()}`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" style={{ color: 'var(--text-tertiary)' }} />}
            <button
              onClick={load}
              className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-md"
              style={{ color: 'var(--text-tertiary)', border: '1px solid var(--border-light)' }}
              onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-primary)')}
              onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-tertiary)')}
            >
              <RefreshCw className="w-3 h-3" />
              Refresh
            </button>
            <Link to="/attack-surface" className="btn-primary" style={{ padding: '7px 16px', fontSize: '13px' }}>
              <Plus className="w-3.5 h-3.5" />
              New Scan
            </Link>
          </div>
        </header>

        {/* Stats bar */}
        <div
          className="grid grid-cols-4 gap-px shrink-0"
          style={{ background: 'var(--border-light)', borderBottom: '1px solid var(--border-light)' }}
        >
          {[
            { label: 'Total Scans',    value: scans.length,     color: 'var(--text-primary)',   icon: Globe },
            { label: 'Running',        value: runningScans.length, color: '#A8C7FA', icon: Loader2 },
            { label: 'Completed',      value: doneScans.length,  color: '#81C995',  icon: CheckCircle },
            { label: 'Errors',         value: errorScans.length, color: '#F28B82',  icon: AlertTriangle },
          ].map(({ label, value, color, icon: Icon }) => (
            <div key={label} className="flex items-center gap-4 px-6 py-5" style={{ background: 'var(--bg-main)' }}>
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                style={{ background: 'var(--border-light)', border: '1px solid var(--border-light)' }}
              >
                <Icon className="w-3.5 h-3.5" style={{ color }} />
              </div>
              <div>
                <p className="text-xs mb-0.5" style={{ color: 'var(--text-tertiary)' }}>{label}</p>
                <p className="text-xl font-light font-mono leading-none" style={{ color }}>{value}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Error */}
        {error && (
          <div
            className="mx-6 mt-4 px-4 py-3 rounded-lg text-xs"
            style={{
              background: 'rgba(242,139,130,0.06)',
              border: '1px solid rgba(242,139,130,0.18)',
              color: '#F28B82',
            }}
          >
            {error}
          </div>
        )}

        {/* Content */}
        <div className="flex-1 flex overflow-hidden">
          <div className="flex-1 overflow-y-auto">
            {loading && scans.length === 0 ? (
              <div className="p-6 space-y-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="skeleton h-14 rounded-lg" />
                ))}
              </div>
            ) : scans.length === 0 ? (
              <div className="empty-state">
                <Globe className="w-10 h-10 mb-2" style={{ color: 'var(--border-medium)' }} />
                <h3>No scans yet</h3>
                <p>Start your first asset discovery scan from the Attack Surface page.</p>
                <Link to="/attack-surface" className="btn-primary mt-4" style={{ fontSize: '13px' }}>
                  <Plus className="w-3.5 h-3.5" />
                  Start First Scan
                </Link>
              </div>
            ) : (
              <table className="data-table">
                <thead
                  className="sticky top-0 z-10"
                  style={{ background: 'var(--bg-header-solid)', backdropFilter: 'blur(8px)' }}
                >
                  <tr>
                    {['#', 'Target', 'Status', 'Tools', 'Assets', 'Duration', 'Started', ''].map((h) => (
                      <th key={h}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan) => {
                    const tools = (scan.tools ?? []).map(parseTool);
                    const duration =
                      scan.started_at && scan.completed_at
                        ? Math.round(
                            (new Date(scan.completed_at).getTime() -
                              new Date(scan.started_at).getTime()) / 1000
                          )
                        : null;
                    const isSelected = selected?.id === scan.id;

                    return (
                      <tr
                        key={scan.id}
                        onClick={() => setSelected(isSelected ? null : scan)}
                        className={isSelected ? 'selected' : ''}
                      >
                        <td>
                          <span className="text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>
                            #{scan.id}
                          </span>
                        </td>
                        <td>
                          <span className="font-mono text-sm">{scan.target}</span>
                        </td>
                        <td>
                          <ScanStatusBadge status={scan.status} />
                        </td>
                        <td>
                          {tools.filter(t => t.status !== 'unavailable').length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {tools.filter(t => t.status !== 'unavailable').map(({ name, status }) => (
                                <span
                                  key={name}
                                  className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                                  style={{
                                    background: 'var(--border-light)',
                                    color: TOOL_STATUS_COLOR[status] ?? '#888',
                                    border: '1px solid var(--border-light)',
                                  }}
                                  title={`${name}: ${status}`}
                                >
                                  {name}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>
                          )}
                        </td>
                        <td>
                          <span
                            className="text-sm font-mono"
                            style={{ color: scan.assets_found > 0 ? '#81C995' : 'var(--text-tertiary)' }}
                          >
                            {scan.assets_found}
                          </span>
                        </td>
                        <td>
                          <span className="text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>
                            {duration !== null ? `${duration}s` : '—'}
                          </span>
                        </td>
                        <td>
                          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                            {scan.started_at
                              ? new Date(scan.started_at).toLocaleString()
                              : '—'}
                          </span>
                        </td>
                        <td onClick={(e) => e.stopPropagation()}>
                          {scan.status === 'done' && (
                            <Link
                              to={`/scans/${scan.id}`}
                              className="text-[10px] px-2 py-1 rounded font-mono"
                              style={{
                                background: 'rgba(168,199,250,0.08)',
                                border: '1px solid rgba(168,199,250,0.18)',
                                color: '#A8C7FA',
                              }}
                            >
                              View →
                            </Link>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          {/* Detail panel */}
          {selected && (
            <ScanDetailPanel scan={selected} onClose={() => setSelected(null)} />
          )}
        </div>
      </div>
    </AppLayout>
  );
}
