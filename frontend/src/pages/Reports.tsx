import { useState, useEffect } from 'react';
import AppLayout from '../components/AppLayout';
import {
  FileText, Download, RefreshCw, Loader2,
  Shield, AlertTriangle, Globe, CheckCircle,
  ExternalLink, BarChart2,
} from 'lucide-react';
import { fetchScans, getScanReportHtmlUrl, type ScanJob, getApiError } from '../api/client';
import { Link } from 'react-router-dom';

const SEV_COLOR: Record<string, string> = {
  critical: '#F28B82', high: '#FFAB40', medium: '#FDD663', low: '#81C995', info: '#A8C7FA',
};

function statusColor(s: string) {
  return s === 'done' ? '#81C995' : s === 'error' ? '#F28B82' : s === 'running' ? '#FDD663' : '#94a3b8';
}

function duration(scan: ScanJob): string {
  if (!scan.started_at) return '—';
  const end = scan.completed_at ? new Date(scan.completed_at) : new Date();
  const sec = Math.round((end.getTime() - new Date(scan.started_at).getTime()) / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

export default function Reports() {
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const data = await fetchScans({ limit: 50 });
      setScans(data);
      setError(null);
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const completedScans = scans.filter(s => s.status === 'done');
  const totalAssets = completedScans.reduce((a, s) => a + (s.assets_found || 0), 0);
  const totalFindings = completedScans.reduce((a, s) => a + (s.findings_count || 0), 0);

  return (
    <AppLayout>
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

        {/* Header */}
        <header className="h-14 shrink-0 flex items-center justify-between px-6"
          style={{ borderBottom: '1px solid var(--border-light)', background: 'var(--bg-header)' }}>
          <div>
            <h1 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Reports</h1>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              Export HTML reports · View attack paths · {completedScans.length} completed scan{completedScans.length !== 1 ? 's' : ''}
            </p>
          </div>
          <button onClick={load} className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg"
            style={{ color: 'var(--text-tertiary)', border: '1px solid var(--border-light)' }}>
            {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
            Refresh
          </button>
        </header>

        {/* Stats bar */}
        <div className="shrink-0 grid gap-px" style={{
          gridTemplateColumns: 'repeat(4, 1fr)',
          background: 'var(--border-light)',
          borderBottom: '1px solid var(--border-light)',
        }}>
          {[
            { label: 'Total Scans', value: scans.length, icon: BarChart2, color: '#A8C7FA' },
            { label: 'Completed', value: completedScans.length, icon: CheckCircle, color: '#81C995' },
            { label: 'Assets Found', value: totalAssets, icon: Globe, color: '#A8C7FA' },
            { label: 'Findings', value: totalFindings, icon: AlertTriangle, color: '#FFAB40' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="px-6 py-3 flex items-center gap-3" style={{ background: 'var(--bg-main)' }}>
              <Icon className="w-4 h-4 shrink-0" style={{ color }} />
              <div>
                <p className="text-lg font-mono" style={{ color }}>{value}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Scan list */}
        <div className="flex-1 overflow-y-auto">
          {loading && scans.length === 0 ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="w-6 h-6 animate-spin" style={{ color: 'var(--text-tertiary)' }} />
            </div>
          ) : error ? (
            <div className="m-6 p-4 rounded-lg text-sm" style={{ background: 'rgba(242,139,130,0.06)', border: '1px solid rgba(242,139,130,0.2)', color: '#F28B82' }}>
              {error}
            </div>
          ) : scans.length === 0 ? (
            <div className="empty-state">
              <FileText className="w-10 h-10 mb-3" style={{ color: 'var(--border-medium)' }} />
              <h3>No scans yet</h3>
              <p>Run a scan from the Attack Surface page to generate your first report.</p>
            </div>
          ) : (
            <div className="p-6 space-y-3">
              {scans.map(scan => (
                <div key={scan.id} className="p-4 rounded-xl flex items-center gap-4"
                  style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-light)' }}>

                  {/* Status indicator */}
                  <div className="w-2 h-2 rounded-full shrink-0" style={{
                    background: statusColor(scan.status),
                    boxShadow: scan.status === 'running' ? `0 0 6px ${statusColor(scan.status)}` : 'none',
                  }} />

                  {/* Main info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Link to={`/scans/${scan.id}`} className="text-sm font-medium hover:underline truncate"
                        style={{ color: 'var(--text-primary)' }}>
                        {scan.target}
                      </Link>
                      <span className="text-[10px] font-mono shrink-0" style={{ color: statusColor(scan.status) }}>
                        {scan.status.toUpperCase()}
                      </span>
                      <span className="text-[10px] font-mono shrink-0" style={{ color: 'var(--text-muted)' }}>
                        #{scan.id}
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-3 text-xs" style={{ color: 'var(--text-tertiary)' }}>
                      <span>{scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}</span>
                      <span>·</span>
                      <span>{duration(scan)} duration</span>
                      {scan.assets_found > 0 && <>
                        <span>·</span>
                        <span className="flex items-center gap-1">
                          <Globe className="w-3 h-3" style={{ color: '#A8C7FA' }} />
                          {scan.assets_found} assets
                        </span>
                      </>}
                      {scan.findings_count > 0 && <>
                        <span>·</span>
                        <span className="flex items-center gap-1">
                          <Shield className="w-3 h-3" style={{ color: '#FFAB40' }} />
                          {scan.findings_count} findings
                        </span>
                      </>}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 shrink-0">
                    <Link to={`/scans/${scan.id}`}
                      className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg transition-all"
                      style={{ background: 'rgba(168,199,250,0.08)', color: '#A8C7FA', border: '1px solid rgba(168,199,250,0.15)' }}>
                      <ExternalLink className="w-3 h-3" />
                      View
                    </Link>
                    {scan.status === 'done' && (
                      <a
                        href={getScanReportHtmlUrl(scan.id)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg transition-all"
                        style={{ background: 'rgba(129,201,149,0.08)', color: '#81C995', border: '1px solid rgba(129,201,149,0.15)' }}
                      >
                        <Download className="w-3 h-3" />
                        HTML
                      </a>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
