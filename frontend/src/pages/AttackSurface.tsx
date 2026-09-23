import React, { useState, useEffect, useCallback, useRef } from 'react';
import AppLayout from '../components/AppLayout';
import AssetGraph from '../components/AssetGraph';
import {
  Search, Plus, RefreshCw, Globe, Cpu, Wifi,
  AlertTriangle, CheckCircle, Clock, X, Loader2,
  List, Network, ChevronDown, Shield, ExternalLink,
} from 'lucide-react';
import {
  fetchAssets, startScan, fetchScan,
  type Asset, type ScanJob, getApiError,
} from '../api/client';

// ─── Status / Port badges ─────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === 'Active'   ? 'badge badge-active'   :
    status === 'Warning'  ? 'badge badge-warning'  :
    status === 'Critical' ? 'badge badge-critical' :
    'badge badge-inactive';
  const dotColor =
    status === 'Active'   ? '#81C995' :
    status === 'Warning'  ? '#FDD663' :
    status === 'Critical' ? '#F28B82' : 'var(--text-tertiary)';
  return (
    <span className={cls}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: dotColor }} />
      {status}
    </span>
  );
}

function PortBadge({ port }: { port: number }) {
  const risky = [21, 22, 23, 25, 80, 8080, 8000, 3000, 3389, 5900, 6379];
  const isRisky = risky.includes(port);
  return (
    <span
      className="text-xs font-mono px-1.5 py-0.5 rounded"
      style={{
        background: isRisky ? 'rgba(253,214,99,0.08)' : 'var(--border-light)',
        color: isRisky ? '#FDD663' : 'var(--text-secondary)',
        border: `1px solid ${isRisky ? 'rgba(253,214,99,0.2)' : 'var(--border-light)'}`,
      }}
    >
      {port}
    </span>
  );
}

// ─── Scan Modal ───────────────────────────────────────────────────────────────

function NewScanModal({
  onClose,
  onScanQueued,
}: {
  onClose: () => void;
  onScanQueued: (job: ScanJob) => void;
}) {
  const [target, setTarget] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const t = target.trim().toLowerCase();
    if (!t) return;

    setValidationError(null);
    setSubmitting(true);
    try {
      const job = await startScan({ target: t });
      onScanQueued(job);
      onClose();
    } catch (err) {
      setValidationError(getApiError(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(14,13,15,0.88)', backdropFilter: 'blur(10px)' }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-xl p-6"
        style={{
          background: 'var(--bg-modal)',
          border: '1px solid var(--border-medium)',
          boxShadow: '0 32px 80px rgba(0,0,0,0.6)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-6">
          <div>
            <h3 className="text-base font-semibold">New Asset Discovery Scan</h3>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              Runs crt.sh · Subfinder · dnsx · httpx · Nmap
            </p>
          </div>
          <button onClick={onClose} style={{ color: 'var(--text-tertiary)' }}>
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs mb-1.5" style={{ color: 'var(--text-secondary)' }}>
              Target Domain or IP Address
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => { setTarget(e.target.value); setValidationError(null); }}
              placeholder="example.com or 192.168.1.0/24"
              autoFocus
              className="input"
            />
            {validationError && (
              <p className="mt-1.5 text-xs" style={{ color: '#F28B82' }}>
                {validationError}
              </p>
            )}
          </div>

          <div
            className="p-3 rounded-lg text-xs leading-relaxed"
            style={{
              background: 'rgba(168,199,250,0.05)',
              border: '1px solid rgba(168,199,250,0.14)',
              color: 'rgba(168,199,250,0.7)',
            }}
          >
            <Shield className="w-3 h-3 inline mr-1.5 mb-0.5" />
            Only scan systems you own or are explicitly authorized to assess.
            OpenSecX logs all scan targets for audit purposes.
          </div>

          <div className="flex gap-3 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="btn-ghost flex-1 justify-center"
              style={{ padding: '10px' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !target.trim()}
              className="btn-primary flex-1 justify-center"
              style={{
                padding: '10px',
                opacity: submitting || !target.trim() ? 0.6 : 1,
              }}
            >
              {submitting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  Queuing...
                </>
              ) : (
                'Start Discovery'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Asset Detail Panel ───────────────────────────────────────────────────────

function AssetDetailPanel({ asset, onClose }: { asset: Asset; onClose: () => void }) {
  const fmt = (d: string | null) =>
    d ? new Date(d).toLocaleString() : '—';

  const dns = asset.dns_records as Record<string, string[]> | null;

  const DNS_COLORS: Record<string, string> = {
    A: '#A8C7FA', AAAA: '#81C995', MX: '#FDD663',
    NS: '#E8A87C', TXT: '#C58AF9', CNAME: '#F28B82',
    SOA: '#80DEEA', CAA: '#FFAB40',
  };

  return (
    <div
      className="w-80 shrink-0 flex flex-col overflow-hidden"
      style={{
        borderLeft: '1px solid var(--border-light)',
        background: 'var(--bg-panel)',
      }}
    >
      <div
        className="flex items-center justify-between px-5 py-4 shrink-0"
        style={{ borderBottom: '1px solid var(--border-light)' }}
      >
        <h4 className="text-sm font-medium">Asset Details</h4>
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

      <div className="flex-1 overflow-y-auto p-5 space-y-4">

        {/* ── Identity ── */}
        <div className="space-y-2">
          <div>
            <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Domain</p>
            <p className="text-sm font-mono break-all">{asset.domain || '—'}</p>
          </div>
          {asset.hostname && asset.hostname !== asset.domain && (
            <div>
              <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Hostname</p>
              <p className="text-sm font-mono">{asset.hostname}</p>
            </div>
          )}
          <div className="flex gap-4">
            <div className="flex-1">
              <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>IP Address</p>
              <p className="text-sm font-mono" style={{ color: '#A8C7FA' }}>{asset.ip_address || '—'}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Status</p>
              <StatusBadge status={asset.status} />
            </div>
          </div>
          {(asset.protocol || asset.service) && (
            <div>
              <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Service</p>
              <p className="text-xs font-mono" style={{ color: '#81C995' }}>
                {[asset.protocol?.toUpperCase(), asset.service].filter(Boolean).join(' · ')}
              </p>
            </div>
          )}
        </div>

        {/* ── DNS Records (nslookup / dnschecker style) ── */}
        {dns && Object.keys(dns).length > 0 && (
          <div style={{ borderTop: '1px solid var(--border-light)', paddingTop: '12px' }}>
            <p className="text-[10px] uppercase tracking-wider mb-3" style={{ color: 'var(--text-tertiary)' }}>
              DNS Records
            </p>
            <div className="space-y-2">
              {Object.entries(dns).map(([type, values]) => (
                <div key={type} className="flex items-start gap-2">
                  <span
                    className="shrink-0 font-mono text-[10px] px-1.5 py-0.5 rounded font-semibold"
                    style={{
                      background: `${DNS_COLORS[type] || '#A8C7FA'}18`,
                      color: DNS_COLORS[type] || '#A8C7FA',
                      border: `1px solid ${DNS_COLORS[type] || '#A8C7FA'}30`,
                      minWidth: '38px',
                      textAlign: 'center',
                    }}
                  >
                    {type}
                  </span>
                  <div className="flex flex-col gap-0.5 min-w-0">
                    {(Array.isArray(values) ? values : [String(values)]).map((v, i) => (
                      <span key={i} className="text-[11px] font-mono break-all" style={{ color: 'var(--text-secondary)' }}>
                        {v}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Tech Stack ── */}
        {asset.technologies && asset.technologies.length > 0 && (
          <div style={{ borderTop: '1px solid var(--border-light)', paddingTop: '12px' }}>
            <p className="text-[10px] uppercase tracking-wider mb-2" style={{ color: 'var(--text-tertiary)' }}>Tech Stack</p>
            <div className="flex flex-wrap gap-1.5">
              {asset.technologies.map((t) => (
                <span
                  key={t}
                  className="text-[10px] px-2 py-0.5 rounded-full font-mono"
                  style={{
                    background: 'rgba(168,199,250,0.08)',
                    border: '1px solid rgba(168,199,250,0.2)',
                    color: '#A8C7FA',
                  }}
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* ── Open Ports ── */}
        {asset.ports && asset.ports.length > 0 && (
          <div style={{ borderTop: '1px solid var(--border-light)', paddingTop: '12px' }}>
            <p className="text-[10px] uppercase tracking-wider mb-2" style={{ color: 'var(--text-tertiary)' }}>Open Ports</p>
            <div className="flex flex-wrap gap-1.5">
              {asset.ports.map((p) => <PortBadge key={p} port={p} />)}
            </div>
          </div>
        )}

        {/* ── TLS Certificate ── */}
        {asset.certificate && (
          <div style={{ borderTop: '1px solid var(--border-light)', paddingTop: '12px' }}>
            <p className="text-[10px] uppercase tracking-wider mb-2" style={{ color: 'var(--text-tertiary)' }}>TLS Certificate</p>
            <div className="space-y-1 text-[11px]" style={{ color: 'var(--text-secondary)' }}>
              {asset.certificate.subject && <p>CN: <span className="font-mono">{asset.certificate.subject}</span></p>}
              {asset.certificate.issuer && <p>Issuer: <span className="font-mono">{asset.certificate.issuer}</span></p>}
              {asset.certificate.not_after && (
                <p style={{ color: new Date(asset.certificate.not_after) < new Date() ? '#F28B82' : '#81C995' }}>
                  Expires: <span className="font-mono">{asset.certificate.not_after}</span>
                </p>
              )}
            </div>
          </div>
        )}

        {/* ── WHOIS / Registration metadata ── */}
        <div
          className="pt-3 space-y-1.5 text-[11px]"
          style={{ borderTop: '1px solid var(--border-light)', color: 'var(--text-tertiary)' }}
        >
          <p className="text-[10px] uppercase tracking-wider mb-2">Registration</p>
          {asset.org && (
            <div className="flex justify-between gap-2">
              <span className="shrink-0">Org</span>
              <span className="font-mono truncate" style={{ color: 'var(--text-secondary)' }}>{asset.org}</span>
            </div>
          )}
          {asset.country && (
            <div className="flex justify-between gap-2">
              <span className="shrink-0">Country</span>
              <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{asset.country}</span>
            </div>
          )}
          <div className="flex justify-between gap-2">
            <span className="shrink-0">Source</span>
            <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{asset.source || '—'}</span>
          </div>
          <div className="flex justify-between gap-2">
            <span className="shrink-0">First Seen</span>
            <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{fmt(asset.first_seen)}</span>
          </div>
          <div className="flex justify-between gap-2">
            <span className="shrink-0">Last Seen</span>
            <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{fmt(asset.last_seen)}</span>
          </div>
          {asset.notes && (
            <div className="pt-1">
              <p className="mb-1">Notes</p>
              <p className="font-mono text-[10px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{asset.notes}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function AttackSurface() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('All');
  const [viewMode, setViewMode] = useState<'table' | 'graph'>('table');
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [showScanModal, setShowScanModal] = useState(false);
  const [activeScan, setActiveScan] = useState<ScanJob | null>(null);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadAssets = useCallback(async () => {
    try {
      const data = await fetchAssets({ limit: 500 });
      setAssets(data);
      setApiError(null);
    } catch (err) {
      setApiError(
        'Cannot connect to the OpenSecX API. Make sure the backend is running: ' +
        'cd backend && uvicorn app.main:app --reload'
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAssets();
  }, [loadAssets]);

  // Poll active scan for status
  const pollScan = useCallback(async (scanId: number) => {
    try {
      const job = await fetchScan(scanId);
      setActiveScan(job);
      if (job.status === 'done' || job.status === 'error') {
        if (pollRef.current) clearInterval(pollRef.current);
        pollRef.current = null;
        // Refresh assets to show newly discovered ones
        await loadAssets();
      }
    } catch {
      if (pollRef.current) clearInterval(pollRef.current);
    }
  }, [loadAssets]);

  const handleScanQueued = useCallback((job: ScanJob) => {
    setActiveScan(job);
    // Poll every 2 seconds for status updates
    pollRef.current = setInterval(() => pollScan(job.id), 2000);
  }, [pollScan]);

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const handleNodeClick = (id: string) => {
    const asset = assets.find((a) => a.domain === id || `ip-${a.ip_address}` === id);
    if (asset) setSelectedAsset(asset);
  };

  const filtered = assets.filter((a) => {
    const matchSearch =
      !search ||
      a.domain?.toLowerCase().includes(search.toLowerCase()) ||
      a.ip_address?.includes(search) ||
      a.hostname?.toLowerCase().includes(search.toLowerCase()) ||
      a.technologies?.some((t) => t.toLowerCase().includes(search.toLowerCase())) ||
      a.org?.toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === 'All' || a.status === statusFilter;
    return matchSearch && matchStatus;
  });

  const total = assets.length;
  const activeCount = assets.filter((a) => a.status === 'Active').length;
  const warningCount = assets.filter((a) => a.status === 'Warning' || a.status === 'Critical').length;
  const allPorts = assets.flatMap((a) => a.ports ?? []);
  const uniquePorts = new Set(allPorts).size;

  return (
    <AppLayout>
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top bar */}
        <header
          className="h-14 shrink-0 flex items-center justify-between px-6"
          style={{ borderBottom: '1px solid var(--border-light)', background: 'var(--bg-header)' }}
        >
          <div>
            <h1 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
              Attack Surface
            </h1>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              Asset Inventory &amp; Discovery — Phase 1
            </p>
          </div>

          <div className="flex items-center gap-2">
            {/* Scan status */}
            {activeScan && activeScan.status === 'running' && (
              <div
                className="flex items-center gap-2 px-3 py-1.5 rounded-md text-xs"
                style={{
                  background: 'rgba(168,199,250,0.07)',
                  border: '1px solid rgba(168,199,250,0.18)',
                  color: '#A8C7FA',
                }}
              >
                <Loader2 className="w-3 h-3 animate-spin" />
                Scanning {activeScan.target}...
              </div>
            )}
            {activeScan && activeScan.status === 'done' && (
              <div
                className="flex items-center gap-2 px-3 py-1.5 rounded-md text-xs cursor-pointer"
                style={{
                  background: 'rgba(129,201,149,0.07)',
                  border: '1px solid rgba(129,201,149,0.18)',
                  color: '#81C995',
                }}
                onClick={() => setActiveScan(null)}
              >
                <CheckCircle className="w-3 h-3" />
                Scan complete — {activeScan.assets_found} assets saved
                <X className="w-3 h-3 ml-1" />
              </div>
            )}
            {activeScan && activeScan.status === 'error' && (
              <div
                className="flex items-center gap-2 px-3 py-1.5 rounded-md text-xs cursor-pointer"
                style={{
                  background: 'rgba(242,139,130,0.07)',
                  border: '1px solid rgba(242,139,130,0.18)',
                  color: '#F28B82',
                }}
                onClick={() => setActiveScan(null)}
                title={activeScan.error ?? ''}
              >
                <AlertTriangle className="w-3 h-3" />
                Scan error — check logs
                <X className="w-3 h-3 ml-1" />
              </div>
            )}

            <button
              onClick={loadAssets}
              className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-md transition-all"
              style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-light)' }}
              onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-primary)')}
              onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-secondary)')}
            >
              <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>

            <button
              onClick={() => setShowScanModal(true)}
              className="btn-primary"
              style={{ padding: '7px 16px', fontSize: '13px' }}
            >
              <Plus className="w-3.5 h-3.5" />
              New Scan
            </button>
          </div>
        </header>

        {/* API error banner */}
        {apiError && (
          <div
            className="mx-6 mt-4 px-4 py-3 rounded-lg text-xs flex items-start gap-2"
            style={{
              background: 'rgba(242,139,130,0.06)',
              border: '1px solid rgba(242,139,130,0.18)',
              color: '#F28B82',
            }}
          >
            <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <div>
              <p className="font-medium mb-0.5">API Connection Error</p>
              <p style={{ color: 'rgba(242,139,130,0.75)' }}>{apiError}</p>
            </div>
          </div>
        )}

        {/* KPI cards */}
        <div
          className="grid grid-cols-4 gap-px shrink-0"
          style={{ background: 'var(--border-light)', borderBottom: '1px solid var(--border-light)' }}
        >
          {[
            { icon: Globe,         label: 'Total Assets',    value: total,         sub: 'All discovered', color: 'var(--text-primary)' },
            { icon: CheckCircle,   label: 'Active',          value: activeCount,   sub: 'Responding',     color: '#81C995' },
            { icon: AlertTriangle, label: 'Needs Attention', value: warningCount,  sub: 'Warning/Critical', color: '#FDD663' },
            { icon: Wifi,          label: 'Unique Ports',    value: uniquePorts,   sub: 'Across all assets', color: '#A8C7FA' },
          ].map(({ icon: Icon, label, value, sub, color }) => (
            <div
              key={label}
              className="flex items-center gap-4 px-6 py-5"
              style={{ background: 'var(--bg-main)' }}
            >
              <div
                className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
                style={{ background: 'var(--border-light)', border: '1px solid var(--border-light)' }}
              >
                <Icon className="w-4 h-4" style={{ color }} />
              </div>
              <div>
                <p className="text-xs mb-0.5" style={{ color: 'var(--text-tertiary)' }}>{label}</p>
                <p className="text-2xl font-light font-mono leading-none" style={{ color }}>
                  {loading ? <span className="skeleton inline-block w-8 h-7 rounded" /> : value}
                </p>
                <p className="text-[10px] mt-1" style={{ color: 'var(--text-muted)' }}>{sub}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div
          className="flex items-center gap-3 px-6 py-3 shrink-0"
          style={{ borderBottom: '1px solid var(--border-light)', background: 'var(--bg-header)' }}
        >
          <div className="relative flex-1 max-w-sm">
            <Search
              className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2"
              style={{ color: 'var(--text-tertiary)' }}
            />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search domains, IPs, technologies, org..."
              className="input pl-9 py-2 text-xs"
            />
          </div>

          <div className="flex items-center gap-1">
            {['All', 'Active', 'Warning', 'Critical'].map((f) => (
              <button
                key={f}
                onClick={() => setStatusFilter(f)}
                className="px-3 py-1.5 rounded-md text-xs transition-all"
                style={{
                  background: statusFilter === f ? 'var(--border-light)' : 'transparent',
                  color: statusFilter === f ? 'var(--text-primary)' : 'var(--text-tertiary)',
                  border: statusFilter === f ? '1px solid var(--border-medium)' : '1px solid transparent',
                }}
              >
                {f}
              </button>
            ))}
          </div>

          {/* View toggle */}
          <div
            className="ml-auto flex items-center p-0.5 rounded-md"
            style={{ background: 'var(--border-light)', border: '1px solid var(--border-light)' }}
          >
            {([['table', List], ['graph', Network]] as const).map(([mode, Icon]) => (
              <button
                key={mode}
                onClick={() => setViewMode(mode)}
                className="flex items-center justify-center p-1.5 rounded"
                style={{
                  background: viewMode === mode ? 'var(--border-medium)' : 'transparent',
                  color: viewMode === mode ? 'var(--text-primary)' : 'var(--text-tertiary)',
                  transition: 'all 0.15s',
                }}
              >
                <Icon className="w-4 h-4" />
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-tertiary)' }}>
            {loading && <Loader2 className="w-3 h-3 animate-spin" />}
            <span>{filtered.length} asset{filtered.length !== 1 ? 's' : ''}</span>
          </div>
        </div>

        {/* Main content */}
        <div className="flex-1 flex overflow-hidden relative">
          {viewMode === 'table' ? (
            <div className="flex-1 overflow-y-auto">
              {loading ? (
                // Skeleton rows
                <div className="p-6 space-y-3">
                  {Array.from({ length: 6 }).map((_, i) => (
                    <div key={i} className="skeleton h-12 w-full rounded-lg" />
                  ))}
                </div>
              ) : filtered.length === 0 ? (
                <div className="empty-state">
                  {assets.length === 0 ? (
                    <>
                      <Shield className="w-12 h-12 mb-2" style={{ color: 'var(--border-medium)' }} />
                      <h3>No assets discovered yet</h3>
                      <p>Click <strong>New Scan</strong> to start asset discovery for an authorized target.</p>
                      <p style={{ fontSize: '11px', marginTop: '4px' }}>
                        crt.sh works immediately · Subfinder, dnsx, httpx, Nmap require installation
                      </p>
                      <button
                        onClick={() => setShowScanModal(true)}
                        className="btn-primary mt-4"
                        style={{ fontSize: '13px' }}
                      >
                        <Plus className="w-3.5 h-3.5" />
                        Start Your First Scan
                      </button>
                    </>
                  ) : (
                    <>
                      <h3>No assets match your filters</h3>
                      <p>Try adjusting the search or status filter.</p>
                    </>
                  )}
                </div>
              ) : (
                <table className="data-table">
                  <thead
                    className="sticky top-0 z-10"
                    style={{ background: 'var(--bg-header-solid)', backdropFilter: 'blur(8px)' }}
                  >
                    <tr>
                      {['Asset / Domain', 'IP Address', 'Open Ports', 'Technologies', 'Source', 'Last Seen', 'Status'].map(
                        (h) => <th key={h}>{h}</th>
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((asset) => (
                      <tr
                        key={asset.id}
                        onClick={() => setSelectedAsset(selectedAsset?.id === asset.id ? null : asset)}
                        className={selectedAsset?.id === asset.id ? 'selected' : ''}
                      >
                        <td>
                          <p className="font-mono text-sm" style={{ color: 'var(--text-primary)' }}>
                            {asset.domain || asset.hostname || '—'}
                          </p>
                          {asset.hostname && asset.hostname !== asset.domain && (
                            <p className="font-mono text-[10px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                              {asset.hostname}
                            </p>
                          )}
                        </td>
                        <td>
                          <p className="font-mono text-sm" style={{ color: 'var(--text-secondary)' }}>
                            {asset.ip_address || '—'}
                          </p>
                        </td>
                        <td>
                          <div className="flex flex-wrap gap-1">
                            {(asset.ports ?? []).slice(0, 5).map((p) => (
                              <PortBadge key={p} port={p} />
                            ))}
                            {(asset.ports?.length ?? 0) > 5 && (
                              <span className="text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>
                                +{asset.ports!.length - 5}
                              </span>
                            )}
                            {!asset.ports?.length && (
                              <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>—</span>
                            )}
                          </div>
                        </td>
                        <td>
                          <div className="flex flex-wrap gap-1">
                            {(asset.technologies ?? []).slice(0, 3).map((t) => (
                              <span
                                key={t}
                                className="text-[11px] px-2 py-0.5 rounded-full"
                                style={{
                                  background: 'var(--border-light)',
                                  border: '1px solid var(--border-light)',
                                  color: 'var(--text-secondary)',
                                }}
                              >
                                {t}
                              </span>
                            ))}
                            {(asset.technologies?.length ?? 0) > 3 && (
                              <span className="text-[11px]" style={{ color: 'var(--text-tertiary)' }}>
                                +{asset.technologies!.length - 3}
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          <span className="text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>
                            {asset.source || '—'}
                          </span>
                        </td>
                        <td>
                          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                            {asset.last_seen
                              ? new Date(asset.last_seen).toLocaleDateString()
                              : '—'}
                          </span>
                        </td>
                        <td>
                          <StatusBadge status={asset.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          ) : (
            <div className="flex-1 w-full h-full" style={{ background: 'var(--bg-surface)' }}>
              <AssetGraph onNodeClick={handleNodeClick} />
            </div>
          )}

          {/* Detail panel */}
          {selectedAsset && (
            <div className={`absolute top-0 right-0 h-full z-20 ${viewMode === 'graph' ? 'shadow-2xl' : ''}`}>
              <AssetDetailPanel asset={selectedAsset} onClose={() => setSelectedAsset(null)} />
            </div>
          )}
        </div>
      </div>

      {showScanModal && (
        <NewScanModal
          onClose={() => setShowScanModal(false)}
          onScanQueued={handleScanQueued}
        />
      )}
    </AppLayout>
  );
}
