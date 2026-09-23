import { useEffect, useState } from 'react';
import HeroCanvas from '../components/HeroCanvas';
import Navbar from '../components/Navbar';
import {
  ArrowRight, Database, AlertTriangle, Shield, BarChart2,
  Activity, FileText, Globe, Layers, Zap, Lock, ChevronRight,
  Server, Cpu
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { fetchStats, type PlatformStats } from '../api/client';

// ─── Static content (real descriptions, not fake data) ────────────────────

const phases = [
  {
    num: '01',
    title: 'Discover',
    desc: 'Map every asset in your attack surface. Subdomains via crt.sh and Subfinder, IPs via dnsx, live services via httpx and Nmap — all normalized into a unified inventory.',
    color: '#A8C7FA',
    tools: ['crt.sh', 'Subfinder', 'dnsx', 'httpx', 'Nmap'],
  },
  {
    num: '02',
    title: 'Assess',
    desc: 'Run authorized VAPT assessments using Nuclei, OWASP ZAP, Nikto and more. Results are normalized into a unified finding format with CVSS, CWE, and CVE mapping.',
    color: '#81C995',
    tools: ['Nuclei', 'OWASP ZAP', 'Nikto', 'SSLyze'],
  },
  {
    num: '03',
    title: 'Prioritize',
    desc: 'Combine CVSS, EPSS, exploit availability and asset criticality into a transparent, explainable risk score. No black boxes — every factor is visible.',
    color: '#FDD663',
    tools: ['NVD', 'FIRST EPSS', 'ExploitDB', 'MITRE ATT&CK'],
  },
  {
    num: '04',
    title: 'Monitor',
    desc: 'Continuously watch for new assets, vulnerabilities, and changes. Scheduled scans, delta detection, certificate expiry alerts and compliance posture tracking.',
    color: '#E8A87C',
    tools: ['ISO 27001', 'NIST CSF', 'CIS Controls', 'OWASP ASVS'],
  },
];

const features = [
  {
    icon: Database,
    title: 'Attack Surface Management',
    desc: 'Continuous asset discovery across domains, IPs, ports, and technologies with full relationship mapping via crt.sh, Subfinder, dnsx and httpx.',
  },
  {
    icon: Shield,
    title: 'Authorized VAPT',
    desc: 'Orchestrate Nmap, Nuclei, ZAP, Nikto and more against authorized targets. Every scan is logged for audit. Never scans unauthorized systems.',
  },
  {
    icon: BarChart2,
    title: 'Risk Intelligence',
    desc: 'Transparent scoring combining CVSS, EPSS, exploit availability and asset criticality. Every factor is visible — no opaque black-box scores.',
  },
  {
    icon: AlertTriangle,
    title: 'Compliance Mapping',
    desc: 'Auto-map findings to ISO 27001, NIST CSF, CIS Controls, OWASP ASVS and PCI DSS via an extensible control-mapping layer.',
  },
  {
    icon: Activity,
    title: 'Continuous Monitoring',
    desc: 'Scheduled scans, delta detection, certificate expiry alerts, DNS change monitoring and technology drift detection.',
  },
  {
    icon: FileText,
    title: 'Professional Reporting',
    desc: 'Generate executive, technical, compliance and remediation reports in PDF, HTML and JSON. Fully customizable templates.',
  },
];

const toolChain = [
  { name: 'crt.sh', tag: 'CT Logs', phase: 1 },
  { name: 'Subfinder', tag: 'OSINT', phase: 1 },
  { name: 'Amass', tag: 'OSINT', phase: 1 },
  { name: 'dnsx', tag: 'DNS', phase: 1 },
  { name: 'httpx', tag: 'HTTP', phase: 1 },
  { name: 'Nmap', tag: 'Ports', phase: 1 },
  { name: 'WhatWeb', tag: 'Tech', phase: 1 },
  { name: 'WHOIS', tag: 'RDAP', phase: 1 },
  { name: 'Nuclei', tag: 'VAPT', phase: 2 },
  { name: 'OWASP ZAP', tag: 'VAPT', phase: 2 },
  { name: 'Nikto', tag: 'VAPT', phase: 2 },
  { name: 'SSLyze', tag: 'TLS', phase: 2 },
];

const phaseTagColor: Record<number, string> = {
  1: 'rgba(168,199,250,0.15)',
  2: 'rgba(129,201,149,0.1)',
};
const phaseTextColor: Record<number, string> = {
  1: '#A8C7FA',
  2: '#81C995',
};

// ─── Components ───────────────────────────────────────────────────────────────

function LiveStatBadge({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="flex flex-col items-center">
      <span
        className="text-3xl font-light tabular-nums"
        style={{ color: color || 'var(--text-primary)', fontFamily: 'IBM Plex Mono, monospace' }}
      >
        {value}
      </span>
      <span className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
        {label}
      </span>
    </div>
  );
}

function StatsSkeleton() {
  return (
    <div className="flex gap-10 animate-pulse">
      {[1, 2, 3].map((i) => (
        <div key={i} className="flex flex-col items-center gap-2">
          <div className="skeleton h-8 w-16 rounded" />
          <div className="skeleton h-3 w-20 rounded" />
        </div>
      ))}
    </div>
  );
}

// ─── Landing Page ─────────────────────────────────────────────────────────────

export default function Landing() {
  const [stats, setStats] = useState<PlatformStats | null>(null);
  const [statsLoading, setStatsLoading] = useState(true);

  useEffect(() => {
    fetchStats()
      .then(setStats)
      .catch((err) => console.error('Failed to load stats:', err))
      .finally(() => setStatsLoading(false));
  }, []);

  return (
    <div style={{ background: 'var(--bg-main)', color: 'var(--text-primary)', minHeight: '100vh' }}>
      <Navbar />

      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <section className="relative flex items-center overflow-hidden" style={{ minHeight: 'calc(100vh - 56px)' }}>
        <div className="absolute inset-0" style={{ opacity: 0.3 }}>
          <HeroCanvas />
        </div>

        <div className="relative w-full max-w-7xl mx-auto px-6 pt-14 pb-10 grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16">
          {/* Left */}
          <div className="animate-slide-up">
            {/* Phase badge */}
            <div
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium mb-5"
              style={{
                background: 'rgba(168,199,250,0.07)',
                border: '1px solid rgba(168,199,250,0.18)',
                color: '#A8C7FA',
              }}
            >
              <span
                className="status-dot online animate-pulse-dot"
                style={{ width: '6px', height: '6px' }}
              />
              Phase 1 Active — Asset Discovery &amp; OSINT
            </div>

            <h1
              className="font-semibold leading-tight mb-4"
              style={{ fontSize: 'clamp(34px, 4.5vw, 56px)', letterSpacing: '-0.025em' }}
            >
              See Your Attack Surface.{' '}
              <span style={{ color: 'var(--text-tertiary)' }}>Understand Your Risk.</span>
            </h1>

            <p
              className="text-base leading-relaxed mb-7 max-w-lg"
              style={{ color: 'var(--text-secondary)', fontSize: '16px', lineHeight: '1.75' }}
            >
              OpenSecX unifies asset discovery, vulnerability assessment, risk intelligence
              and compliance into one open-source security platform. Built for security teams
              that demand clarity over complexity.
            </p>

            {/* CTAs */}
            <div className="flex flex-wrap gap-3 mb-8">
              <Link
                to="/attack-surface"
                className="btn-primary"
                style={{ padding: '11px 24px', fontSize: '14px' }}
              >
                Start Assessment
                <ArrowRight className="w-4 h-4" />
              </Link>
              <a
                href="#platform"
                className="btn-ghost"
                style={{ padding: '11px 24px', fontSize: '14px' }}
              >
                Explore Platform
              </a>
            </div>

            {/* Live stats from API — real numbers only */}
            {statsLoading ? (
              <StatsSkeleton />
            ) : stats ? (
              <div
                className="flex flex-wrap gap-8 pt-8"
                style={{ borderTop: '1px solid var(--border-light)' }}
              >
                <LiveStatBadge
                  label="Assets discovered"
                  value={stats.total_assets.toLocaleString()}
                />
                <LiveStatBadge
                  label="Scans completed"
                  value={stats.completed_scans.toLocaleString()}
                  color="#81C995"
                />
                <LiveStatBadge
                  label="Unique domains"
                  value={stats.unique_domains.toLocaleString()}
                  color="#A8C7FA"
                />
              </div>
            ) : (
              <div
                className="flex items-center gap-2 pt-8 text-xs"
                style={{
                  borderTop: '1px solid var(--border-light)',
                  color: 'var(--text-tertiary)',
                }}
              >
                <span
                  className="status-dot offline"
                  style={{ width: '6px', height: '6px' }}
                />
                Backend offline — start the API server to see live stats
              </div>
            )}
          </div>

          {/* Right — dashboard preview with real data structure */}
          <div
            className="hidden lg:flex flex-col rounded-xl overflow-hidden animate-fade-in delay-400"
            style={{
              border: '1px solid var(--border-light)',
              background: 'rgba(26,25,27,0.92)',
              backdropFilter: 'blur(12px)',
              boxShadow: '0 32px 80px rgba(0,0,0,0.4)',
            }}
          >
            {/* Window chrome */}
            <div
              className="flex items-center gap-2 px-4 py-3 shrink-0"
              style={{ borderBottom: '1px solid var(--border-light)' }}
            >
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: '#F28B82' }} />
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: '#FDD663' }} />
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: '#81C995' }} />
              <span className="ml-3 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                opensecx — attack-surface
              </span>
              <div className="ml-auto flex items-center gap-1.5">
                <span className="status-dot online" style={{ width: '5px', height: '5px' }} />
                <span className="text-[10px] font-mono" style={{ color: 'rgba(129,201,149,0.7)' }}>
                  live
                </span>
              </div>
            </div>

            {/* KPI row — shows live data if available, placeholders if not */}
            <div className="grid grid-cols-3 gap-px" style={{ background: 'var(--border-light)' }}>
              {[
                {
                  l: 'Total Assets',
                  v: stats ? stats.total_assets.toLocaleString() : '—',
                  c: 'var(--text-primary)',
                },
                {
                  l: 'Needs Attention',
                  v: stats ? (stats.warning_assets + stats.critical_assets).toString() : '—',
                  c: '#FDD663',
                },
                {
                  l: 'Scans Run',
                  v: stats ? stats.total_scans.toLocaleString() : '—',
                  c: '#A8C7FA',
                },
              ].map((k) => (
                <div key={k.l} className="px-4 py-4" style={{ background: 'var(--bg-surface)' }}>
                  <p className="text-xs mb-1" style={{ color: 'var(--text-tertiary)' }}>
                    {k.l}
                  </p>
                  <p className="text-2xl font-light font-mono" style={{ color: k.c }}>
                    {k.v}
                  </p>
                </div>
              ))}
            </div>

            {/* Asset table header */}
            <div
              className="px-4 py-2 grid grid-cols-3 text-[10px] font-medium uppercase tracking-wider"
              style={{
                color: 'var(--text-muted)',
                borderBottom: '1px solid var(--border-light)',
              }}
            >
              <span>Asset / Domain</span>
              <span>IP Address</span>
              <span>Status</span>
            </div>

            {/* Static demo data — landing page is public, shows what the tool CAN display */}
            <div className="p-3 space-y-1.5">
              {[
                { domain: 'api.target.com', ip: '104.21.45.22', status: 'Active', statusColor: '#81C995' },
                { domain: 'dev.target.com', ip: '172.67.18.94', status: 'Warning', statusColor: '#FDD663' },
                { domain: 'mail.target.com', ip: '198.41.222.10', status: 'Active', statusColor: '#81C995' },
              ].map((r) => (
                <div
                  key={r.domain}
                  className="grid grid-cols-3 items-center py-2 px-3 rounded-md"
                  style={{
                    background: 'var(--border-light)',
                    border: '1px solid var(--border-light)',
                  }}
                >
                  <p className="text-xs font-mono truncate pr-2" style={{ color: 'var(--text-primary)' }}>
                    {r.domain}
                  </p>
                  <p className="text-[10px] font-mono truncate pr-2" style={{ color: 'var(--text-tertiary)' }}>
                    {r.ip}
                  </p>
                  <span
                    className="inline-flex items-center gap-1 text-[10px] font-medium"
                    style={{ color: r.statusColor }}
                  >
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: r.statusColor }} />
                    {r.status}
                  </span>
                </div>
              ))}
              <p className="text-center text-[10px] py-1" style={{ color: 'var(--text-muted)' }}>
                — Your results appear in the platform after scanning —
              </p>
            </div>
          </div>
        </div>

        {/* Scroll indicator */}
        <div
          className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2"
          style={{ color: 'var(--text-muted)' }}
        >
          <span className="text-[11px] tracking-widest uppercase">Scroll</span>
          <div
            className="w-px h-8"
            style={{ background: 'linear-gradient(to bottom, var(--text-muted), transparent)' }}
          />
        </div>
      </section>

      {/* ── Platform Phases ───────────────────────────────────────────────── */}
      <section
        id="platform"
        className="py-14"
        style={{ borderTop: '1px solid var(--border-light)' }}
      >
        <div className="max-w-7xl mx-auto px-6">
          <p className="section-label">The OpenSecX Workflow</p>
          <h2
            className="text-3xl font-semibold mb-4"
            style={{ letterSpacing: '-0.02em' }}
          >
            Four phases. One platform.
          </h2>
          <p className="text-sm mb-8 max-w-xl" style={{ color: 'var(--text-secondary)' }}>
            Built incrementally. Phase 1 is live. Phases 2–4 are in active development.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
            {phases.map((p, i) => (
              <div
                key={p.num}
                className="relative p-6 rounded-xl transition-all"
                style={{
                  border: '1px solid var(--border-light)',
                  background: 'var(--border-light)',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--border-light)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--border-light)')}
              >
                {/* Phase connector */}
                {i < phases.length - 1 && (
                  <div
                    className="hidden lg:flex absolute top-10 -right-3 z-10 items-center"
                    style={{ width: '24px' }}
                  >
                    <div className="flex-1 h-px" style={{ background: 'var(--border-medium)' }} />
                    <ChevronRight className="w-3 h-3" style={{ color: 'var(--border-medium)' }} />
                  </div>
                )}

                {/* Phase number */}
                <p
                  className="text-4xl font-light mb-4 font-mono"
                  style={{ color: p.color, opacity: 0.65 }}
                >
                  {p.num}
                </p>

                <h3 className="text-base font-semibold mb-3">{p.title}</h3>
                <p className="text-sm leading-relaxed mb-5" style={{ color: 'var(--text-secondary)' }}>
                  {p.desc}
                </p>

                {/* Tool tags */}
                <div className="flex flex-wrap gap-1.5">
                  {p.tools.map((t) => (
                    <span
                      key={t}
                      className="text-[10px] px-2 py-0.5 rounded font-mono"
                      style={{
                        background: 'var(--border-light)',
                        border: '1px solid var(--border-light)',
                        color: 'var(--text-tertiary)',
                      }}
                    >
                      {t}
                    </span>
                  ))}
                </div>

                {/* Phase 1 active indicator */}
                {i === 0 && (
                  <div
                    className="mt-4 flex items-center gap-1.5 text-[10px]"
                    style={{ color: '#81C995' }}
                  >
                    <span className="status-dot online" style={{ width: '5px', height: '5px' }} />
                    Active
                  </div>
                )}
                {i > 0 && (
                  <div
                    className="mt-4 text-[10px]"
                    style={{ color: 'var(--text-muted)' }}
                  >
                    Coming in Phase {i + 1}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Features ───────────────────────────────────────────────────────── */}
      <section
        id="features"
        className="py-14"
        style={{ borderTop: '1px solid var(--border-light)' }}
      >
        <div className="max-w-7xl mx-auto px-6">
          <p className="section-label">Capabilities</p>
          <h2
            className="text-3xl font-semibold mb-4"
            style={{ letterSpacing: '-0.02em' }}
          >
            Everything a security team needs.
          </h2>
          <p className="text-sm mb-8 max-w-xl" style={{ color: 'var(--text-secondary)' }}>
            Not another isolated scanner. An orchestration platform that integrates proven tools,
            normalizes results, and presents them in one clear interface.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {features.map((f, idx) => (
              <div
                key={f.title}
                className="p-6 rounded-xl transition-all animate-fade-in"
                style={{
                  border: '1px solid var(--border-light)',
                  background: 'var(--border-light)',
                  animationDelay: `${idx * 0.08}s`,
                  opacity: 0,
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--border-light)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--border-light)')}
              >
                <div
                  className="w-9 h-9 rounded-lg flex items-center justify-center mb-5"
                  style={{ background: 'var(--border-light)', border: '1px solid var(--border-light)' }}
                >
                  <f.icon className="w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
                </div>
                <h3 className="font-semibold mb-2 text-base">{f.title}</h3>
                <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                  {f.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Architecture ─────────────────────────────────────────────────── */}
      <section
        id="architecture"
        className="py-14"
        style={{ borderTop: '1px solid var(--border-light)' }}
      >
        <div className="max-w-7xl mx-auto px-6">
          <p className="section-label">Architecture</p>
          <h2
            className="text-3xl font-semibold mb-4"
            style={{ letterSpacing: '-0.02em' }}
          >
            Orchestrating the best open-source tools.
          </h2>
          <p className="text-base mb-6 max-w-2xl" style={{ color: 'var(--text-secondary)' }}>
            OpenSecX doesn't replace security tools — it orchestrates them. Each tool runs
            through a normalized adapter. Results flow into a unified data model with deduplication,
            enrichment and risk scoring.
          </p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 items-start">
            {/* Data flow diagram */}
            <div
              className="p-6 rounded-xl font-mono text-sm"
              style={{
                background: 'rgba(18,17,19,0.9)',
                border: '1px solid var(--border-light)',
              }}
            >
              <p className="text-xs section-label mb-4">Data flow</p>
              {[
                { label: 'Target Domain / IP', color: 'var(--text-primary)', indent: 0 },
                { label: '  ↓', color: 'var(--border-medium)', indent: 0 },
                { label: 'Asset Discovery & OSINT (Phase 1)', color: '#A8C7FA', indent: 0 },
                { label: '  ↓  crt.sh · Subfinder · dnsx · httpx · Nmap', color: 'rgba(168,199,250,0.45)', indent: 0 },
                { label: 'Attack Surface Inventory', color: '#A8C7FA', indent: 0 },
                { label: '  ↓', color: 'var(--border-medium)', indent: 0 },
                { label: 'VAPT Assessment (Phase 2)', color: '#81C995', indent: 0 },
                { label: '  ↓  Nuclei · ZAP · Nikto · SSLyze', color: 'rgba(129,201,149,0.45)', indent: 0 },
                { label: 'Finding Normalization', color: '#81C995', indent: 0 },
                { label: '  ↓', color: 'var(--border-medium)', indent: 0 },
                { label: 'Risk Scoring + Threat Intel (Phase 3)', color: '#FDD663', indent: 0 },
                { label: '  ↓  CVSS · EPSS · NVD · ATT&CK', color: 'rgba(253,214,99,0.45)', indent: 0 },
                { label: 'Compliance Mapping', color: '#FDD663', indent: 0 },
                { label: '  ↓', color: 'var(--border-medium)', indent: 0 },
                { label: 'Dashboard & Reports (Phase 4)', color: 'var(--text-primary)', indent: 0 },
              ].map((row, i) => (
                <p
                  key={i}
                  style={{ color: row.color, margin: '2px 0', fontSize: '12px', lineHeight: '1.6' }}
                >
                  {row.label}
                </p>
              ))}
            </div>

            {/* Tool chain grid */}
            <div>
              <p className="text-sm mb-5" style={{ color: 'var(--text-tertiary)' }}>
                Integrated scanner adapters — plugin architecture
              </p>
              <div className="grid grid-cols-2 gap-2">
                {toolChain.map((t) => (
                  <div
                    key={t.name}
                    className="flex items-center justify-between px-3 py-2.5 rounded-lg"
                    style={{
                      background: 'var(--border-light)',
                      border: '1px solid var(--border-light)',
                    }}
                  >
                    <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                      {t.name}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <span
                        className="text-[10px] px-1.5 py-0.5 rounded font-mono"
                        style={{
                          background: phaseTagColor[t.phase],
                          color: phaseTextColor[t.phase],
                        }}
                      >
                        {t.tag}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
              <p className="text-xs mt-4" style={{ color: 'var(--text-muted)' }}>
                New scanner adapters can be added without modifying core business logic.
              </p>

              {/* Stack info */}
              <div className="mt-8 space-y-2">
                {[
                  { icon: Server, label: 'FastAPI + SQLAlchemy + SQLite / PostgreSQL' },
                  { icon: Layers, label: 'React + TypeScript + Vite' },
                  { icon: Cpu, label: 'Docker + Docker Compose deployment' },
                  { icon: Lock, label: 'JWT auth · RBAC · Audit logging' },
                ].map((item) => (
                  <div
                    key={item.label}
                    className="flex items-center gap-3 text-xs"
                    style={{ color: 'var(--text-tertiary)' }}
                  >
                    <item.icon className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--text-tertiary)' }} />
                    {item.label}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── CTA ──────────────────────────────────────────────────────────── */}
      <section
        className="py-12"
        style={{ borderTop: '1px solid var(--border-light)' }}
      >
        <div className="max-w-7xl mx-auto px-6">
          <div
            className="rounded-xl p-8 text-center"
            style={{
              background: 'var(--border-light)',
              border: '1px solid var(--border-light)',
            }}
          >
            <p className="section-label mb-4">Get Started</p>
            <h2
              className="text-3xl font-semibold mb-4"
              style={{ letterSpacing: '-0.02em' }}
            >
              Ready to see your attack surface?
            </h2>
            <p className="text-base mb-8 max-w-md mx-auto" style={{ color: 'var(--text-secondary)' }}>
              OpenSecX is open-source and designed for authorized security testing only.
              Run a scan on systems you own or are explicitly authorized to assess.
            </p>
            <div className="flex flex-wrap items-center justify-center gap-3">
              <Link
                to="/attack-surface"
                className="btn-primary"
                style={{ padding: '12px 28px', fontSize: '14px' }}
              >
                Open Platform
                <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                to="/dashboard"
                className="btn-ghost"
                style={{ padding: '12px 28px', fontSize: '14px' }}
              >
                View Dashboard
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ── Footer ───────────────────────────────────────────────────────── */}
      <footer
        className="py-8"
        style={{ borderTop: '1px solid var(--border-light)' }}
      >
        <div
          className="max-w-7xl mx-auto px-6 flex items-center justify-between text-xs"
          style={{ color: 'var(--text-muted)' }}
        >
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
            <span className="font-semibold text-sm" style={{ color: 'var(--text-secondary)' }}>
              OpenSecX
            </span>
          </div>
          <span>Open-source cybersecurity exposure management · Authorized use only</span>
          <span className="font-mono">Phase 1 — v1.0.0</span>
        </div>
      </footer>
    </div>
  );
}
