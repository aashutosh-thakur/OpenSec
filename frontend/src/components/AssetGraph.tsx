import { useEffect, useRef, useState } from 'react';

interface GraphNode {
  id: string;
  label: string;
  type: 'domain' | 'subdomain' | 'ip' | 'port';
  x: number;
  y: number;
  vx: number;
  vy: number;
  status?: string;
}

interface GraphEdge {
  source: string;
  target: string;
}

const TYPE_COLOR: Record<string, string> = {
  domain:    'var(--text-primary)',
  subdomain: '#A8C7FA',
  ip:        '#81C995',
  port:      '#FDD663',
};

const TYPE_RADIUS: Record<string, number> = {
  domain:    18,
  subdomain: 12,
  ip:        10,
  port:      6,
};

function buildGraph(): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [
    { id: 'example.com', label: 'example.com', type: 'domain', x: 0, y: 0, vx: 0, vy: 0 },
    { id: 'api.example.com', label: 'api.', type: 'subdomain', x: 0, y: 0, vx: 0, vy: 0 },
    { id: 'dev.example.com', label: 'dev.', type: 'subdomain', x: 0, y: 0, vx: 0, vy: 0, status: 'Warning' },
    { id: 'mail.example.com', label: 'mail.', type: 'subdomain', x: 0, y: 0, vx: 0, vy: 0 },
    { id: 'staging.example.com', label: 'staging.', type: 'subdomain', x: 0, y: 0, vx: 0, vy: 0 },
    { id: 'vpn.example.com', label: 'vpn.', type: 'subdomain', x: 0, y: 0, vx: 0, vy: 0 },
    { id: 'legacy.example.com', label: 'legacy.', type: 'subdomain', x: 0, y: 0, vx: 0, vy: 0, status: 'Critical' },
    { id: 'ip-93.184.216.34', label: '93.184.216.34', type: 'ip', x: 0, y: 0, vx: 0, vy: 0 },
    { id: 'ip-93.184.216.35', label: '93.184.216.35', type: 'ip', x: 0, y: 0, vx: 0, vy: 0 },
    { id: 'ip-93.184.216.36', label: '93.184.216.36', type: 'ip', x: 0, y: 0, vx: 0, vy: 0, status: 'Warning' },
    { id: 'ip-104.21.45.78', label: '104.21.45.78', type: 'ip', x: 0, y: 0, vx: 0, vy: 0 },
    { id: 'port-80', label: ':80', type: 'port', x: 0, y: 0, vx: 0, vy: 0 },
    { id: 'port-443', label: ':443', type: 'port', x: 0, y: 0, vx: 0, vy: 0 },
    { id: 'port-22', label: ':22', type: 'port', x: 0, y: 0, vx: 0, vy: 0, status: 'Warning' },
    { id: 'port-8080', label: ':8080', type: 'port', x: 0, y: 0, vx: 0, vy: 0 },
  ];

  const edges: GraphEdge[] = [
    { source: 'example.com', target: 'api.example.com' },
    { source: 'example.com', target: 'dev.example.com' },
    { source: 'example.com', target: 'mail.example.com' },
    { source: 'example.com', target: 'staging.example.com' },
    { source: 'example.com', target: 'vpn.example.com' },
    { source: 'example.com', target: 'legacy.example.com' },
    { source: 'api.example.com', target: 'ip-93.184.216.35' },
    { source: 'dev.example.com', target: 'ip-93.184.216.36' },
    { source: 'mail.example.com', target: 'ip-93.184.216.34' },
    { source: 'staging.example.com', target: 'ip-104.21.45.78' },
    { source: 'ip-93.184.216.35', target: 'port-443' },
    { source: 'ip-93.184.216.36', target: 'port-22' },
    { source: 'ip-93.184.216.36', target: 'port-8080' },
    { source: 'ip-93.184.216.34', target: 'port-80' },
    { source: 'ip-93.184.216.34', target: 'port-443' },
  ];

  return { nodes, edges };
}

export default function AssetGraph({ onNodeClick }: { onNodeClick?: (id: string) => void }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const nodesRef = useRef<GraphNode[]>([]);
  const hoveredRef = useRef<string | null>(null);
  const animRef = useRef<number>(0);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; label: string; type: string } | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const { nodes, edges } = buildGraph();

    // Position nodes in a radial layout
    const cx = canvas.offsetWidth / 2;
    const cy = canvas.offsetHeight / 2;
    nodes[0].x = cx; nodes[0].y = cy; // root at center

    const subdomains = nodes.filter(n => n.type === 'subdomain');
    subdomains.forEach((n, i) => {
      const angle = (i / subdomains.length) * Math.PI * 2 - Math.PI / 2;
      n.x = cx + Math.cos(angle) * 130;
      n.y = cy + Math.sin(angle) * 100;
    });

    const ips = nodes.filter(n => n.type === 'ip');
    ips.forEach((n, i) => {
      const angle = (i / ips.length) * Math.PI * 2 - Math.PI / 4;
      n.x = cx + Math.cos(angle) * 230;
      n.y = cy + Math.sin(angle) * 180;
    });

    const ports = nodes.filter(n => n.type === 'port');
    ports.forEach((n, i) => {
      const angle = (i / ports.length) * Math.PI * 2;
      n.x = cx + Math.cos(angle) * 320;
      n.y = cy + Math.sin(angle) * 230;
    });

    nodesRef.current = nodes;

    const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]));

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    const draw = () => {
      if (!ctx) return;
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Edges
      edges.forEach(e => {
        const s = nodeMap[e.source];
        const t = nodeMap[e.target];
        if (!s || !t) return;
        ctx.beginPath();
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);
        const isHovered = hoveredRef.current === e.source || hoveredRef.current === e.target;
        ctx.strokeStyle = isHovered ? 'var(--text-muted)' : 'var(--border-light)';
        ctx.lineWidth = isHovered ? 1.5 : 0.8;
        ctx.stroke();
      });

      // Nodes
      nodes.forEach(n => {
        const r = TYPE_RADIUS[n.type];
        const isHovered = hoveredRef.current === n.id;
        const baseColor = n.status === 'Critical' ? '#F28B82' : n.status === 'Warning' ? '#FDD663' : TYPE_COLOR[n.type];

        // Glow for hovered
        if (isHovered) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
          ctx.fillStyle = `${baseColor}20`;
          ctx.fill();
        }

        // Node circle
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = isHovered ? baseColor : `${baseColor}AA`;
        ctx.fill();

        // Border
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.strokeStyle = `${baseColor}50`;
        ctx.lineWidth = 1;
        ctx.stroke();

        // Label for larger nodes
        if (n.type === 'domain' || n.type === 'subdomain' || isHovered) {
          ctx.fillStyle = isHovered ? 'var(--text-primary)' : 'var(--text-secondary)';
          ctx.font = `${n.type === 'domain' ? 11 : 9}px IBM Plex Mono, monospace`;
          ctx.textAlign = 'center';
          ctx.fillText(n.label, n.x, n.y + r + 12);
        }
      });

      animRef.current = requestAnimationFrame(draw);
    };

    draw();

    // Mouse tracking
    const onMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      let found: GraphNode | null = null;
      for (const n of nodesRef.current) {
        const r = TYPE_RADIUS[n.type];
        const dx = n.x - mx;
        const dy = n.y - my;
        if (Math.sqrt(dx * dx + dy * dy) < r + 4) {
          found = n;
          break;
        }
      }

      if (found) {
        hoveredRef.current = found.id;
        canvas.style.cursor = 'pointer';
        setTooltip({ x: e.clientX - rect.left, y: e.clientY - rect.top, label: found.id, type: found.type });
      } else {
        hoveredRef.current = null;
        canvas.style.cursor = 'default';
        setTooltip(null);
      }
    };

    const onClick = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      for (const n of nodesRef.current) {
        const r = TYPE_RADIUS[n.type];
        const dx = n.x - mx;
        const dy = n.y - my;
        if (Math.sqrt(dx * dx + dy * dy) < r + 4) {
          onNodeClick?.(n.id);
          break;
        }
      }
    };

    canvas.addEventListener('mousemove', onMouseMove);
    canvas.addEventListener('click', onClick);

    return () => {
      cancelAnimationFrame(animRef.current);
      canvas.removeEventListener('mousemove', onMouseMove);
      canvas.removeEventListener('click', onClick);
      window.removeEventListener('resize', resize);
    };
  }, [onNodeClick]);

  return (
    <div className="relative w-full h-full">
      <canvas ref={canvasRef} className="w-full h-full" style={{ display: 'block' }} />

      {/* Legend */}
      <div
        className="absolute bottom-3 left-3 flex items-center gap-4 px-3 py-2 rounded-lg text-xs"
        style={{ background: 'rgba(30,29,31,0.9)', border: '1px solid var(--border-light)' }}
      >
        {Object.entries(TYPE_COLOR).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: color }} />
            <span style={{ color: 'var(--text-secondary)' }} className="capitalize">{type}</span>
          </div>
        ))}
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: '#F28B82' }} />
          <span style={{ color: 'var(--text-secondary)' }}>Risk</span>
        </div>
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="absolute pointer-events-none px-2.5 py-1.5 rounded-md text-xs font-mono"
          style={{
            left: tooltip.x + 14,
            top: tooltip.y - 8,
            background: 'rgba(30,29,31,0.95)',
            border: '1px solid var(--border-medium)',
            color: 'var(--text-primary)',
            zIndex: 10,
          }}
        >
          <p>{tooltip.label}</p>
          <p style={{ color: 'var(--text-tertiary)' }} className="capitalize">{tooltip.type}</p>
        </div>
      )}
    </div>
  );
}
