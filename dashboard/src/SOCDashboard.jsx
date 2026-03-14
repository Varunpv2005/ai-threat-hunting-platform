import { useState, useEffect, useRef, useCallback } from "react";
import {
  Chart as ChartJS,
  CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, ArcElement, RadialLinearScale,
  Title, Tooltip, Legend, Filler,
} from "chart.js";
import { Line, Bar, Doughnut } from "react-chartjs-2";

ChartJS.register(
  CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, ArcElement, RadialLinearScale,
  Title, Tooltip, Legend, Filler
);

// ─────────────────────────────────────────────────────────────────
// API Layer — swap BASE_URL to connect to your FastAPI backend
// ─────────────────────────────────────────────────────────────────
const BASE_URL = "http://localhost:8000/api/v1";

const api = {
  get: async (path) => {
    try {
      const r = await fetch(`${BASE_URL}${path}`);
      const j = await r.json();
      return j.data ?? j;
    } catch {
      return null;
    }
  },
  post: async (path, body) => {
    try {
      const r = await fetch(`${BASE_URL}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = await r.json();
      return j.data ?? j;
    } catch {
      return null;
    }
  },
};

// ─────────────────────────────────────────────────────────────────
// Deterministic mock data (used when backend is offline)
// ─────────────────────────────────────────────────────────────────
const MOCK_STATS = {
  total_logs: 18472, total_threats: 347, total_alerts: 89,
  open_alerts: 23, critical_count: 12, high_count: 31,
  detection_rate: 0.0188,
  threats_by_category: {
    brute_force: 142, data_exfiltration: 67,
    privilege_escalation: 54, suspicious_login: 48,
    password_spray: 24, automated_scanner: 12,
  },
  alerts_by_severity: { CRITICAL: 12, HIGH: 31, MEDIUM: 28, LOW: 18 },
  top_source_ips: [
    { ip: "185.220.101.15", count: 34 },
    { ip: "203.0.113.42",   count: 28 },
    { ip: "162.247.72.199", count: 21 },
    { ip: "198.51.100.7",   count: 17 },
    { ip: "89.163.207.56",  count: 14 },
  ],
  top_targeted_users: [
    { user: "alice", count: 41 }, { user: "admin", count: 35 },
    { user: "root",  count: 29 }, { user: "david", count: 18 },
    { user: "carol", count: 12 },
  ],
};

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

// Seeded deterministic timeline (24h)
const MOCK_TIMELINE = (() => {
  const seed = [3,1,0,0,2,1,4,8,12,7,5,9,15,11,6,14,19,22,16,9,7,4,3,2];
  const labels = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2,"0")}:00`);
  return { labels, values: seed };
})();

const MOCK_THREATS = [
  { threat_id:"t1", timestamp:"2024-01-15T03:22:00Z", source_ip:"185.220.101.15", username:"alice",
    anomaly_score:97.5, threat_category:"brute_force", severity:"CRITICAL",
    primary_confidence:0.97, mitre_techniques:["T1110.001","T1110.003"] },
  { threat_id:"t2", timestamp:"2024-01-15T07:45:00Z", source_ip:"203.0.113.42", username:"admin",
    anomaly_score:91.2, threat_category:"privilege_escalation", severity:"CRITICAL",
    primary_confidence:0.89, mitre_techniques:["T1548.003","T1078"] },
  { threat_id:"t3", timestamp:"2024-01-15T09:12:00Z", source_ip:"10.0.1.33", username:"david",
    anomaly_score:88.4, threat_category:"data_exfiltration", severity:"CRITICAL",
    primary_confidence:0.92, mitre_techniques:["T1005","T1025"] },
  { threat_id:"t4", timestamp:"2024-01-15T11:30:00Z", source_ip:"162.247.72.199", username:"carol",
    anomaly_score:86.1, threat_category:"suspicious_login", severity:"HIGH",
    primary_confidence:0.81, mitre_techniques:["T1078","T1133"] },
  { threat_id:"t5", timestamp:"2024-01-15T13:55:00Z", source_ip:"198.51.100.7", username:"bob",
    anomaly_score:79.3, threat_category:"password_spray", severity:"HIGH",
    primary_confidence:0.74, mitre_techniques:["T1110.003"] },
  { threat_id:"t6", timestamp:"2024-01-15T16:22:00Z", source_ip:"89.163.207.56", username:"root",
    anomaly_score:68.7, threat_category:"automated_scanner", severity:"MEDIUM",
    primary_confidence:0.63, mitre_techniques:["T1595","T1046"] },
];

const MOCK_ALERTS = [
  { alert_id:"a1", timestamp:"2024-01-15T03:22:00Z", severity:"CRITICAL",
    title:"Brute Force Attack Detected", category:"brute_force",
    source_ip:"185.220.101.15", username:"alice",
    description:"35 failed login attempts from RU-origin IP in 14 seconds. Account locked.",
    actions_taken:["block_ip","disable_user","send_alert"], status:"open" },
  { alert_id:"a2", timestamp:"2024-01-15T07:45:00Z", severity:"CRITICAL",
    title:"Privilege Escalation Attempt", category:"privilege_escalation",
    source_ip:"203.0.113.42", username:"admin",
    description:"7 admin_access events + /etc/shadow read. Host quarantined.",
    actions_taken:["disable_user","quarantine_host","rotate_credentials"], status:"open" },
  { alert_id:"a3", timestamp:"2024-01-15T09:12:00Z", severity:"CRITICAL",
    title:"Data Exfiltration Activity", category:"data_exfiltration",
    source_ip:"10.0.1.33", username:"david",
    description:"18.4 GB read from sensitive paths via rsync. Outbound blocked.",
    actions_taken:["block_ip","rate_limit_user","send_alert"], status:"acknowledged" },
  { alert_id:"a4", timestamp:"2024-01-15T11:30:00Z", severity:"HIGH",
    title:"Suspicious Login – High-Risk Country", category:"suspicious_login",
    source_ip:"162.247.72.199", username:"carol",
    description:"Successful auth from KP without MFA. MFA enforcement applied.",
    actions_taken:["enforce_mfa","send_alert"], status:"open" },
  { alert_id:"a5", timestamp:"2024-01-15T13:55:00Z", severity:"HIGH",
    title:"Password Spray Attack", category:"password_spray",
    source_ip:"198.51.100.7", username:"multiple",
    description:"Single IP targeted 8 accounts. 48h block applied.",
    actions_taken:["block_ip","send_alert"], status:"resolved" },
];

// ─────────────────────────────────────────────────────────────────
// Design tokens
// ─────────────────────────────────────────────────────────────────
const C = {
  bg:       "#080c10",
  surface:  "#0d1117",
  border:   "#1a2332",
  dim:      "#1e2d3d",
  muted:    "#3d5166",
  text:     "#8fb5cc",
  bright:   "#c8e6fa",
  green:    "#00ff88",
  greenDim: "#00cc6a",
  amber:    "#ffb347",
  red:      "#ff4655",
  redDim:   "#cc2233",
  cyan:     "#00d4ff",
  purple:   "#8b5cf6",
  critical: "#ff4655",
  high:     "#ff8c42",
  medium:   "#ffd60a",
  low:      "#00d4ff",
  info:     "#3d5166",
};

const sevColor = (s) => ({
  CRITICAL: C.critical, HIGH: C.high,
  MEDIUM: C.medium, LOW: C.low, INFO: C.info,
}[s] ?? C.muted);

const catIcon = (c) => ({
  brute_force: "⚡", privilege_escalation: "⬆", data_exfiltration: "📤",
  suspicious_login: "🌐", password_spray: "🌊", automated_scanner: "🤖",
  unknown: "?",
}[c] ?? "?");

// ─────────────────────────────────────────────────────────────────
// Global styles (injected once)
// ─────────────────────────────────────────────────────────────────
const GLOBAL_CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: ${C.bg}; --surface: ${C.surface}; --border: ${C.border};
    --dim: ${C.dim}; --muted: ${C.muted}; --text: ${C.text};
    --bright: ${C.bright}; --green: ${C.green}; --green-dim: ${C.greenDim};
    --amber: ${C.amber}; --red: ${C.red}; --cyan: ${C.cyan};
    --font-mono: 'Share Tech Mono', monospace;
    --font-ui: 'Rajdhani', sans-serif;
  }

  html, body, #root { height: 100%; background: var(--bg); color: var(--text); }
  body { font-family: var(--font-ui); font-size: 14px; overflow-x: hidden; }

  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--muted); border-radius: 2px; }

  .soc-scanline {
    pointer-events: none;
    position: fixed; inset: 0; z-index: 9999;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,255,136,0.015) 2px,
      rgba(0,255,136,0.015) 4px
    );
  }

  .soc-grid-bg {
    background-image:
      linear-gradient(rgba(0,212,255,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.04) 1px, transparent 1px);
    background-size: 48px 48px;
  }

  @keyframes pulse-dot { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
  @keyframes slide-in  { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
  @keyframes blink     { 0%,49% { opacity: 1; } 50%,100% { opacity: 0; } }
  @keyframes glitch    {
    0%,100% { clip-path: inset(0 0 100% 0); }
    20%     { clip-path: inset(30% 0 50% 0); transform: translateX(-2px); }
    40%     { clip-path: inset(60% 0 10% 0); transform: translateX(2px); }
    60%     { clip-path: inset(10% 0 70% 0); transform: translateX(-1px); }
    80%     { clip-path: inset(80% 0 5% 0);  transform: translateX(1px); }
  }
  @keyframes sweep { from { width: 0; } to { width: 100%; } }

  .card-animate { animation: slide-in 0.35s ease both; }

  .soc-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 2px;
    position: relative;
    overflow: hidden;
  }
  .soc-card::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent);
    opacity: 0.5;
  }

  .threat-row {
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
    cursor: default;
  }
  .threat-row:hover { background: rgba(0,212,255,0.04); }
  .threat-row:last-child { border-bottom: none; }

  .alert-row { border-left: 2px solid transparent; transition: all 0.15s; }
  .alert-row:hover { border-left-color: var(--cyan); background: rgba(0,212,255,0.03); }

  .sev-badge {
    font-family: var(--font-mono); font-size: 10px; font-weight: bold;
    padding: 2px 6px; border-radius: 2px; letter-spacing: 0.08em;
    border: 1px solid currentColor;
  }

  .stat-val {
    font-family: var(--font-mono);
    font-size: 2.2rem;
    font-weight: 400;
    line-height: 1;
    letter-spacing: -0.02em;
  }

  .live-dot {
    display: inline-block; width: 7px; height: 7px;
    border-radius: 50%; background: var(--green);
    animation: pulse-dot 1.4s ease-in-out infinite;
    box-shadow: 0 0 6px var(--green);
  }

  .sweep-bar {
    height: 2px;
    background: linear-gradient(90deg, var(--cyan), var(--green));
    animation: sweep 1.2s ease both;
  }

  .section-label {
    font-family: var(--font-mono); font-size: 10px;
    letter-spacing: 0.15em; color: var(--muted);
    text-transform: uppercase;
  }

  .ip-tag {
    font-family: var(--font-mono); font-size: 11px;
    background: var(--dim); border: 1px solid var(--border);
    padding: 3px 8px; border-radius: 2px; color: var(--cyan);
    white-space: nowrap;
  }

  .sim-btn {
    font-family: var(--font-ui); font-weight: 600; font-size: 13px;
    letter-spacing: 0.06em; text-transform: uppercase;
    background: transparent; color: var(--green);
    border: 1px solid var(--green-dim);
    padding: 8px 16px; border-radius: 2px;
    cursor: pointer; transition: all 0.15s;
    white-space: nowrap;
  }
  .sim-btn:hover { background: rgba(0,255,136,0.08); border-color: var(--green); }
  .sim-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .sim-btn.danger { color: var(--red); border-color: var(--red); }
  .sim-btn.danger:hover { background: rgba(255,70,85,0.08); }

  select.soc-select {
    font-family: var(--font-mono); font-size: 11px;
    background: var(--dim); color: var(--text);
    border: 1px solid var(--border); border-radius: 2px;
    padding: 6px 10px; outline: none; cursor: pointer;
    appearance: none;
  }

  .console-text {
    font-family: var(--font-mono); font-size: 11px;
    color: var(--green); line-height: 1.6;
    white-space: pre-wrap; word-break: break-all;
  }

  .ticker-item { animation: slide-in 0.3s ease both; }
`;

function injectStyles() {
  if (document.getElementById("soc-global-css")) return;
  const el = document.createElement("style");
  el.id = "soc-global-css";
  el.textContent = GLOBAL_CSS;
  document.head.appendChild(el);
}

// ─────────────────────────────────────────────────────────────────
// Utility components
// ─────────────────────────────────────────────────────────────────

function SevBadge({ sev }) {
  return (
    <span className="sev-badge" style={{ color: sevColor(sev), borderColor: sevColor(sev) + "66" }}>
      {sev}
    </span>
  );
}

function SectionHeader({ label, sub, action }) {
  return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between",
                  padding:"14px 18px 0", marginBottom: 10 }}>
      <div>
        <div className="section-label">{label}</div>
        {sub && <div style={{ fontSize:12, color: C.muted, marginTop:2 }}>{sub}</div>}
      </div>
      {action}
    </div>
  );
}

function SweepBar() {
  return <div className="sweep-bar" />;
}

// ─────────────────────────────────────────────────────────────────
// Stat Card
// ─────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, accent, delay = 0 }) {
  const [displayed, setDisplayed] = useState(0);

  useEffect(() => {
    const target = typeof value === "number" ? value : 0;
    let start = null;
    const dur = 900;
    const step = (ts) => {
      if (!start) start = ts;
      const p = Math.min((ts - start) / dur, 1);
      const ease = 1 - Math.pow(1 - p, 3);
      setDisplayed(Math.round(ease * target));
      if (p < 1) requestAnimationFrame(step);
    };
    const t = setTimeout(() => requestAnimationFrame(step), delay);
    return () => clearTimeout(t);
  }, [value, delay]);

  return (
    <div className="soc-card card-animate" style={{ padding:"18px 20px", animationDelay:`${delay}ms` }}>
      <SweepBar />
      <div className="section-label" style={{ marginBottom: 10 }}>{label}</div>
      <div className="stat-val" style={{ color: accent || C.bright }}>
        {typeof value === "number"
          ? displayed.toLocaleString()
          : value}
      </div>
      {sub && <div style={{ fontSize:11, color: C.muted, marginTop:6, fontFamily:"var(--font-mono)" }}>{sub}</div>}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Attack Timeline Chart
// ─────────────────────────────────────────────────────────────────
function TimelineChart({ data }) {
  const chartData = {
    labels: data.labels,
    datasets: [
      {
        label: "Threats",
        data: data.values,
        fill: true,
        borderColor: C.cyan,
        borderWidth: 1.5,
        pointRadius: 0,
        pointHoverRadius: 4,
        pointHoverBackgroundColor: C.cyan,
        tension: 0.4,
        backgroundColor: (ctx) => {
          const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, 200);
          g.addColorStop(0, "rgba(0,212,255,0.18)");
          g.addColorStop(1, "rgba(0,212,255,0.01)");
          return g;
        },
      },
    ],
  };

  const options = {
    responsive: true, maintainAspectRatio: false,
    animation: { duration: 1200, easing: "easeOutQuart" },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: C.surface,
        borderColor: C.border,
        borderWidth: 1,
        titleColor: C.muted,
        bodyColor: C.bright,
        titleFont: { family: "'Share Tech Mono'" },
        bodyFont: { family: "'Share Tech Mono'" },
        callbacks: {
          title: (i) => `  ${i[0].label}`,
          label: (i) => `  threats: ${i.raw}`,
        },
      },
    },
    scales: {
      x: {
        grid: { color: "rgba(26,35,50,0.8)", drawTicks: false },
        ticks: { color: C.muted, font: { family:"'Share Tech Mono'", size:10 },
                 maxTicksLimit: 8, maxRotation: 0 },
        border: { color: C.border },
      },
      y: {
        grid: { color: "rgba(26,35,50,0.8)", drawTicks: false },
        ticks: { color: C.muted, font: { family:"'Share Tech Mono'", size:10 },
                 stepSize: 5 },
        border: { color: C.border },
        min: 0,
      },
    },
  };

  return (
    <div className="soc-card card-animate" style={{ animationDelay:"100ms" }}>
      <SweepBar />
      <SectionHeader label="Attack Timeline" sub="threats detected / hour (last 24h)" />
      <div style={{ padding:"0 18px 18px", height: 180 }}>
        <Line data={chartData} options={options} />
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Category Bar Chart
// ─────────────────────────────────────────────────────────────────
function CategoryChart({ data }) {
  const labels = Object.keys(data).map(k => k.replace(/_/g," "));
  const values = Object.values(data);
  const colors = [C.red, C.amber, C.purple, C.cyan, C.high, C.greenDim];

  const chartData = {
    labels,
    datasets: [{
      data: values,
      backgroundColor: colors.map(c => c + "cc"),
      borderColor: colors,
      borderWidth: 1,
      borderRadius: 1,
      hoverBackgroundColor: colors,
    }],
  };

  const options = {
    indexAxis: "y",
    responsive: true, maintainAspectRatio: false,
    animation: { duration: 1000, easing: "easeOutQuart" },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: C.surface, borderColor: C.border, borderWidth: 1,
        titleColor: C.muted, bodyColor: C.bright,
        titleFont: { family:"'Share Tech Mono'" }, bodyFont: { family:"'Share Tech Mono'" },
      },
    },
    scales: {
      x: {
        grid: { color: "rgba(26,35,50,0.8)" },
        ticks: { color: C.muted, font: { family:"'Share Tech Mono'", size:10 } },
        border: { color: C.border },
      },
      y: {
        grid: { display: false },
        ticks: { color: C.text, font: { family:"'Rajdhani'", size:12, weight:"500" } },
        border: { display: false },
      },
    },
  };

  return (
    <div className="soc-card card-animate" style={{ animationDelay:"150ms" }}>
      <SweepBar />
      <SectionHeader label="Threat Categories" sub="by detection count" />
      <div style={{ padding:"0 18px 18px", height: 220 }}>
        <Bar data={chartData} options={options} />
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Severity Donut
// ─────────────────────────────────────────────────────────────────
function SeverityDonut({ data }) {
  const labels = SEV_ORDER.filter(s => data[s]);
  const values = labels.map(s => data[s]);
  const colors = labels.map(sevColor);

  const chartData = {
    labels,
    datasets: [{
      data: values,
      backgroundColor: colors.map(c => c + "bb"),
      borderColor: colors,
      borderWidth: 1,
      hoverOffset: 4,
    }],
  };

  const options = {
    responsive: true, maintainAspectRatio: false,
    cutout: "72%",
    animation: { duration: 900, easing: "easeOutQuart" },
    plugins: {
      legend: {
        position: "right",
        labels: {
          color: C.text, font: { family:"'Share Tech Mono'", size:11 },
          boxWidth: 12, padding: 10,
          generateLabels: (chart) => {
            const ds = chart.data.datasets[0];
            return chart.data.labels.map((l, i) => ({
              text: `${l.padEnd(9)} ${ds.data[i]}`,
              fillStyle: ds.backgroundColor[i],
              strokeStyle: ds.borderColor[i],
              lineWidth: 1, index: i,
            }));
          },
        },
      },
      tooltip: {
        backgroundColor: C.surface, borderColor: C.border, borderWidth: 1,
        titleColor: C.muted, bodyColor: C.bright,
        titleFont: { family:"'Share Tech Mono'" }, bodyFont: { family:"'Share Tech Mono'" },
      },
    },
  };

  const total = values.reduce((a,b) => a+b, 0);

  return (
    <div className="soc-card card-animate" style={{ animationDelay:"200ms" }}>
      <SweepBar />
      <SectionHeader label="Alert Severity" sub={`${total} total alerts`} />
      <div style={{ padding:"0 18px 18px", height: 180, position:"relative" }}>
        <Doughnut data={chartData} options={options} />
        <div style={{ position:"absolute", top:"50%", left:"35%",
                      transform:"translate(-50%,-50%)", textAlign:"center",
                      pointerEvents:"none" }}>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:24, color:C.bright }}>{total}</div>
          <div className="section-label">total</div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Active Threats Table
// ─────────────────────────────────────────────────────────────────
function ThreatsTable({ threats }) {
  return (
    <div className="soc-card card-animate" style={{ animationDelay:"50ms" }}>
      <SweepBar />
      <SectionHeader
        label="Active Threats"
        sub={`${threats.filter(t => t.severity === "CRITICAL").length} critical`}
        action={<span className="section-label" style={{ color:C.red }}>● LIVE</span>}
      />
      <div style={{ overflowX:"auto" }}>
        <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
          <thead>
            <tr style={{ borderBottom:`1px solid ${C.border}` }}>
              {["SEV","TYPE","SOURCE IP","USER","SCORE","MITRE","TIME"].map(h => (
                <th key={h} style={{ padding:"7px 18px", textAlign:"left",
                                     fontFamily:"var(--font-mono)", fontSize:10,
                                     color:C.muted, fontWeight:"normal",
                                     letterSpacing:"0.1em", whiteSpace:"nowrap" }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {threats.map((t, i) => (
              <tr key={t.threat_id} className="threat-row"
                  style={{ animationDelay:`${i*40}ms` }}>
                <td style={{ padding:"10px 18px" }}>
                  <SevBadge sev={t.severity} />
                </td>
                <td style={{ padding:"10px 18px" }}>
                  <span style={{ display:"flex", alignItems:"center", gap:6 }}>
                    <span>{catIcon(t.threat_category)}</span>
                    <span style={{ color:C.bright, fontFamily:"var(--font-ui)",
                                   fontWeight:500, fontSize:12 }}>
                      {t.threat_category.replace(/_/g," ")}
                    </span>
                  </span>
                </td>
                <td style={{ padding:"10px 18px" }}>
                  <span className="ip-tag">{t.source_ip}</span>
                </td>
                <td style={{ padding:"10px 18px",
                             fontFamily:"var(--font-mono)", color:C.text, fontSize:11 }}>
                  {t.username}
                </td>
                <td style={{ padding:"10px 18px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                    <div style={{ width:48, height:4, background:C.dim, borderRadius:2 }}>
                      <div style={{ width:`${t.anomaly_score}%`, height:"100%",
                                    borderRadius:2, transition:"width 0.8s",
                                    background: t.anomaly_score>85 ? C.red :
                                                t.anomaly_score>65 ? C.amber : C.cyan }} />
                    </div>
                    <span style={{ fontFamily:"var(--font-mono)", fontSize:11,
                                   color:C.bright }}>{t.anomaly_score.toFixed(1)}</span>
                  </div>
                </td>
                <td style={{ padding:"10px 18px" }}>
                  <div style={{ display:"flex", gap:4, flexWrap:"wrap" }}>
                    {t.mitre_techniques.slice(0,2).map(m => (
                      <span key={m} style={{ fontFamily:"var(--font-mono)", fontSize:10,
                                             background:C.dim, padding:"2px 5px",
                                             borderRadius:1, color:C.purple,
                                             border:`1px solid ${C.purple}44` }}>
                        {m}
                      </span>
                    ))}
                  </div>
                </td>
                <td style={{ padding:"10px 18px",
                             fontFamily:"var(--font-mono)", fontSize:10, color:C.muted,
                             whiteSpace:"nowrap" }}>
                  {new Date(t.timestamp).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Security Alerts Feed
// ─────────────────────────────────────────────────────────────────
function AlertsFeed({ alerts }) {
  const statusColor = { open:C.red, acknowledged:C.amber, resolved:C.muted };

  return (
    <div className="soc-card card-animate" style={{ animationDelay:"120ms" }}>
      <SweepBar />
      <SectionHeader
        label="Security Alerts"
        sub={`${alerts.filter(a=>a.status==="open").length} open`}
      />
      <div style={{ padding:"0 18px 18px", display:"flex", flexDirection:"column", gap:8 }}>
        {alerts.map((a, i) => (
          <div key={a.alert_id} className="alert-row ticker-item"
               style={{ padding:"12px 14px", background:C.bg,
                        borderRadius:2, border:`1px solid ${C.border}`,
                        animationDelay:`${i*60}ms` }}>
            <div style={{ display:"flex", justifyContent:"space-between",
                          alignItems:"flex-start", gap:12, marginBottom:6 }}>
              <div style={{ display:"flex", alignItems:"center", gap:8, flexWrap:"wrap" }}>
                <SevBadge sev={a.severity} />
                <span style={{ fontFamily:"var(--font-ui)", fontWeight:600, fontSize:13,
                               color:C.bright }}>
                  {a.title}
                </span>
              </div>
              <span style={{ fontFamily:"var(--font-mono)", fontSize:10,
                             color:statusColor[a.status], whiteSpace:"nowrap",
                             border:`1px solid currentColor`, padding:"2px 6px",
                             borderRadius:2 }}>
                {a.status.toUpperCase()}
              </span>
            </div>
            <p style={{ fontSize:12, color:C.text, marginBottom:8, lineHeight:1.5 }}>
              {a.description}
            </p>
            <div style={{ display:"flex", alignItems:"center", gap:12, flexWrap:"wrap" }}>
              <span className="ip-tag">{a.source_ip}</span>
              <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:C.muted }}>
                user: {a.username}
              </span>
              <div style={{ display:"flex", gap:4, flexWrap:"wrap" }}>
                {a.actions_taken.map(ac => (
                  <span key={ac} style={{ fontFamily:"var(--font-mono)", fontSize:10,
                                          background:C.dim, padding:"2px 6px",
                                          borderRadius:2, color:C.greenDim }}>
                    {ac}
                  </span>
                ))}
              </div>
              <span style={{ marginLeft:"auto", fontFamily:"var(--font-mono)",
                             fontSize:10, color:C.muted }}>
                {new Date(a.timestamp).toLocaleString([], {
                  month:"short", day:"numeric",
                  hour:"2-digit", minute:"2-digit"
                })}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Suspicious IP Panel
// ─────────────────────────────────────────────────────────────────
function IPPanel({ ips, users }) {
  return (
    <div className="soc-card card-animate" style={{ animationDelay:"160ms" }}>
      <SweepBar />
      <SectionHeader label="Top Threat Sources" />
      <div style={{ padding:"0 18px 18px" }}>
        <div className="section-label" style={{ marginBottom:8, marginTop:4 }}>
          Suspicious IPs
        </div>
        <div style={{ display:"flex", flexDirection:"column", gap:6, marginBottom:18 }}>
          {ips.map((ip, i) => {
            const pct = (ip.count / ips[0].count) * 100;
            return (
              <div key={ip.ip} style={{ display:"flex", alignItems:"center", gap:10 }}>
                <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:C.muted,
                               width:14, textAlign:"right" }}>
                  {i+1}
                </span>
                <span className="ip-tag" style={{ minWidth:120 }}>{ip.ip}</span>
                <div style={{ flex:1, height:3, background:C.dim, borderRadius:2 }}>
                  <div style={{ width:`${pct}%`, height:"100%", borderRadius:2,
                                background:i===0?C.red:i<3?C.amber:C.cyan,
                                transition:"width 1s ease" }} />
                </div>
                <span style={{ fontFamily:"var(--font-mono)", fontSize:11,
                               color:C.bright, minWidth:28, textAlign:"right" }}>
                  {ip.count}
                </span>
              </div>
            );
          })}
        </div>

        <div className="section-label" style={{ marginBottom:8 }}>
          Top Targeted Users
        </div>
        <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
          {users.map((u, i) => {
            const pct = (u.count / users[0].count) * 100;
            return (
              <div key={u.user} style={{ display:"flex", alignItems:"center", gap:10 }}>
                <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:C.muted,
                               width:14, textAlign:"right" }}>
                  {i+1}
                </span>
                <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:C.text,
                               minWidth:60 }}>
                  {u.user}
                </span>
                <div style={{ flex:1, height:3, background:C.dim, borderRadius:2 }}>
                  <div style={{ width:`${pct}%`, height:"100%", borderRadius:2,
                                background:C.purple, transition:"width 1s ease" }} />
                </div>
                <span style={{ fontFamily:"var(--font-mono)", fontSize:11,
                               color:C.bright, minWidth:28, textAlign:"right" }}>
                  {u.count}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Simulate Attack Panel
// ─────────────────────────────────────────────────────────────────
function SimulatePanel({ onSimulate }) {
  const [type, setType]   = useState("brute_force");
  const [intensity, setIn] = useState("medium");
  const [loading, setLoad] = useState(false);
  const [result, setRes]  = useState(null);

  const TYPES = [
    "brute_force","privilege_escalation","data_exfiltration",
    "suspicious_login","password_spray","automated_scanner",
  ];

  const run = async () => {
    setLoad(true); setRes(null);
    const r = await onSimulate({ attack_type: type, intensity, dry_run: false });
    setRes(r);
    setLoad(false);
  };

  return (
    <div className="soc-card card-animate" style={{ animationDelay:"80ms" }}>
      <SweepBar />
      <SectionHeader label="Attack Simulator" sub="POST /api/v1/simulate_attack" />
      <div style={{ padding:"0 18px 18px" }}>
        <div style={{ display:"flex", gap:10, flexWrap:"wrap", marginBottom:12 }}>
          <select className="soc-select" value={type} onChange={e=>setType(e.target.value)}>
            {TYPES.map(t => (
              <option key={t} value={t}>{t.replace(/_/g," ")}</option>
            ))}
          </select>
          <select className="soc-select" value={intensity} onChange={e=>setIn(e.target.value)}>
            {["low","medium","high"].map(i => (
              <option key={i} value={i}>{i}</option>
            ))}
          </select>
          <button className="sim-btn danger" onClick={run} disabled={loading}>
            {loading ? "▶ SIMULATING…" : "▶ SIMULATE ATTACK"}
          </button>
        </div>

        {loading && (
          <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:C.green }}>
            ▶ Generating events… scoring… classifying… evaluating rules…
            <span style={{ animation:"blink 0.8s infinite" }}>█</span>
          </div>
        )}

        {result && (
          <div style={{ background:C.bg, border:`1px solid ${C.border}`,
                        borderRadius:2, padding:12 }}>
            <div style={{ display:"flex", gap:12, flexWrap:"wrap", marginBottom:10 }}>
              <SevBadge sev={result.severity || "HIGH"} />
              <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:C.green }}>
                ✓ DETECTED
              </span>
              <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:C.text }}>
                score: <span style={{ color:C.bright }}>{result.anomaly_score}</span>
              </span>
              <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:C.text }}>
                conf: <span style={{ color:C.bright }}>
                  {(result.confidence*100).toFixed(0)}%
                </span>
              </span>
            </div>
            <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:C.muted,
                          marginBottom:6 }}>
              category: <span style={{ color:C.cyan }}>
                {result.threat_category?.replace(/_/g," ")}
              </span>
              {"  "}events: <span style={{ color:C.cyan }}>{result.events_generated}</span>
              {"  "}rules fired: <span style={{ color:C.cyan }}>
                {result.rules_fired?.length ?? 0}
              </span>
            </div>
            {result.actions_triggered?.length > 0 && (
              <div style={{ display:"flex", gap:4, flexWrap:"wrap", marginBottom:8 }}>
                <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:C.muted }}>
                  actions:
                </span>
                {result.actions_triggered.map(a => (
                  <span key={a} style={{ fontFamily:"var(--font-mono)", fontSize:10,
                                          background:C.dim, padding:"2px 6px",
                                          borderRadius:2, color:C.greenDim }}>
                    {a}
                  </span>
                ))}
              </div>
            )}
            {result.mitre_techniques?.length > 0 && (
              <div style={{ display:"flex", gap:4, flexWrap:"wrap" }}>
                {result.mitre_techniques.map(m => (
                  <span key={m} style={{ fontFamily:"var(--font-mono)", fontSize:10,
                                          background:C.dim, padding:"2px 5px",
                                          borderRadius:1, color:C.purple,
                                          border:`1px solid ${C.purple}44` }}>
                    {m}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// API Reference Panel
// ─────────────────────────────────────────────────────────────────
function APIPanel() {
  const endpoints = [
    { method:"GET",  path:"/api/v1/logs",           desc:"Paginated log feed" },
    { method:"GET",  path:"/api/v1/threats",         desc:"Detected threats" },
    { method:"GET",  path:"/api/v1/alerts",          desc:"Security alerts" },
    { method:"POST", path:"/api/v1/simulate_attack", desc:"Simulate attack" },
    { method:"POST", path:"/api/v1/ingest",          desc:"Ingest log events" },
    { method:"GET",  path:"/api/v1/stats",           desc:"Dashboard stats" },
    { method:"GET",  path:"/api/v1/rules",           desc:"Response rules" },
  ];
  const mc = { GET:C.green, POST:C.amber };

  return (
    <div className="soc-card card-animate" style={{ animationDelay:"200ms" }}>
      <SweepBar />
      <SectionHeader label="API Endpoints" sub="FastAPI backend — localhost:8000" />
      <div style={{ padding:"0 18px 18px", display:"flex", flexDirection:"column", gap:4 }}>
        {endpoints.map(ep => (
          <div key={ep.path}
               style={{ display:"flex", alignItems:"center", gap:10,
                         padding:"7px 10px", background:C.bg,
                         border:`1px solid ${C.border}`, borderRadius:2 }}>
            <span style={{ fontFamily:"var(--font-mono)", fontSize:10, fontWeight:"bold",
                           color:mc[ep.method], minWidth:36, letterSpacing:"0.05em" }}>
              {ep.method}
            </span>
            <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:C.cyan, flex:1 }}>
              {ep.path}
            </span>
            <span style={{ fontSize:11, color:C.muted }}>{ep.desc}</span>
          </div>
        ))}
        <div style={{ marginTop:8, fontFamily:"var(--font-mono)", fontSize:10,
                      color:C.muted, lineHeight:1.7 }}>
          {"// Connect to backend:\nconst BASE = 'http://localhost:8000';\nawait fetch(`${BASE}/api/v1/threats?severity=CRITICAL`);"}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Header
// ─────────────────────────────────────────────────────────────────
function Header({ stats, lastUpdate }) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick(x => x+1), 1000);
    return () => clearInterval(t);
  }, []);

  const now = new Date();
  const timeStr = now.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"});

  return (
    <header style={{ background:C.surface, borderBottom:`1px solid ${C.border}`,
                     padding:"0 24px", height:56,
                     display:"flex", alignItems:"center", justifyContent:"space-between" }}>
      <div style={{ display:"flex", alignItems:"center", gap:16 }}>
        <div style={{ fontFamily:"var(--font-ui)", fontWeight:700, fontSize:18,
                      letterSpacing:"0.12em", color:C.bright, textTransform:"uppercase" }}>
          SOC<span style={{ color:C.cyan }}>·</span>SENTINEL
        </div>
        <div style={{ width:1, height:20, background:C.border }} />
        <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:C.muted,
                      letterSpacing:"0.08em" }}>
          AI THREAT HUNTING & INCIDENT RESPONSE
        </div>
      </div>

      <div style={{ display:"flex", alignItems:"center", gap:20 }}>
        <div style={{ textAlign:"right" }}>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:C.muted }}>
            THREATS DETECTED
          </div>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:15, color:C.red }}>
            {stats?.total_threats ?? "—"}
          </div>
        </div>
        <div style={{ width:1, height:24, background:C.border }} />
        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
          <span className="live-dot" />
          <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:C.green }}>
            LIVE
          </span>
        </div>
        <div style={{ fontFamily:"var(--font-mono)", fontSize:12, color:C.muted }}>
          {timeStr}
        </div>
      </div>
    </header>
  );
}

// ─────────────────────────────────────────────────────────────────
// Root Dashboard
// ─────────────────────────────────────────────────────────────────
export default function SOCDashboard() {
  injectStyles();

  const [stats,   setStats]   = useState(null);
  const [threats, setThreats] = useState([]);
  const [alerts,  setAlerts]  = useState([]);
  const [lastUpd, setLastUpd] = useState(null);
  const [online,  setOnline]  = useState(false);

  // Fetch or fall back to mock
  const refresh = useCallback(async () => {
    const s = await api.get("/stats");
    if (s && s.total_logs !== undefined) {
      setStats(s);
      setOnline(true);
    } else {
      setStats(MOCK_STATS);
      setOnline(false);
    }

    const t = await api.get("/threats?limit=6");
    setThreats(Array.isArray(t) ? t : MOCK_THREATS);

    const a = await api.get("/alerts?limit=5");
    setAlerts(Array.isArray(a) ? a : MOCK_ALERTS);

    setLastUpd(new Date());
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 15000);
    return () => clearInterval(id);
  }, [refresh]);

  const handleSimulate = async (body) => {
    const r = await api.post("/simulate_attack", body);
    if (r) {
      setTimeout(refresh, 800);
      return r;
    }
    // offline mock result
    return {
      anomaly_score: 97.5, threat_detected: true,
      threat_category: body.attack_type, severity: "CRITICAL",
      confidence: 0.94, events_generated: 35,
      rules_fired: ["brute_force_block_ip","brute_force_disable_account"],
      actions_triggered: ["block_ip","disable_user","send_alert"],
      mitre_techniques: ["T1110.001","T1110.003"],
    };
  };

  const s = stats || MOCK_STATS;

  return (
    <div style={{ minHeight:"100vh", background:C.bg }} className="soc-grid-bg">
      <div className="soc-scanline" />

      <Header stats={s} lastUpdate={lastUpd} />

      {/* Connection status bar */}
      <div style={{ background: online ? "rgba(0,255,136,0.06)" : "rgba(255,70,85,0.06)",
                    borderBottom:`1px solid ${online ? C.greenDim+"44" : C.red+"44"}`,
                    padding:"5px 24px", display:"flex", alignItems:"center", gap:10 }}>
        <span style={{ fontFamily:"var(--font-mono)", fontSize:10,
                       color: online ? C.green : C.red }}>
          {online ? "● CONNECTED TO FASTAPI BACKEND" : "○ OFFLINE — SHOWING DEMO DATA"}
        </span>
        {!online && (
          <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:C.muted }}>
            Start: uvicorn backend.api.main:app --reload --port 8000
          </span>
        )}
        <span style={{ marginLeft:"auto", fontFamily:"var(--font-mono)", fontSize:10,
                       color:C.muted }}>
          {lastUpd ? `Updated ${lastUpd.toLocaleTimeString()}` : "Initializing…"}
        </span>
      </div>

      {/* Main grid */}
      <div style={{ padding:20, display:"flex", flexDirection:"column", gap:16 }}>

        {/* Row 1: KPI stats */}
        <div style={{ display:"grid", gap:12,
                      gridTemplateColumns:"repeat(auto-fit, minmax(160px, 1fr))" }}>
          <StatCard label="Total Logs Ingested" value={s.total_logs}
                    accent={C.bright} delay={0} />
          <StatCard label="Threats Detected" value={s.total_threats}
                    accent={C.red} delay={60}
                    sub={`${(s.detection_rate*100).toFixed(2)}% detection rate`} />
          <StatCard label="Open Alerts" value={s.open_alerts}
                    accent={C.amber} delay={120} />
          <StatCard label="Critical Incidents" value={s.critical_count}
                    accent={C.red} delay={180} sub="immediate response" />
          <StatCard label="High Severity" value={s.high_count}
                    accent={C.high} delay={240} sub="analyst review" />
        </div>

        {/* Row 2: Charts */}
        <div style={{ display:"grid", gap:12,
                      gridTemplateColumns:"2fr 1fr 1fr" }}>
          <TimelineChart data={MOCK_TIMELINE} />
          <CategoryChart data={s.threats_by_category} />
          <SeverityDonut data={s.alerts_by_severity} />
        </div>

        {/* Row 3: Threats table full width */}
        <ThreatsTable threats={threats.length ? threats : MOCK_THREATS} />

        {/* Row 4: Alerts + IP panel + Simulator */}
        <div style={{ display:"grid", gap:12, gridTemplateColumns:"2fr 1fr" }}>
          <AlertsFeed alerts={alerts.length ? alerts : MOCK_ALERTS} />
          <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
            <IPPanel ips={s.top_source_ips} users={s.top_targeted_users} />
            <SimulatePanel onSimulate={handleSimulate} />
          </div>
        </div>

        {/* Row 5: API reference */}
        <APIPanel />

        {/* Footer */}
        <div style={{ textAlign:"center", padding:"8px 0 4px",
                      fontFamily:"var(--font-mono)", fontSize:10, color:C.muted }}>
          SOC·SENTINEL v1.0 — AI Threat Hunting & Incident Response Platform
          {"  //  "}
          IsolationForest + ThreatClassifier + SOAR RuleEngine
          {"  //  "}
          FastAPI backend
        </div>
      </div>
    </div>
  );
}
