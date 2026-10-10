"use client";

import { useEffect, useState } from "react";
import { ShieldAlert, FileText, Activity, Zap, TrendingUp } from "lucide-react";

interface Analytics {
  total_requests: number;
  blocked_requests: number;
  masked_requests: number;
  allowed_requests: number;
  average_risk_score: number;
  entity_breakdown: { entity_type: string; count: number }[];
  provider_stats: { provider: string; calls: number; successful_calls: number; failed_calls: number; avg_latency_ms: number | null }[];
  recent_security_events: {
    entity_type: string;
    event_type: string;
    action: string;
    provider: string;
    timestamp: string;
  }[];
}

export default function AnalyticsPage() {
  const [data, setData] = useState<Analytics | null>(null);
  const [loading, setLoading] = useState(true);

  const fetch_data = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/analytics", { cache: "no-store" });
      if (res.ok) setData(await res.json());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetch_data();
    const t = setInterval(fetch_data, 5000);
    return () => clearInterval(t);
  }, []);

  if (loading)
    return (
      <div className="p-8 flex items-center justify-center h-full">
        <div className="text-slate-400 animate-pulse">Loading analytics...</div>
      </div>
    );

  if (!data)
    return (
      <div className="p-8">
        <p className="text-red-400">Failed to load analytics. Is the backend running?</p>
      </div>
    );

  const blockRate =
    data.total_requests > 0
      ? ((data.blocked_requests / data.total_requests) * 100).toFixed(1)
      : "0.0";

  return (
    <div className="p-8 space-y-8 animate-in fade-in duration-700">
      <header>
        <h2 className="text-3xl font-bold tracking-tight text-white mb-1">Analytics</h2>
        <p className="text-slate-400 text-sm">
          Live security metrics from real firewall traffic.
        </p>
      </header>

      {/* Top KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard label="Total Requests" value={data.total_requests} icon={Activity} />
        <StatCard label="Blocked" value={data.blocked_requests} icon={ShieldAlert} danger />
        <StatCard label="Masked / Redacted" value={data.masked_requests} icon={FileText} warn />
        <StatCard label="Allowed Clean" value={data.allowed_requests} icon={Zap} />
        <StatCard
          label="Avg Risk Score"
          value={data.average_risk_score.toFixed(2)}
          icon={TrendingUp}
          danger={data.average_risk_score >= 5}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Entity breakdown */}
        <div className="glass-panel p-6">
          <h3 className="text-lg font-semibold text-slate-200 mb-4">
            Top Detected Entity Types
          </h3>
          {data.entity_breakdown.length === 0 ? (
            <p className="text-slate-500 text-sm">No security events recorded yet.</p>
          ) : (
            <div className="space-y-3">
              {data.entity_breakdown.map((e) => {
                const maxCount = data.entity_breakdown[0].count;
                const pct = Math.round((e.count / maxCount) * 100);
                return (
                  <div key={e.entity_type}>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-300 font-mono">{e.entity_type}</span>
                      <span className="text-slate-400">{e.count}</span>
                    </div>
                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-blue-500 to-emerald-500 rounded-full transition-all duration-700"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Provider stats */}
        <div className="glass-panel p-6">
          <h3 className="text-lg font-semibold text-slate-200 mb-4">Provider Performance</h3>
          {data.provider_stats.length === 0 ? (
            <p className="text-slate-500 text-sm">
              No provider calls yet. Send a request through the gateway.
            </p>
          ) : (
            <div className="space-y-4">
              {data.provider_stats.map((p) => (
                <div
                  key={p.provider}
                  className="flex items-center justify-between p-3 rounded-lg bg-slate-900/60 border border-slate-800"
                >
                  <div>
                    <p className="text-sm font-semibold text-white capitalize">{p.provider}</p>
                    <p className="text-xs text-slate-400">
                      {p.calls} call{p.calls !== 1 ? "s" : ""}
                      {p.failed_calls > 0 && (
                        <span className="text-red-400 ml-1">({p.failed_calls} failed)</span>
                      )}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className={`text-sm font-mono ${
                      p.avg_latency_ms !== null ? "text-emerald-400" : "text-slate-500"
                    }`}>
                      {p.avg_latency_ms !== null
                        ? `${p.avg_latency_ms.toFixed(2)} ms`
                        : "— ms"}
                    </p>
                    <p className="text-xs text-slate-500">
                      {p.avg_latency_ms !== null ? "avg latency" : "no successful calls"}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Recent security events */}
      <div className="glass-panel p-6">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-semibold text-slate-200">Recent Security Events</h3>
          <span className="text-xs text-slate-500">Block rate: {blockRate}%</span>
        </div>
        {data.recent_security_events.length === 0 ? (
          <p className="text-slate-500 text-sm">No events yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-slate-400 text-xs border-b border-slate-800">
                  <th className="text-left py-2 pr-4">Entity</th>
                  <th className="text-left py-2 pr-4">Type</th>
                  <th className="text-left py-2 pr-4">Action</th>
                  <th className="text-left py-2 pr-4">Provider</th>
                  <th className="text-left py-2">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {data.recent_security_events.map((ev, i) => (
                  <tr key={i} className="hover:bg-slate-800/20 transition-colors">
                    <td className="py-2 pr-4 font-mono text-xs text-slate-300">{ev.entity_type}</td>
                    <td className="py-2 pr-4 text-slate-400">{ev.event_type}</td>
                    <td className="py-2 pr-4">
                      <ActionBadge action={ev.action} />
                    </td>
                    <td className="py-2 pr-4 text-slate-400 capitalize">{ev.provider}</td>
                    <td className="py-2 text-slate-500 text-xs">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, icon: Icon, danger = false, warn = false }: any) {
  const color = danger
    ? "text-red-400"
    : warn
    ? "text-yellow-400"
    : "text-white";
  return (
    <div className="glass-panel p-5 relative overflow-hidden group">
      <div className="absolute top-0 right-0 p-3 opacity-10 group-hover:opacity-20 transition-opacity">
        <Icon className="w-10 h-10" />
      </div>
      <p className="text-xs font-medium text-slate-400 mb-1">{label}</p>
      <p className={`text-3xl font-bold tracking-tight ${color}`}>{value}</p>
    </div>
  );
}

function ActionBadge({ action }: { action: string }) {
  const styles: Record<string, string> = {
    BLOCK: "text-red-400 bg-red-400/10 border-red-400/20",
    MASK: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
    TOKENIZE: "text-blue-400 bg-blue-400/10 border-blue-400/20",
    ALLOW: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
  };
  const cls = styles[action] ?? "text-slate-400 bg-slate-400/10 border-slate-400/20";
  return (
    <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${cls}`}>
      {action}
    </span>
  );
}
