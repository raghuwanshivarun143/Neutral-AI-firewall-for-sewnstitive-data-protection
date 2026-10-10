"use client";

import { Activity, ShieldAlert, FileText, Zap, ServerCrash, CheckCircle2 } from 'lucide-react';
import { useEffect, useState } from 'react';

export default function Dashboard() {
  const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  const [stats, setStats] = useState({
    total_requests: 0,
    blocked_requests: 0,
    masked_requests: 0,
    allowed_requests: 0,
    recent_security_events: [] as any[]
  });

  const [isHealthy, setIsHealthy] = useState(false);
  const [offlineReason, setOfflineReason] = useState("Connecting to CIPHER01 backend...");
  const [providers, setProviders] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;

    async function fetchData() {
      try {
        const [analyticsRes, healthRes, providerRes] = await Promise.all([
          fetch(`${API_URL}/api/analytics`, { cache: "no-store" }).catch(() => null),
          fetch(`${API_URL}/health`, { cache: "no-store" }).catch(() => null),
          fetch(`${API_URL}/health/providers`, { cache: "no-store" }).catch(() => null),
        ]);

        if (!mounted) return;

        let healthy = false;

        if (healthRes?.ok) {
          const healthData = await healthRes.json();
          if (healthData.status === "online") {
            healthy = true;
          }
        }

        setIsHealthy(healthy);
        if (!healthy) {
          setOfflineReason("Unable to connect to CIPHER01 backend");
        }

        if (analyticsRes?.ok) {
          const data = await analyticsRes.json();
          setStats(data);
        }

        if (providerRes?.ok) {
          const pData = await providerRes.json();
          setProviders(pData.providers || {});
        }
        
      } catch (err) {
        if (mounted) {
          setIsHealthy(false);
          setOfflineReason("Unable to connect to CIPHER01 backend");
        }
        console.error("Failed to fetch dashboard data:", err);
      } finally {
        if (mounted) setLoading(false);
      }
    }

    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [API_URL]);

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[50vh]">
        <div className="text-slate-400">Loading Dashboard...</div>
      </div>
    );
  }

  return (
    <div className="p-8 space-y-8 animate-in fade-in duration-700">
      <header className="flex justify-between items-end">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white mb-1">Overview</h2>
          <p className="text-slate-400 text-sm">Real-time status of CIPHER01 firewall and metrics.</p>
        </div>
        <div className="flex gap-2">
          {isHealthy ? (
            <span className="flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-400 text-xs font-semibold border border-emerald-500/20">
              <CheckCircle2 className="w-3.5 h-3.5" /> SYSTEM HEALTHY
            </span>
          ) : (
            <span className="flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 text-red-400 text-xs font-semibold border border-red-500/20">
              <ServerCrash className="w-3.5 h-3.5" /> OFFLINE
            </span>
          )}
        </div>
      </header>

      {!isHealthy && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          <strong>Backend Offline:</strong> {offlineReason}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard title="Total Requests" value={stats.total_requests} icon={Activity} />
        <MetricCard title="Blocked Threats" value={stats.blocked_requests} icon={ShieldAlert} alert />
        <MetricCard title="PII Redacted" value={stats.masked_requests} icon={FileText} />
        <MetricCard title="Allowed Requests" value={stats.allowed_requests} icon={Zap} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 glass-panel p-6 flex flex-col min-h-[384px]">
          <h3 className="text-lg font-semibold text-slate-200 mb-4">Traffic Volume</h3>
          <div className="flex-1 flex flex-col border border-slate-800/50 rounded bg-slate-950/30 overflow-hidden relative">
            {stats.total_requests === 0 ? (
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-slate-500 text-sm">No traffic data yet.</span>
              </div>
            ) : (
              <TrafficChart stats={stats} />
            )}
          </div>
        </div>

        <div className="space-y-6">
          <div className="glass-panel p-6 flex flex-col h-48">
            <h3 className="text-lg font-semibold text-slate-200 mb-4">Provider Status</h3>
            <div className="flex-1 space-y-3 overflow-y-auto">
              {['openai', 'anthropic', 'ollama'].map(pName => {
                const p = providers[pName];
                let statusText = "NOT CONFIGURED";
                let statusColor = "text-slate-500 bg-slate-500/10 border-slate-500/20";
                
                if (p) {
                  if (p.status === "healthy") {
                    statusText = "ONLINE";
                    statusColor = "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
                  } else if (p.status === "not_configured") {
                    statusText = "NOT CONFIGURED";
                    statusColor = "text-slate-500 bg-slate-500/10 border-slate-500/20";
                  } else if (p.status === "unreachable" || p.status === "unhealthy") {
                    statusText = p.status === "unreachable" ? "OFFLINE" : "ERROR";
                    statusColor = "text-red-400 bg-red-500/10 border-red-500/20";
                  }
                }
                
                return (
                  <div key={pName} className="flex justify-between items-center text-sm border-b border-slate-800/50 pb-2 last:border-0">
                    <span className="capitalize text-slate-300 font-medium">{pName}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold border ${statusColor}`}>
                      {statusText}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="glass-panel p-6 flex flex-col h-[180px]">
            <h3 className="text-lg font-semibold text-slate-200 mb-4">Recent Threats</h3>
            <div className="flex-1 space-y-3 overflow-y-auto pr-1">
              {stats.recent_security_events.length > 0 ? (
                stats.recent_security_events.map((evt: any, i: number) => (
                  <ThreatItem 
                    key={i} 
                    threat={`${evt.entity_type} detected`} 
                    time={evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : 'Unknown'} 
                    severity={evt.action === "MASK" ? "REDACTED" : evt.action === "BLOCK" ? "BLOCKED" : evt.action} 
                  />
                ))
              ) : (
                <div className="flex items-center justify-center h-full">
                  <p className="text-sm text-slate-500">No threats intercepted yet.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricCard({ title, value, icon: Icon, alert = false }: { title: string; value: string | number; icon: any; alert?: boolean }) {
  return (
    <div className="glass-panel p-6 relative overflow-hidden group">
      <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
        <Icon className="w-16 h-16" />
      </div>
      <div className="relative z-10">
        <p className="text-sm font-medium text-slate-400 mb-1">{title}</p>
        <p className={`text-4xl font-bold tracking-tight ${alert ? 'text-red-400' : 'text-white'}`}>{value}</p>
      </div>
    </div>
  );
}

function ThreatItem({ threat, time, severity }: { threat: string; time: string; severity: string }) {
  const getSeverityColor = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'BLOCKED': return 'text-red-400 bg-red-400/10 border-red-400/20';
      case 'REDACTED': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20';
      default: return 'text-blue-400 bg-blue-400/10 border-blue-400/20';
    }
  };

  return (
    <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex justify-between items-center">
      <div>
        <p className="text-sm font-medium text-slate-300">{threat}</p>
        <p className="text-xs text-slate-500">{time}</p>
      </div>
      <span className={`text-[10px] font-bold px-2 py-1 rounded border ${getSeverityColor(severity)}`}>
        {severity}
      </span>
    </div>
  );
}

// Simple CSS-based bar chart using the stats
function TrafficChart({ stats }: { stats: any }) {
  const total = stats.total_requests || 1;
  const allowPct = (stats.allowed_requests / total) * 100;
  const blockPct = (stats.blocked_requests / total) * 100;
  const maskPct = (stats.masked_requests / total) * 100;

  return (
    <div className="h-full w-full flex flex-col p-6">
      <div className="flex-1 flex items-end gap-2 sm:gap-4 lg:gap-8 pb-4">
        {/* We just show a simple bar representation of the totals */}
        <ChartBar label="Allowed" value={stats.allowed_requests} pct={allowPct} color="bg-emerald-500" />
        <ChartBar label="Masked" value={stats.masked_requests} pct={maskPct} color="bg-yellow-500" />
        <ChartBar label="Blocked" value={stats.blocked_requests} pct={blockPct} color="bg-red-500" />
      </div>
      <div className="flex justify-between items-center pt-4 border-t border-slate-800">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-emerald-500"></div>
          <span className="text-xs text-slate-400">Allowed</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
          <span className="text-xs text-slate-400">Redacted</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <span className="text-xs text-slate-400">Blocked</span>
        </div>
      </div>
    </div>
  );
}

function ChartBar({ label, value, pct, color }: { label: string; value: number; pct: number; color: string }) {
  // ensure minimum height for visibility if value > 0
  const height = value > 0 ? Math.max(pct, 5) : 0;
  
  return (
    <div className="flex-1 flex flex-col justify-end items-center group relative h-full">
      {/* Tooltip */}
      <div className="opacity-0 group-hover:opacity-100 absolute -top-8 bg-slate-800 text-white text-xs py-1 px-2 rounded whitespace-nowrap transition-opacity pointer-events-none z-10">
        {value} Requests
      </div>
      <div 
        className={`w-full max-w-[120px] rounded-t-md transition-all duration-1000 ease-out ${color} opacity-80 group-hover:opacity-100`}
        style={{ height: `${height}%` }}
      ></div>
    </div>
  );
}
