"use client";

import { useEffect, useState, useRef } from "react";
import { Activity, Shield, X, Eye, Lock, ChevronDown, ChevronUp } from "lucide-react";

interface RequestRecord {
  id: string;
  timestamp: string;
  session_id: string;
  provider: string;
  model: string;
  risk_score: number;
  risk_level: string;
  action: string;
  status: string;
  processing_time_ms: number;
  provider_latency_ms: number;
  entity_count: number;
  security_events: {
    entity_type: string;
    event_type: string;
    action: string;
    masked_value: string;
  }[];
}

interface ProviderInfo {
  name: string;
}

const ACTION_META: Record<string, { label: string; color: string; icon: React.ElementType }> = {
  BLOCK:    { label: "Blocked",  color: "text-red-400 bg-red-400/10 border-red-400/25",      icon: X },
  MASK:     { label: "Masked",   color: "text-yellow-400 bg-yellow-400/10 border-yellow-400/25", icon: Eye },
  TOKENIZE: { label: "Tokenized",color: "text-blue-400 bg-blue-400/10 border-blue-400/25",   icon: Lock },
  ALLOW:    { label: "Allowed",  color: "text-emerald-400 bg-emerald-400/10 border-emerald-400/25", icon: Shield },
};

export default function FirewallLive() {
  const [requests, setRequests] = useState<RequestRecord[]>([]);
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [filter, setFilter] = useState<string>("ALL");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [newIds, setNewIds] = useState<Set<string>>(new Set());
  const prevIdsRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    const load = async () => {
      try {
        const [reqRes, provRes] = await Promise.all([
          fetch("http://localhost:8000/api/requests?limit=30"),
          fetch("http://localhost:8000/api/providers"),
        ]);
        if (reqRes.ok) {
          const data: RequestRecord[] = await reqRes.json();
          const incoming = new Set(data.map(r => r.id));
          const fresh = new Set([...incoming].filter(id => !prevIdsRef.current.has(id)));
          if (fresh.size > 0 && prevIdsRef.current.size > 0) {
            setNewIds(fresh);
            setTimeout(() => setNewIds(new Set()), 2000);
          }
          prevIdsRef.current = incoming;
          setRequests(data);
        }
        if (provRes.ok) {
          const pd = await provRes.json();
          setProviders((pd.providers || []).map((n: string) => ({ name: n })));
        }
      } catch (e) {
        console.error("Firewall fetch error:", e);
      }
    };
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, []);

  const filtered = filter === "ALL" ? requests : requests.filter(r => r.action === filter);

  const counts = {
    ALL:      requests.length,
    BLOCK:    requests.filter(r => r.action === "BLOCK").length,
    MASK:     requests.filter(r => r.action === "MASK").length,
    ALLOW:    requests.filter(r => r.action === "ALLOW").length,
    TOKENIZE: requests.filter(r => r.action === "TOKENIZE").length,
  };

  return (
    <div className="p-8 space-y-6 animate-in fade-in duration-700">
      <header className="flex justify-between items-end">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white mb-1">Firewall Live</h2>
          <p className="text-slate-400 text-sm">Real-time view of all intercepted AI traffic.</p>
        </div>
        <span className="flex items-center gap-2 text-xs font-medium text-emerald-400 bg-emerald-400/10 px-3 py-1.5 rounded-full border border-emerald-400/20">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse inline-block" />
          Polling every 3s
        </span>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Main feed */}
        <div className="lg:col-span-3 space-y-4">
          {/* Filter tabs */}
          <div className="flex gap-2 flex-wrap">
            {(["ALL", "BLOCK", "MASK", "ALLOW", "TOKENIZE"] as const).map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`text-xs px-3 py-1.5 rounded-full border font-semibold transition-all ${
                  filter === f
                    ? f === "ALL"
                      ? "bg-white/10 border-white/30 text-white"
                      : ACTION_META[f]?.color ?? "bg-white/10 border-white/30 text-white"
                    : "bg-transparent border-slate-700 text-slate-400 hover:border-slate-500"
                }`}
              >
                {f} <span className="opacity-60">({counts[f]})</span>
              </button>
            ))}
          </div>

          <div className="glass-panel divide-y divide-slate-800/50">
            {filtered.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-sm">
                No requests yet. Send something through the firewall.
              </div>
            ) : (
              filtered.map(req => {
                const meta = ACTION_META[req.action] ?? ACTION_META.ALLOW;
                const Icon = meta.icon;
                const isNew = newIds.has(req.id);
                const isOpen = expanded[req.id];

                return (
                  <div
                    key={req.id}
                    className={`transition-all duration-500 ${isNew ? "bg-white/5" : ""}`}
                  >
                    <div
                      className="flex items-center gap-4 px-5 py-3.5 cursor-pointer hover:bg-slate-800/20 transition-colors"
                      onClick={() => setExpanded(p => ({ ...p, [req.id]: !p[req.id] }))}
                    >
                      {/* Status icon */}
                      <div className={`flex-shrink-0 w-7 h-7 rounded-full flex items-center justify-center border ${meta.color}`}>
                        <Icon className="w-3.5 h-3.5" />
                      </div>

                      {/* Main info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border ${meta.color}`}>
                            {meta.label}
                          </span>
                          {req.entity_count > 0 && (
                            <span className="text-[10px] text-slate-400">
                              {req.entity_count} entity{req.entity_count !== 1 ? "ies" : ""}
                            </span>
                          )}
                          {isNew && (
                            <span className="text-[10px] text-emerald-400 animate-pulse">NEW</span>
                          )}
                        </div>
                        <div className="flex items-center gap-3 text-xs text-slate-400">
                          <span className="capitalize font-medium text-slate-300">{req.provider}</span>
                          <span>•</span>
                          <span className="font-mono">{req.model || "—"}</span>
                          <span>•</span>
                          <span>risk: <span className={
                            req.risk_score >= 8 ? "text-red-400" :
                            req.risk_score >= 5 ? "text-orange-400" :
                            req.risk_score >= 2 ? "text-yellow-400" : "text-emerald-400"
                          }>{req.risk_score.toFixed(1)}</span></span>
                          <span>•</span>
                          <span>{req.processing_time_ms.toFixed(0)}ms</span>
                        </div>
                      </div>

                      {/* Timestamp + chevron */}
                      <div className="flex items-center gap-3 flex-shrink-0">
                        <span className="text-xs text-slate-500">
                          {new Date(req.timestamp).toLocaleTimeString()}
                        </span>
                        {req.security_events.length > 0 && (
                          isOpen ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />
                        )}
                      </div>
                    </div>

                    {/* Expanded security events */}
                    {isOpen && req.security_events.length > 0 && (
                      <div className="px-16 pb-3 space-y-1.5">
                        {req.security_events.map((ev, i) => (
                          <div key={i} className="flex items-center gap-3 text-xs">
                            <span className="font-mono text-slate-400">{ev.entity_type}</span>
                            <span className="text-slate-600">→</span>
                            <span className={`font-bold ${
                              ev.action === "BLOCK" ? "text-red-400" :
                              ev.action === "MASK" ? "text-yellow-400" :
                              ev.action === "TOKENIZE" ? "text-blue-400" : "text-emerald-400"
                            }`}>{ev.action}</span>
                            {ev.masked_value && (
                              <>
                                <span className="text-slate-600">→</span>
                                <span className="font-mono text-slate-500">{ev.masked_value}</span>
                              </>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Quick actions */}
          <div className="glass-panel p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">Quick Actions</h3>
            <div className="space-y-2">
              <a
                href="http://localhost:8000/docs"
                target="_blank"
                rel="noopener noreferrer"
                className="block w-full py-2 px-3 rounded-md bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 transition-colors border border-slate-700 text-center"
              >
                API Docs (Swagger)
              </a>
              <a
                href="http://localhost:8000/health"
                target="_blank"
                rel="noopener noreferrer"
                className="block w-full py-2 px-3 rounded-md bg-emerald-600/10 hover:bg-emerald-600/20 text-emerald-400 text-xs font-medium transition-colors border border-emerald-600/20 text-center"
              >
                Health Check
              </a>
            </div>
          </div>

          {/* Active providers */}
          <div className="glass-panel p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">Registered Providers</h3>
            <div className="space-y-2.5">
              {providers.length > 0 ? (
                providers.map(p => (
                  <div key={p.name} className="flex items-center justify-between">
                    <span className="text-sm text-slate-300 capitalize flex items-center gap-2">
                      <Activity className="w-3.5 h-3.5 text-emerald-400" />
                      {p.name}
                    </span>
                    <span className="text-[10px] text-emerald-400 font-semibold">ONLINE</span>
                  </div>
                ))
              ) : (
                <p className="text-xs text-slate-500">Loading providers...</p>
              )}
            </div>
          </div>

          {/* Stats */}
          <div className="glass-panel p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">Session Stats</h3>
            <div className="space-y-2">
              <StatRow label="Total" value={counts.ALL} />
              <StatRow label="Blocked" value={counts.BLOCK} danger />
              <StatRow label="Masked" value={counts.MASK} warn />
              <StatRow label="Allowed" value={counts.ALLOW} />
              <div className="pt-2 border-t border-slate-800 mt-2">
                <StatRow
                  label="Block Rate"
                  value={`${counts.ALL > 0 ? ((counts.BLOCK / counts.ALL) * 100).toFixed(0) : 0}%`}
                  danger={counts.BLOCK > 0}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatRow({ label, value, danger = false, warn = false }: { label: string; value: string | number; danger?: boolean; warn?: boolean }) {
  return (
    <div className="flex justify-between text-xs">
      <span className="text-slate-400">{label}</span>
      <span className={`font-semibold ${danger ? "text-red-400" : warn ? "text-yellow-400" : "text-slate-200"}`}>
        {value}
      </span>
    </div>
  );
}
