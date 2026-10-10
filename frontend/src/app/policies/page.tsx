"use client";

import { useEffect, useState } from "react";
import { Shield, Lock, Eye, X } from "lucide-react";

interface Policy {
  id: string;
  entity_type: string;
  action: string;
  enabled: boolean;
  priority: number;
  description: string;
}

const ACTION_COLORS: Record<string, string> = {
  BLOCK: "text-red-400 bg-red-400/10 border-red-400/20",
  MASK: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  TOKENIZE: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  ALLOW: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
};

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);
  const [message, setMessage] = useState<{ text: string; ok: boolean } | null>(null);

  const loadPolicies = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/policies");
      if (res.ok) setPolicies(await res.json());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicies();
  }, []);

  const updatePolicy = async (id: string, patch: { action?: string; enabled?: boolean }) => {
    setSaving(id);
    try {
      const res = await fetch(`http://localhost:8000/api/policies/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      if (res.ok) {
        setMessage({ text: "Policy updated successfully.", ok: true });
        await loadPolicies();
      } else {
        setMessage({ text: "Failed to update policy.", ok: false });
      }
    } catch {
      setMessage({ text: "Network error.", ok: false });
    } finally {
      setSaving(null);
      setTimeout(() => setMessage(null), 3000);
    }
  };

  const grouped: Record<string, Policy[]> = {};
  policies.forEach((p) => {
    const group = p.entity_type.includes("KEY") || p.entity_type.includes("PASSWORD") || p.entity_type.includes("TOKEN") || p.entity_type.includes("JWT")
      ? "Secrets & Credentials"
      : p.entity_type.includes("EMAIL") || p.entity_type.includes("PHONE") || p.entity_type.includes("SSN") || p.entity_type.includes("AADHAAR") || p.entity_type.includes("PAN")
      ? "Personal Identifiers (PII)"
      : p.entity_type.includes("INJECT") || p.entity_type.includes("ENCODED")
      ? "Attack Patterns"
      : "Other";
    grouped[group] = grouped[group] || [];
    grouped[group].push(p);
  });

  const groupOrder = ["Attack Patterns", "Secrets & Credentials", "Personal Identifiers (PII)", "Other"];

  return (
    <div className="p-8 space-y-8 animate-in fade-in duration-700">
      <header className="flex justify-between items-end">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white mb-1">Security Policies</h2>
          <p className="text-slate-400 text-sm">
            Configure the firewall action for each detected entity type.
          </p>
        </div>
        {message && (
          <div
            className={`text-sm px-4 py-2 rounded-lg border ${
              message.ok
                ? "text-emerald-400 bg-emerald-400/10 border-emerald-400/20"
                : "text-red-400 bg-red-400/10 border-red-400/20"
            }`}
          >
            {message.text}
          </div>
        )}
      </header>

      {loading ? (
        <div className="text-slate-400 animate-pulse">Loading policies...</div>
      ) : (
        <div className="space-y-8">
          {groupOrder.map((group) => {
            const items = grouped[group];
            if (!items || items.length === 0) return null;
            return (
              <div key={group}>
                <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3">
                  {group}
                </h3>
                <div className="glass-panel divide-y divide-slate-800/50">
                  {items
                    .sort((a, b) => b.priority - a.priority)
                    .map((policy) => (
                      <PolicyRow
                        key={policy.id}
                        policy={policy}
                        saving={saving === policy.id}
                        onActionChange={(action) =>
                          updatePolicy(policy.id, { action })
                        }
                        onToggle={() =>
                          updatePolicy(policy.id, { enabled: !policy.enabled })
                        }
                      />
                    ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function PolicyRow({
  policy,
  saving,
  onActionChange,
  onToggle,
}: {
  policy: Policy;
  saving: boolean;
  onActionChange: (a: string) => void;
  onToggle: () => void;
}) {
  return (
    <div
      className={`flex items-center justify-between px-5 py-4 transition-colors hover:bg-slate-800/20 ${
        !policy.enabled ? "opacity-40" : ""
      }`}
    >
      <div className="flex items-center gap-4 min-w-0">
        <div className="flex-shrink-0">
          {policy.action === "BLOCK" ? (
            <X className="w-4 h-4 text-red-400" />
          ) : policy.action === "MASK" ? (
            <Eye className="w-4 h-4 text-yellow-400" />
          ) : policy.action === "TOKENIZE" ? (
            <Lock className="w-4 h-4 text-blue-400" />
          ) : (
            <Shield className="w-4 h-4 text-emerald-400" />
          )}
        </div>
        <div className="min-w-0">
          <p className="text-sm font-mono font-semibold text-slate-200 truncate">
            {policy.entity_type}
          </p>
          <p className="text-xs text-slate-500 truncate">{policy.description}</p>
        </div>
      </div>

      <div className="flex items-center gap-3 flex-shrink-0 ml-4">
        <select
          value={policy.action}
          disabled={saving || !policy.enabled}
          onChange={(e) => onActionChange(e.target.value)}
          className="text-xs bg-slate-800 border border-slate-700 text-white rounded-md px-2 py-1.5 focus:outline-none focus:border-blue-500 disabled:opacity-50 cursor-pointer"
        >
          <option value="ALLOW">ALLOW</option>
          <option value="MASK">MASK</option>
          <option value="TOKENIZE">TOKENIZE</option>
          <option value="BLOCK">BLOCK</option>
        </select>

        {/* Toggle */}
        <button
          onClick={onToggle}
          disabled={saving}
          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none ${
            policy.enabled ? "bg-emerald-500" : "bg-slate-700"
          } disabled:opacity-50`}
        >
          <span
            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
              policy.enabled ? "translate-x-4" : "translate-x-0.5"
            }`}
          />
        </button>
      </div>
    </div>
  );
}
