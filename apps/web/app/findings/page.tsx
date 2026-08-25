'use client';

import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  ShieldCheck,
  CheckCircle2,
  ExternalLink,
  Bot,
  ArrowUpDown,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';
import { FindingDetailDrawer } from '@/components/finding-detail-drawer';

export default function FindingsPage() {
  const { currentProject } = useAuth();
  const [findings, setFindings] = useState<any[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);

  const loadFindings = async () => {
    if (!currentProject) return;
    setLoading(true);
    try {
      const data = await api.getFindings(currentProject.id);
      setFindings(data);
    } catch (err) {
      console.error('Failed loading findings', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, [currentProject]);

  const filtered = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase()) ||
      f.asset_target.toLowerCase().includes(search.toLowerCase()) ||
      (f.cwe && f.cwe.toLowerCase().includes(search.toLowerCase()));

    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesStatus = statusFilter === 'ALL' || f.status === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Vulnerability Findings & Evidence</h1>
          <p className="text-xs text-muted-foreground mt-1">
            Normalized, correlated, and deduplicated security findings for{' '}
            <span className="font-semibold text-slate-200">{currentProject?.name}</span>
          </p>
        </div>
        <div className="text-xs text-muted-foreground">
          Showing <span className="font-bold text-white">{filtered.length}</span> of {findings.length} findings
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col gap-3 rounded-xl border border-border/60 bg-[#111827] p-4 sm:flex-row sm:items-center sm:justify-between">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search by title, CWE, target, or keyword..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-border bg-[#0b0f19] pl-9 pr-3 py-1.5 text-xs text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
          />
        </div>

        {/* Severity Filter Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto text-xs">
          {['ALL', 'Critical', 'High', 'Medium', 'Low'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`rounded-lg px-2.5 py-1 text-[11px] font-semibold transition ${
                severityFilter === sev
                  ? 'bg-blue-600 text-white'
                  : 'bg-[#0b0f19] text-muted-foreground hover:bg-slate-800 hover:text-white'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Status Filter Dropdown */}
        <div className="flex items-center gap-2 text-xs">
          <span className="text-muted-foreground">Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-lg border border-border bg-[#0b0f19] px-2.5 py-1 text-xs text-white focus:border-blue-500 focus:outline-none"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">OPEN</option>
            <option value="IN_PROGRESS">IN PROGRESS</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
            <option value="ACCEPTED_RISK">ACCEPTED RISK</option>
          </select>
        </div>
      </div>

      {/* Findings Table */}
      <div className="rounded-xl border border-border/60 bg-[#111827] shadow-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border/60 bg-[#0b0f19] text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-5 py-3.5">Severity</th>
                <th className="px-5 py-3.5">Vulnerability Title & CWE</th>
                <th className="px-5 py-3.5">Affected Asset / Endpoint</th>
                <th className="px-5 py-3.5">Risk Score / CVSS</th>
                <th className="px-5 py-3.5">Detection Engine</th>
                <th className="px-5 py-3.5">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted-foreground">
                    No findings match the configured filter criteria.
                  </td>
                </tr>
              ) : (
                filtered.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelectedFinding(f)}
                    className="hover:bg-slate-800/40 cursor-pointer transition"
                  >
                    <td className="px-5 py-4">
                      <span
                        className={`rounded-full px-2.5 py-0.5 text-[10px] font-bold uppercase ${
                          f.severity === 'Critical'
                            ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                            : f.severity === 'High'
                            ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                            : f.severity === 'Medium'
                            ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                            : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                        }`}
                      >
                        {f.severity}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <div className="font-bold text-white hover:text-blue-400 transition">
                        {f.title}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[11px] text-muted-foreground">{f.category}</span>
                        {f.cwe && (
                          <span className="rounded bg-slate-800 px-1.5 py-0.2 text-[9px] font-mono text-blue-300">
                            {f.cwe}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      <div className="font-mono text-slate-300 truncate max-w-[200px]">
                        {f.asset_target}
                      </div>
                      {f.endpoint && (
                        <div className="font-mono text-[11px] text-muted-foreground truncate max-w-[200px]">
                          {f.endpoint}
                        </div>
                      )}
                    </td>
                    <td className="px-5 py-4">
                      <div className="font-extrabold text-blue-400">
                        {f.platform_risk_score} <span className="text-[10px] text-muted-foreground font-normal">/100</span>
                      </div>
                      <div className="text-[10px] text-muted-foreground">CVSS: {f.cvss_score}</div>
                    </td>
                    <td className="px-5 py-4 text-slate-300">
                      <span className="text-[11px]">{f.scanner}</span>
                    </td>
                    <td className="px-5 py-4">
                      <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-semibold text-slate-300 uppercase">
                        {f.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Finding Detail Slide-Over */}
      {selectedFinding && (
        <FindingDetailDrawer
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onStatusUpdated={() => loadFindings()}
        />
      )}
    </div>
  );
}
