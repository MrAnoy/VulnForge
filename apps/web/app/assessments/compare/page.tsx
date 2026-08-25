'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ArrowLeft,
  ArrowRight,
  GitCompare,
  TrendingUp,
  TrendingDown,
  Minus,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Layers,
  Sparkles,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';

export default function CompareAssessmentsPage() {
  const { currentProject } = useAuth();
  const [assessments, setAssessments] = useState<any[]>([]);
  const [baseId, setBaseId] = useState<string>('');
  const [targetId, setTargetId] = useState<string>('');
  const [comparison, setComparison] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (currentProject) {
      loadAssessments();
    }
  }, [currentProject]);

  const loadAssessments = async () => {
    if (!currentProject) return;
    try {
      const data = await api.getAssessments(currentProject.id);
      setAssessments(data);
      if (data.length >= 2) {
        setBaseId(data[data.length - 1].id);
        setTargetId(data[0].id);
      }
    } catch (e: any) {
      console.error(e);
    }
  };

  const handleCompare = async () => {
    if (!baseId || !targetId || !currentProject) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.compareAssessments(currentProject.id, baseId, targetId);
      setComparison(res);
    } catch (e: any) {
      setError(e?.message || 'Failed to compare assessments');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Link
              href="/assessments"
              className="text-xs text-muted-foreground hover:text-white transition flex items-center gap-1"
            >
              <ArrowLeft className="h-3.5 w-3.5" /> Back to Assessments
            </Link>
          </div>
          <h1 className="text-2xl font-bold text-white mt-1">Assessment Comparison & Delta Engine</h1>
          <p className="text-xs text-muted-foreground">
            Track measurable security progress between checkpoints, identifying resolved vs newly discovered vulnerabilities.
          </p>
        </div>
      </div>

      {/* Selector Box */}
      <div className="rounded-xl border border-border/80 bg-[#111827] p-6 shadow-sm">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-center">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2">
              1. Baseline Assessment (Earlier Checkpoint)
            </label>
            <select
              value={baseId}
              onChange={(e) => setBaseId(e.target.value)}
              className="w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
            >
              <option value="">Select Baseline...</option>
              {assessments.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.profile}) — Score: {a.risk_score}/100 — {new Date(a.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2">
              2. Target Assessment (Later Checkpoint)
            </label>
            <select
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              className="w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
            >
              <option value="">Select Target...</option>
              {assessments.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.profile}) — Score: {a.risk_score}/100 — {new Date(a.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="mt-6 flex justify-end">
          <button
            onClick={handleCompare}
            disabled={!baseId || !targetId || loading}
            className="flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-xs font-bold text-white shadow-md hover:bg-blue-500 disabled:opacity-50 transition"
          >
            <GitCompare className="h-4 w-4" />
            {loading ? 'Analyzing Delta...' : 'Compare Assessments'}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg bg-rose-500/10 border border-rose-500/20 p-4 text-xs text-rose-400">
          {error}
        </div>
      )}

      {/* Comparison Results Display */}
      {comparison && (
        <div className="space-y-6">
          {/* Executive Delta Banner */}
          <div className="rounded-xl border border-blue-500/30 bg-blue-500/10 p-6 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-xl bg-blue-500/20 flex items-center justify-center text-blue-400">
                <Sparkles className="h-6 w-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Posture Progression Verdict</h3>
                <p className="text-xs text-blue-200 mt-0.5">{comparison.summary_verdict}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="text-right">
                <div className="text-[10px] text-slate-400 uppercase font-semibold">Posture Delta</div>
                <div
                  className={`text-2xl font-black ${
                    comparison.score_delta > 0
                      ? 'text-emerald-400'
                      : comparison.score_delta < 0
                      ? 'text-rose-400'
                      : 'text-slate-300'
                  }`}
                >
                  {comparison.score_delta > 0 ? `+${comparison.score_delta}` : comparison.score_delta} pts
                </div>
              </div>
            </div>
          </div>

          {/* Metric Comparison Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="rounded-xl border border-border/80 bg-[#111827] p-4">
              <span className="text-[11px] font-semibold text-muted-foreground uppercase">Critical Delta</span>
              <div className="mt-2 text-2xl font-black text-white">
                {comparison.critical_delta > 0 ? `+${comparison.critical_delta}` : comparison.critical_delta}
              </div>
            </div>
            <div className="rounded-xl border border-border/80 bg-[#111827] p-4">
              <span className="text-[11px] font-semibold text-muted-foreground uppercase">High Delta</span>
              <div className="mt-2 text-2xl font-black text-white">
                {comparison.high_delta > 0 ? `+${comparison.high_delta}` : comparison.high_delta}
              </div>
            </div>
            <div className="rounded-xl border border-border/80 bg-[#111827] p-4">
              <span className="text-[11px] font-semibold text-muted-foreground uppercase">Resolved Findings</span>
              <div className="mt-2 text-2xl font-black text-emerald-400">
                {comparison.resolved_findings.length}
              </div>
            </div>
            <div className="rounded-xl border border-border/80 bg-[#111827] p-4">
              <span className="text-[11px] font-semibold text-muted-foreground uppercase">New Findings</span>
              <div className="mt-2 text-2xl font-black text-rose-400">
                {comparison.new_findings.length}
              </div>
            </div>
          </div>

          {/* Detailed Lists */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Resolved Vulnerabilities */}
            <div className="rounded-xl border border-border/80 bg-[#111827] p-5">
              <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                Resolved Vulnerabilities ({comparison.resolved_findings.length})
              </h3>
              {comparison.resolved_findings.length === 0 ? (
                <p className="text-xs text-muted-foreground">No vulnerabilities were resolved between these runs.</p>
              ) : (
                <div className="space-y-2">
                  {comparison.resolved_findings.map((f: any) => (
                    <div
                      key={f.id}
                      className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 flex items-center justify-between"
                    >
                      <div>
                        <div className="text-xs font-bold text-white">{f.title}</div>
                        <div className="text-[10px] text-muted-foreground mt-0.5">{f.asset_target}</div>
                      </div>
                      <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-400">
                        FIXED
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* New Vulnerabilities */}
            <div className="rounded-xl border border-border/80 bg-[#111827] p-5">
              <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
                <AlertTriangle className="h-4 w-4 text-rose-400" />
                Newly Discovered Vulnerabilities ({comparison.new_findings.length})
              </h3>
              {comparison.new_findings.length === 0 ? (
                <p className="text-xs text-muted-foreground">No new vulnerabilities were introduced.</p>
              ) : (
                <div className="space-y-2">
                  {comparison.new_findings.map((f: any) => (
                    <div
                      key={f.id}
                      className="rounded-lg border border-rose-500/20 bg-rose-500/5 p-3 flex items-center justify-between"
                    >
                      <div>
                        <div className="text-xs font-bold text-white">{f.title}</div>
                        <div className="text-[10px] text-muted-foreground mt-0.5">{f.asset_target}</div>
                      </div>
                      <span className="rounded bg-rose-500/20 px-2 py-0.5 text-[10px] font-bold text-rose-400">
                        {f.severity}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
