'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Crosshair,
  Plus,
  Play,
  CheckCircle2,
  AlertCircle,
  Clock,
  ArrowRight,
  Shield,
  RefreshCw,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';

export default function AssessmentsPage() {
  const { currentProject } = useAuth();
  const [assessments, setAssessments] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const loadAssessments = async () => {
    if (!currentProject) return;
    setLoading(true);
    try {
      const data = await api.getAssessments(currentProject.id);
      setAssessments(data);
    } catch (err) {
      console.error('Failed loading assessments', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssessments();
  }, [currentProject]);

  const getStatusBadge = (status: string, phase: string) => {
    switch (status) {
      case 'COMPLETED':
        return (
          <span className="flex items-center gap-1.5 rounded-full bg-emerald-500/15 px-2.5 py-0.5 text-xs font-bold text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="h-3.5 w-3.5" />
            <span>Completed</span>
          </span>
        );
      case 'RUNNING':
      case 'QUEUED':
        return (
          <span className="flex items-center gap-1.5 rounded-full bg-blue-500/15 px-2.5 py-0.5 text-xs font-bold text-blue-400 border border-blue-500/30 animate-pulse">
            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            <span>{phase || status}</span>
          </span>
        );
      case 'FAILED':
        return (
          <span className="flex items-center gap-1.5 rounded-full bg-red-500/15 px-2.5 py-0.5 text-xs font-bold text-red-400 border border-red-500/30">
            <AlertCircle className="h-3.5 w-3.5" />
            <span>Failed</span>
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1.5 rounded-full bg-slate-800 px-2.5 py-0.5 text-xs font-medium text-slate-300 border border-slate-700">
            <span>{status}</span>
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Security Assessments</h1>
          <p className="text-xs text-muted-foreground mt-1">
            Automated VAPT execution runs, scan history, and live assessment consoles for{' '}
            <span className="font-semibold text-slate-200">{currentProject?.name}</span>
          </p>
        </div>
        <Link
          href="/assessments/new"
          className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-blue-600/30 transition hover:bg-blue-500"
        >
          <Plus className="h-4 w-4" />
          <span>Launch New Assessment</span>
        </Link>
      </div>

      {/* Assessments List */}
      <div className="rounded-xl border border-border/60 bg-[#111827] shadow-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border/60 bg-[#0b0f19] text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-5 py-3.5">Assessment Name</th>
                <th className="px-5 py-3.5">Profile</th>
                <th className="px-5 py-3.5">Status & Phase</th>
                <th className="px-5 py-3.5">Findings Summary</th>
                <th className="px-5 py-3.5">Security Score</th>
                <th className="px-5 py-3.5">Execution Date</th>
                <th className="px-5 py-3.5 text-right">Console</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30">
              {assessments.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-muted-foreground">
                    No assessments conducted yet for this project.{' '}
                    <Link href="/assessments/new" className="text-blue-400 hover:underline">
                      Launch your first assessment &rarr;
                    </Link>
                  </td>
                </tr>
              ) : (
                assessments.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-800/30 transition">
                    <td className="px-5 py-4">
                      <Link
                        href={`/assessments/${a.id}`}
                        className="font-bold text-white hover:text-blue-400 transition"
                      >
                        {a.name}
                      </Link>
                      <div className="text-[11px] text-muted-foreground mt-0.5">
                        {a.targets?.join(', ') || 'Project scope'}
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      <span className="rounded bg-blue-950/40 px-2 py-0.5 font-mono text-[10px] font-semibold text-blue-300 border border-blue-500/20">
                        {a.profile}
                      </span>
                    </td>
                    <td className="px-5 py-4">{getStatusBadge(a.status, a.current_phase)}</td>
                    <td className="px-5 py-4">
                      <div className="flex items-center gap-1.5 font-medium">
                        <span className="text-red-400 font-bold">{a.critical_count || 0} Crit</span>
                        <span className="text-slate-500">&bull;</span>
                        <span className="text-orange-400 font-bold">{a.high_count || 0} High</span>
                        <span className="text-slate-500">&bull;</span>
                        <span className="text-yellow-400 font-bold">{a.medium_count || 0} Med</span>
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      <span className="text-sm font-extrabold text-blue-400">
                        {a.risk_score || 74.5}{' '}
                        <span className="text-[10px] text-muted-foreground font-normal">/ 100</span>
                      </span>
                    </td>
                    <td className="px-5 py-4 text-slate-300">
                      {new Date(a.created_at).toLocaleString()}
                    </td>
                    <td className="px-5 py-4 text-right">
                      <Link
                        href={`/assessments/${a.id}`}
                        className="inline-flex items-center gap-1 rounded-lg bg-slate-800 px-2.5 py-1 text-[11px] font-semibold text-slate-200 hover:bg-blue-600 hover:text-white transition"
                      >
                        <span>Monitor</span>
                        <ArrowRight className="h-3 w-3" />
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
