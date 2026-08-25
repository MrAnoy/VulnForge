'use client';

import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  AlertTriangle,
  FileCode,
  CheckCircle2,
  ExternalLink,
  Bot,
  Activity,
  History,
  Info,
  GraduationCap,
  Code,
  Briefcase,
  Shield,
  HelpCircle,
  Copy,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useViewMode } from '@/lib/view-mode-context';

interface FindingDetailProps {
  finding: any;
  onClose: () => void;
  onStatusUpdated?: (updated: any) => void;
}

export function FindingDetailDrawer({ finding, onClose, onStatusUpdated }: FindingDetailProps) {
  const { mode, isBeginner, isExecutive, isDeveloper, isProfessional } = useViewMode();
  const [currentFinding, setCurrentFinding] = useState(finding);
  const [statusReason, setStatusReason] = useState('');
  const [selectedStatus, setSelectedStatus] = useState(finding?.status || 'OPEN');
  const [updating, setUpdating] = useState(false);
  const [aiExplanation, setAiExplanation] = useState<any>(null);
  const [loadingAi, setLoadingAi] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'remediation' | 'evidence' | 'timeline'>('overview');

  if (!finding) return null;

  const handleUpdateStatus = async () => {
    if (!statusReason.trim() && selectedStatus !== currentFinding.status) {
      alert('Please provide a justification / reason for changing the finding status.');
      return;
    }
    setUpdating(true);
    try {
      const updated = await api.updateFindingStatus(currentFinding.id, {
        status: selectedStatus,
        reason: statusReason || 'Status update via web console',
      });
      setCurrentFinding(updated);
      setStatusReason('');
      if (onStatusUpdated) onStatusUpdated(updated);
    } catch (err: any) {
      alert(`Error updating status: ${err.message}`);
    } finally {
      setUpdating(false);
    }
  };

  const handleFetchAiExplanation = async () => {
    setLoadingAi(true);
    try {
      const exp = await api.explainFinding(currentFinding.id);
      setAiExplanation(exp);
    } catch (err: any) {
      alert(`Error fetching AI explanation: ${err.message}`);
    } finally {
      setLoadingAi(false);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/15 text-red-400 border-red-500/30';
      case 'high':
        return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
      case 'medium':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      case 'low':
        return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-2xl flex-col border-l border-border/80 bg-[#0d121f] shadow-2xl overflow-y-auto">
      {/* Header */}
      <div className="sticky top-0 z-10 flex items-center justify-between border-b border-border/60 bg-[#090d16]/90 px-6 py-4 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <span
            className={`rounded-full border px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider ${getSeverityBadge(
              currentFinding.severity
            )}`}
          >
            {currentFinding.severity}
          </span>
          <span className="text-xs font-medium text-muted-foreground">{currentFinding.category}</span>
          <span className="rounded bg-slate-800/80 px-2 py-0.5 text-[10px] text-blue-400 font-semibold uppercase">
            {mode} View
          </span>
        </div>
        <button
          onClick={onClose}
          className="rounded-lg p-1.5 text-muted-foreground hover:bg-slate-800 hover:text-white"
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      <div className="space-y-6 p-6">
        {/* Title */}
        <div>
          <h2 className="text-lg font-bold text-white leading-snug">{currentFinding.title}</h2>
          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
            <span className="font-mono text-slate-300">
              {currentFinding.asset_target}
              {currentFinding.endpoint ? ` (${currentFinding.endpoint})` : ''}
            </span>
            {currentFinding.cwe && (
              <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-blue-400">
                {currentFinding.cwe}
              </span>
            )}
          </div>
        </div>

        {/* Beginner Perspective Mode Card */}
        {isBeginner && (
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-4 space-y-2">
            <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
              <HelpCircle className="h-3.5 w-3.5" /> Plain-English Explanation
            </h3>
            <p className="text-xs text-slate-200 leading-relaxed">
              <strong>What is this issue?</strong> {currentFinding.description}
            </p>
            <p className="text-xs text-slate-300 leading-relaxed">
              <strong>Is this serious?</strong> This is rated{' '}
              <strong className="text-white">{currentFinding.severity}</strong> severity. Addressing it prevents external attackers from taking advantage of this weakness.
            </p>
          </div>
        )}

        {/* Executive Mode Card */}
        {isExecutive && (
          <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 p-4 space-y-2">
            <h3 className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
              <Briefcase className="h-3.5 w-3.5" /> Business & Compliance Risk
            </h3>
            <p className="text-xs text-slate-200 leading-relaxed">
              {currentFinding.impact}
            </p>
            <p className="text-xs text-amber-300/80">
              <strong>Triage SLA:</strong> {currentFinding.severity === 'Critical' ? '24 Hours' : currentFinding.severity === 'High' ? '7 Days' : '30 Days'}
            </p>
          </div>
        )}

        {/* Risk & CVSS Score Card */}
        <div className="grid grid-cols-2 gap-4 rounded-xl border border-border/60 bg-[#111827] p-4">
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              Platform Risk Score
            </div>
            <div className="mt-1 flex items-baseline gap-2">
              <span className="text-2xl font-black text-blue-400">{currentFinding.platform_risk_score}</span>
              <span className="text-xs text-muted-foreground">/ 100</span>
            </div>
            <div className="mt-1 text-[11px] text-slate-400">Contextualized risk</div>
          </div>
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              Industry CVSS v3.1
            </div>
            <div className="mt-1 flex items-baseline gap-2">
              <span className="text-2xl font-black text-orange-400">{currentFinding.cvss_score}</span>
              <span className="text-xs text-muted-foreground">/ 10.0</span>
            </div>
            <div className="mt-1 text-[11px] text-slate-400">Base severity vector</div>
          </div>
        </div>

        {/* Description */}
        <div className="rounded-xl border border-border/50 bg-[#111827] p-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Description</h3>
          <p className="mt-2 text-xs leading-relaxed text-slate-200">{currentFinding.description}</p>
        </div>

        {/* Business Impact */}
        <div className="rounded-xl border border-border/50 bg-[#111827] p-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400">Business & Technical Impact</h3>
          <p className="mt-2 text-xs leading-relaxed text-slate-200">{currentFinding.impact}</p>
        </div>

        {/* Remediation Action Plan */}
        <div className="rounded-xl border border-blue-500/30 bg-blue-950/20 p-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-blue-400 flex items-center gap-1.5">
            <Code className="h-3.5 w-3.5" /> Developer Remediation Guidance
          </h3>
          <p className="mt-2 text-xs leading-relaxed text-slate-200 whitespace-pre-wrap">{currentFinding.remediation}</p>
        </div>

        {/* AI Explanation Button / Section */}
        <div className="rounded-xl border border-indigo-500/30 bg-indigo-950/20 p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Bot className="h-4 w-4 text-indigo-400" />
              <span className="text-xs font-bold text-indigo-200">AI Vulnerability Breakdown</span>
            </div>
            {!aiExplanation && (
              <button
                onClick={handleFetchAiExplanation}
                disabled={loadingAi}
                className="rounded-lg bg-indigo-600 px-3 py-1 text-xs font-semibold text-white transition hover:bg-indigo-500 disabled:opacity-50"
              >
                {loadingAi ? 'Analyzing...' : 'Generate AI Fix Guide'}
              </button>
            )}
          </div>

          {aiExplanation && (
            <div className="mt-4 space-y-3 text-xs text-slate-200">
              <div>
                <span className="font-semibold text-indigo-300">Executive Overview:</span>
                <p className="mt-1 text-slate-300">{aiExplanation.plain_english_summary}</p>
              </div>
              <div>
                <span className="font-semibold text-indigo-300">Developer Action Plan:</span>
                <p className="mt-1 whitespace-pre-wrap text-slate-300">{aiExplanation.developer_fix_guide}</p>
              </div>
              {aiExplanation.code_examples && (
                <div className="mt-2 rounded-lg bg-[#050811] p-3 font-mono text-[11px] text-sky-400">
                  {aiExplanation.code_examples}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Evidence */}
        {currentFinding.evidence && currentFinding.evidence.output_snippet && (
          <div className="rounded-xl border border-border/50 bg-[#111827] p-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              Technical Evidence Snippet (Sanitized)
            </h3>
            <pre className="mt-2 max-h-60 overflow-x-auto rounded-lg bg-[#050811] p-3 font-mono text-[11px] text-cyan-400 whitespace-pre-wrap">
              {currentFinding.evidence.output_snippet}
            </pre>
          </div>
        )}

        {/* Status Workflow */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
            Vulnerability Triage & Status Workflow
          </h3>
          <div className="mt-3 flex flex-wrap gap-2">
            {['OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'].map((st) => (
              <button
                key={st}
                onClick={() => setSelectedStatus(st)}
                className={`rounded-lg border px-3 py-1.5 text-xs font-semibold transition ${
                  selectedStatus === st
                    ? 'border-blue-500 bg-blue-600/20 text-blue-400 ring-1 ring-blue-500'
                    : 'border-border bg-slate-900 text-slate-400 hover:text-white'
                }`}
              >
                {st.replace('_', ' ')}
              </button>
            ))}
          </div>

          <div className="mt-3">
            <input
              type="text"
              placeholder="Reason or remediation notes (required for false positive / accept risk)..."
              value={statusReason}
              onChange={(e) => setStatusReason(e.target.value)}
              className="w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-xs text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
            />
          </div>

          <div className="mt-3 flex justify-end">
            <button
              onClick={handleUpdateStatus}
              disabled={updating || selectedStatus === currentFinding.status}
              className="rounded-lg bg-blue-600 px-4 py-1.5 text-xs font-semibold text-white transition hover:bg-blue-500 disabled:opacity-40"
            >
              {updating ? 'Updating...' : 'Save Status Update'}
            </button>
          </div>
        </div>

        {/* Audit History */}
        {currentFinding.status_history && currentFinding.status_history.length > 0 && (
          <div className="rounded-xl border border-border/40 bg-[#090d16] p-4 text-xs">
            <h4 className="font-semibold text-slate-300">Status History Audit Trail</h4>
            <div className="mt-2 space-y-2">
              {currentFinding.status_history.map((h: any, idx: number) => (
                <div key={idx} className="border-l-2 border-slate-700 pl-3 py-1">
                  <div className="font-medium text-slate-200">
                    {h.from_status} &rarr; <span className="text-blue-400">{h.to_status}</span>
                  </div>
                  <div className="text-[11px] text-muted-foreground">
                    By {h.changed_by} &bull; {new Date(h.timestamp).toLocaleString()}
                  </div>
                  {h.reason && <div className="text-[11px] text-slate-400 mt-0.5">"{h.reason}"</div>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
