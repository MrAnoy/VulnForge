'use client';

import React, { useEffect, useState, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  Crosshair,
  CheckCircle2,
  AlertCircle,
  Clock,
  Terminal,
  StopCircle,
  FileText,
  Shield,
  Activity,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import { api } from '@/lib/api';

const phases = [
  { id: 'INITIALIZING', label: 'Initializing' },
  { id: 'SCOPE_VALIDATION', label: 'Scope Check' },
  { id: 'RECON', label: 'Reconnaissance' },
  { id: 'DISCOVERY', label: 'Network Discovery' },
  { id: 'ASSESSMENT', label: 'Security Assessment' },
  { id: 'CORRELATION', label: 'Correlation' },
  { id: 'RISK_ANALYSIS', label: 'Risk Scoring' },
  { id: 'COMPLETED', label: 'Completed' },
];

export default function AssessmentConsolePage() {
  const { id } = useParams();
  const router = useRouter();
  const assessmentId = id as string;

  const [assessment, setAssessment] = useState<any>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [isCancelling, setIsCancelling] = useState(false);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  const loadAssessmentData = async () => {
    try {
      const aData = await api.getAssessment(assessmentId);
      setAssessment(aData);
      if (aData.project_id) {
        const fData = await api.getFindings(aData.project_id);
        const filtered = fData.filter((f) => f.assessment_id === assessmentId);
        setFindings(filtered);
      }
    } catch (err) {
      console.error('Error fetching assessment', err);
    }
  };

  useEffect(() => {
    loadAssessmentData();
    const interval = setInterval(loadAssessmentData, 3000);
    return () => clearInterval(interval);
  }, [assessmentId]);

  // Connect Server-Sent Events (SSE) Stream
  useEffect(() => {
    const eventSource = new EventSource(`http://127.0.0.1:8000/api/assessments/${assessmentId}/stream`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setLogs((prev) => {
          if (prev.some((l) => l.timestamp === data.timestamp && l.message === data.message)) {
            return prev;
          }
          return [...prev, data];
        });
      } catch (err) {
        console.error('SSE parse error', err);
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [assessmentId]);

  // Auto-scroll terminal
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const handleCancelScan = async () => {
    if (!confirm('Are you sure you want to trigger the emergency kill switch for this assessment?')) return;
    setIsCancelling(true);
    try {
      await api.cancelAssessment(assessmentId);
      await loadAssessmentData();
    } catch (err: any) {
      alert(`Error cancelling assessment: ${err.message}`);
    } finally {
      setIsCancelling(false);
    }
  };

  const getPhaseIndex = (currPhase: string) => {
    const idx = phases.findIndex((p) => p.id === currPhase);
    return idx === -1 ? 0 : idx;
  };

  const currentPhaseIndex = getPhaseIndex(assessment?.current_phase || 'INITIALIZING');
  const isFinished = assessment?.status === 'COMPLETED' || assessment?.status === 'FAILED' || assessment?.status === 'CANCELLED';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-border/40 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="rounded bg-blue-500/10 px-2 py-0.5 text-[10px] font-bold text-blue-400 border border-blue-500/20">
              {assessment?.profile || 'STANDARD_VAPT'}
            </span>
            <span className="text-xs text-muted-foreground">ID: {assessmentId.slice(0, 8)}...</span>
          </div>
          <h1 className="text-2xl font-black text-white mt-1">
            {assessment?.name || 'Live Security Assessment'}
          </h1>
          <div className="text-xs text-muted-foreground mt-0.5">
            Targets: <span className="font-mono text-slate-300">{assessment?.targets?.join(', ') || 'Scoped targets'}</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {!isFinished && (
            <button
              onClick={handleCancelScan}
              disabled={isCancelling}
              className="flex items-center gap-1.5 rounded-lg border border-red-500/40 bg-red-950/20 px-3.5 py-2 text-xs font-bold text-red-400 transition hover:bg-red-900/30"
            >
              <StopCircle className="h-4 w-4" />
              <span>{isCancelling ? 'Stopping...' : 'Emergency Kill Switch'}</span>
            </button>
          )}

          {assessment?.status === 'COMPLETED' && (
            <Link
              href="/reports"
              className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-xs font-bold text-white shadow-lg shadow-blue-600/30 transition hover:bg-blue-500"
            >
              <FileText className="h-4 w-4" />
              <span>Generate Deliverable Report</span>
            </Link>
          )}
        </div>
      </div>

      {/* Phase Stepper */}
      <div className="rounded-xl border border-border/60 bg-[#111827] p-5 shadow-lg">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
            Assessment Phase Stepper
          </span>
          <span className="text-xs font-bold text-blue-400">
            {assessment?.progress_percent || 0}% Complete
          </span>
        </div>

        {/* Progress bar */}
        <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800 mb-6">
          <div
            className="h-full bg-gradient-to-r from-blue-600 to-indigo-500 transition-all duration-500"
            style={{ width: `${assessment?.progress_percent || 5}%` }}
          />
        </div>

        {/* Phase Pills */}
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8">
          {phases.map((p, idx) => {
            const isDone = idx < currentPhaseIndex || assessment?.status === 'COMPLETED';
            const isCurrent = idx === currentPhaseIndex && assessment?.status === 'RUNNING';
            return (
              <div
                key={p.id}
                className={`flex flex-col items-center rounded-lg border p-2.5 text-center transition ${
                  isDone
                    ? 'border-emerald-500/30 bg-emerald-950/20 text-emerald-400'
                    : isCurrent
                    ? 'border-blue-500 bg-blue-600/20 text-blue-400 ring-1 ring-blue-500 animate-pulse'
                    : 'border-border/40 bg-[#0b0f19] text-muted-foreground'
                }`}
              >
                <div className="flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold">
                  {isDone ? <CheckCircle2 className="h-4 w-4" /> : idx + 1}
                </div>
                <span className="mt-1 text-[10px] font-semibold leading-tight">{p.label}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Main Execution Split: Live Terminal Logs + Real-Time Findings */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Terminal Logs Window */}
        <div className="rounded-xl border border-border/60 bg-[#070b14] shadow-2xl overflow-hidden flex flex-col h-[420px]">
          <div className="flex items-center justify-between border-b border-border/40 bg-[#0d121f] px-4 py-2.5 text-xs">
            <div className="flex items-center gap-2">
              <Terminal className="h-4 w-4 text-blue-400" />
              <span className="font-bold text-white">Live Execution Terminal</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
              </span>
              <span className="text-[11px] text-muted-foreground font-mono">STREAMING</span>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-4 font-mono text-[11px] space-y-1.5 leading-relaxed text-slate-300">
            {logs.length === 0 ? (
              <div className="text-slate-500">Connecting to live assessment log stream...</div>
            ) : (
              logs.map((l, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  <span className="text-slate-500 shrink-0">
                    [{new Date(l.timestamp).toLocaleTimeString()}]
                  </span>
                  <span
                    className={`font-bold shrink-0 ${
                      l.level === 'ERROR'
                        ? 'text-red-400'
                        : l.level === 'WARNING'
                        ? 'text-yellow-400'
                        : 'text-blue-400'
                    }`}
                  >
                    [{l.phase || 'INFO'}]
                  </span>
                  <span className="text-slate-200">{l.message}</span>
                </div>
              ))
            )}
            <div ref={terminalEndRef} />
          </div>
        </div>

        {/* Live Findings Discovered */}
        <div className="rounded-xl border border-border/60 bg-[#111827] shadow-lg p-5 flex flex-col h-[420px]">
          <div className="flex items-center justify-between border-b border-border/40 pb-3">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              <h3 className="text-sm font-bold text-white">Discovered Findings ({findings.length})</h3>
            </div>
            <span className="text-xs text-muted-foreground">Normalized & Deduplicated</span>
          </div>

          <div className="mt-3 flex-1 overflow-y-auto divide-y divide-border/30 space-y-1">
            {findings.length === 0 ? (
              <div className="py-16 text-center text-xs text-muted-foreground">
                {isFinished
                  ? 'No security vulnerabilities identified in target scope.'
                  : 'Probing in progress. Findings will appear here in real-time as scanners discover and normalize issues...'}
              </div>
            ) : (
              findings.map((f) => (
                <div key={f.id} className="py-2.5 text-xs flex items-center justify-between">
                  <div className="space-y-0.5 max-w-[75%]">
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded px-1.5 py-0.2 text-[10px] font-bold uppercase ${
                          f.severity === 'Critical'
                            ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                            : f.severity === 'High'
                            ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                            : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                        }`}
                      >
                        {f.severity}
                      </span>
                      <span className="font-semibold text-slate-200 truncate">{f.title}</span>
                    </div>
                    <div className="text-[11px] text-muted-foreground font-mono truncate">
                      {f.endpoint || '/'} &bull; {f.scanner}
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="font-bold text-blue-400">{f.platform_risk_score}</span>
                    <span className="text-[10px] text-muted-foreground">/100</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
