'use client';

import React, { useEffect, useState } from 'react';
import {
  FileText,
  Download,
  Plus,
  ShieldCheck,
  CheckCircle2,
  FileCode,
  ExternalLink,
  Sparkles,
  Palette,
  Briefcase,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';

export default function ReportsPage() {
  const { currentProject } = useAuth();
  const [assessments, setAssessments] = useState<any[]>([]);
  const [reports, setReports] = useState<any[]>([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState('');
  const [reportType, setReportType] = useState('EXECUTIVE');
  const [reportFormat, setReportFormat] = useState('HTML');
  const [title, setTitle] = useState('');
  const [includeEvidence, setIncludeEvidence] = useState(true);
  const [showBranding, setShowBranding] = useState(false);
  const [companyName, setCompanyName] = useState('VulnForge Security Services');
  const [consultantName, setConsultantName] = useState('Senior Security Architect');
  const [clientName, setClientName] = useState(currentProject?.client_name || '');
  const [classification, setClassification] = useState('CONFIDENTIAL');
  const [accentColor, setAccentColor] = useState('#3b82f6');
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);

  const loadData = async () => {
    if (!currentProject) return;
    setLoading(true);
    try {
      const [aData, rData] = await Promise.all([
        api.getAssessments(currentProject.id),
        api.getReports(currentProject.id),
      ]);
      setAssessments(aData);
      setReports(rData);
      if (aData.length > 0 && !selectedAssessmentId) {
        setSelectedAssessmentId(aData[0].id);
      }
    } catch (err) {
      console.error('Error loading reports', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [currentProject]);

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAssessmentId) {
      alert('Please select an assessment to generate a report for.');
      return;
    }
    setGenerating(true);
    try {
      const rep = await api.generateReport({
        assessment_id: selectedAssessmentId,
        report_type: reportType,
        report_format: reportFormat,
        title: title || undefined,
        include_evidence: includeEvidence,
        branding: {
          company_name: companyName,
          consultant_name: consultantName,
          client_name: clientName || undefined,
          classification: classification,
          accent_color: accentColor,
        },
      });
      await loadData();
      if (rep.download_url) {
        window.open(`http://127.0.0.1:8000${rep.download_url}`, '_blank');
      }
    } catch (err: any) {
      alert(`Error generating report: ${err.message}`);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-black text-white">Security Deliverable Reports & White-Labeling</h1>
        <p className="text-xs text-muted-foreground mt-1">
          Generate consulting-grade Executive, Technical, and Developer reports in HTML, PDF, JSON, or CSV for{' '}
          <span className="font-semibold text-slate-200">{currentProject?.name}</span>
        </p>
      </div>

      {/* Generator Form */}
      <div className="rounded-xl border border-border/60 bg-[#111827] p-6 shadow-xl space-y-6">
        <div className="flex items-center justify-between border-b border-border/40 pb-3">
          <div className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-blue-400" />
            <h2 className="text-sm font-bold text-white">Generate Deliverable Report</h2>
          </div>
          <button
            type="button"
            onClick={() => setShowBranding(!showBranding)}
            className="flex items-center gap-1.5 rounded-lg border border-border bg-[#0b0f19] px-3 py-1.5 text-xs font-semibold text-slate-300 hover:text-white transition"
          >
            <Palette className="h-3.5 w-3.5 text-indigo-400" />
            <span>{showBranding ? 'Hide White-Label Settings' : 'White-Label Branding'}</span>
          </button>
        </div>

        <form onSubmit={handleGenerateReport} className="space-y-4 text-xs">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="font-semibold text-slate-200">Source Assessment *</label>
              <select
                value={selectedAssessmentId}
                onChange={(e) => setSelectedAssessmentId(e.target.value)}
                className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
              >
                {assessments.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({new Date(a.created_at).toLocaleDateString()}) - {a.profile}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="font-semibold text-slate-200">Custom Title (Optional)</label>
              <input
                type="text"
                placeholder="e.g. Q3 2026 Core Banking Security Evaluation"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="font-semibold text-slate-200">Report Tier / Deliverable Type</label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
                className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
              >
                <option value="EXECUTIVE">Executive Summary (Boardroom / Leadership)</option>
                <option value="TECHNICAL">Technical Security Report (AppSec / Red Team)</option>
                <option value="DEVELOPER">Developer Actionable Fix Guide</option>
              </select>
            </div>

            <div>
              <label className="font-semibold text-slate-200">Export Format</label>
              <select
                value={reportFormat}
                onChange={(e) => setReportFormat(e.target.value)}
                className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
              >
                <option value="HTML">Interactive HTML Deliverable</option>
                <option value="PDF">Formal Document PDF</option>
                <option value="JSON">Structured Machine JSON</option>
                <option value="CSV">Raw Findings CSV</option>
              </select>
            </div>
          </div>

          {/* White-Label Branding Controls */}
          {showBranding && (
            <div className="rounded-xl border border-indigo-500/30 bg-indigo-950/20 p-4 space-y-4">
              <div className="flex items-center gap-2 text-xs font-bold text-indigo-300">
                <Briefcase className="h-4 w-4" />
                <span>Enterprise White-Label Customization</span>
              </div>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                <div>
                  <label className="text-slate-300">Company Name</label>
                  <input
                    type="text"
                    value={companyName}
                    onChange={(e) => setCompanyName(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="text-slate-300">Consultant / Assessor</label>
                  <input
                    type="text"
                    value={consultantName}
                    onChange={(e) => setConsultantName(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="text-slate-300">Client Name</label>
                  <input
                    type="text"
                    placeholder="e.g. Acme Corp"
                    value={clientName}
                    onChange={(e) => setClientName(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="text-slate-300">Classification</label>
                  <select
                    value={classification}
                    onChange={(e) => setClassification(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-1.5 text-white"
                  >
                    <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                    <option value="RESTRICTED">RESTRICTED</option>
                    <option value="INTERNAL AUDIT">INTERNAL AUDIT</option>
                    <option value="PUBLIC SUMMARY">PUBLIC SUMMARY</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-300">Accent Color</label>
                  <input
                    type="color"
                    value={accentColor}
                    onChange={(e) => setAccentColor(e.target.value)}
                    className="mt-1 h-8 w-full rounded-lg border border-border bg-[#0b0f19] px-1 py-1 cursor-pointer"
                  />
                </div>
              </div>
            </div>
          )}

          <div className="pt-2 flex items-center justify-between">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={includeEvidence}
                onChange={(e) => setIncludeEvidence(e.target.checked)}
                className="rounded border-border bg-slate-900 text-blue-600 focus:ring-blue-500"
              />
              <span className="font-medium text-slate-300">Include Sanitized Technical Evidence Snippets</span>
            </label>

            <button
              type="submit"
              disabled={generating || assessments.length === 0}
              className="flex items-center gap-2 rounded-lg bg-blue-600 px-6 py-2.5 font-bold text-white shadow-lg shadow-blue-600/30 transition hover:bg-blue-500 disabled:opacity-40"
            >
              <Download className="h-4 w-4" />
              <span>{generating ? 'Generating Document...' : 'Generate & Download Report'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Generated Reports History */}
      <div className="rounded-xl border border-border/60 bg-[#111827] shadow-lg overflow-hidden">
        <div className="border-b border-border/40 bg-[#0b0f19] px-5 py-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-white">Generated Report Deliverables</h3>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border/60 bg-[#0b0f19]/60 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-5 py-3.5">Report Title</th>
                <th className="px-5 py-3.5">Type</th>
                <th className="px-5 py-3.5">Format</th>
                <th className="px-5 py-3.5">Security Score</th>
                <th className="px-5 py-3.5">Generated At</th>
                <th className="px-5 py-3.5 text-right">Download</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30">
              {reports.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-muted-foreground">
                    No generated reports yet. Select an assessment above and click "Generate & Download Report".
                  </td>
                </tr>
              ) : (
                reports.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-800/30 transition">
                    <td className="px-5 py-4 font-bold text-white">{r.title}</td>
                    <td className="px-5 py-4">
                      <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-semibold text-slate-300">
                        {r.report_type}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <span className="rounded bg-blue-950/40 px-2 py-0.5 text-[10px] font-mono text-blue-300 border border-blue-500/20">
                        {r.report_format}
                      </span>
                    </td>
                    <td className="px-5 py-4 text-blue-400 font-extrabold">{r.security_score}/100</td>
                    <td className="px-5 py-4 text-slate-300">{new Date(r.created_at).toLocaleString()}</td>
                    <td className="px-5 py-4 text-right">
                      {r.download_url && (
                        <a
                          href={`http://127.0.0.1:8000${r.download_url}`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 rounded-lg bg-blue-600/20 px-3 py-1 text-xs font-semibold text-blue-400 border border-blue-500/30 hover:bg-blue-600 hover:text-white transition"
                        >
                          <Download className="h-3.5 w-3.5" />
                          <span>Download</span>
                        </a>
                      )}
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
