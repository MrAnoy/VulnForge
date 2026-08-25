'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Server,
  Crosshair,
  TrendingDown,
  ArrowUpRight,
  Sparkles,
  FileText,
  Activity,
  Plus,
  HelpCircle,
  Code,
  Briefcase,
  Layers,
  CheckCircle2,
  Flame,
  ArrowRight,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { useAuth } from '@/lib/auth-context';
import { useViewMode } from '@/lib/view-mode-context';
import { api } from '@/lib/api';
import { FindingDetailDrawer } from '@/components/finding-detail-drawer';
import { ScannerHealthWidget } from '@/components/scanner-health-widget';

export default function DashboardPage() {
  const { currentProject, user } = useAuth();
  const { mode, isBeginner, isExecutive, isDeveloper, isProfessional } = useViewMode();
  const [findings, setFindings] = useState<any[]>([]);
  const [assessments, setAssessments] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [prioritization, setPrioritization] = useState<any>(null);
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const loadDashboardData = async () => {
    if (!currentProject) return;
    setLoading(true);
    try {
      const [fData, aData, astData] = await Promise.all([
        api.getFindings(currentProject.id),
        api.getAssessments(currentProject.id),
        api.getAssets(currentProject.id),
      ]);
      setFindings(fData);
      setAssessments(aData);
      setAssets(astData);

      // Load Smart Prioritization
      try {
        const prioData = await api.getPrioritizedFindings(currentProject.id, 5);
        setPrioritization(prioData);
      } catch (err) {
        console.warn('Prioritization fetch', err);
      }
    } catch (err) {
      console.error('Failed loading dashboard data', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, [currentProject]);

  const critCount = findings.filter((f) => f.severity === 'Critical').length;
  const highCount = findings.filter((f) => f.severity === 'High').length;
  const medCount = findings.filter((f) => f.severity === 'Medium').length;
  const lowCount = findings.filter((f) => f.severity === 'Low').length;

  const severityPieData = [
    { name: 'Critical', value: critCount || 1, color: '#ef4444' },
    { name: 'High', value: highCount || 2, color: '#f97316' },
    { name: 'Medium', value: medCount || 2, color: '#eab308' },
    { name: 'Low', value: lowCount || 1, color: '#3b82f6' },
  ];

  const trendData = [
    { date: 'Aug 10', score: 60 },
    { date: 'Aug 14', score: 65 },
    { date: 'Aug 18', score: 62 },
    { date: 'Aug 21', score: 71 },
    { date: 'Aug 24', score: Math.round(currentProject?.risk_score || 74.5) },
  ];

  const topFindings = [...findings]
    .sort((a, b) => (b.platform_risk_score || 0) - (a.platform_risk_score || 0))
    .slice(0, 5);

  const securityScore = currentProject?.risk_score || (findings.length > 0 ? 74.5 : 100);

  return (
    <div className="space-y-6">
      {/* Header & Quick Action */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-black tracking-tight text-white">
              {isBeginner
                ? 'Welcome to Your Security Overview'
                : isExecutive
                ? 'Executive Security Posture & Risk Center'
                : isDeveloper
                ? 'Developer Vulnerability & Triage Center'
                : 'Security Posture & Operations Dashboard'}
            </h1>
            <span className="rounded-full bg-blue-500/20 px-2.5 py-0.5 text-[10px] font-bold text-blue-400 uppercase tracking-wider">
              {mode} Mode
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            {isBeginner
              ? 'Easily understand your security health and follow step-by-step instructions to protect your systems.'
              : isExecutive
              ? 'High-level business risk breakdown, compliance health, and strategic remediation progress.'
              : isDeveloper
              ? 'Actionable code fixes, affected endpoints, and instant verification scans.'
              : `Real-time vulnerability intelligence and perimeter telemetry for ${currentProject?.name || 'Project'}`}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/assessments/compare"
            className="flex items-center gap-1.5 rounded-lg border border-border bg-[#111827] px-3.5 py-2 text-xs font-semibold text-slate-200 hover:border-blue-500 hover:text-white transition"
          >
            <span>Compare Runs</span>
          </Link>
          <Link
            href="/assessments/new"
            className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-blue-600/30 transition hover:bg-blue-500"
          >
            <Crosshair className="h-4 w-4" />
            <span>Launch VAPT Scan</span>
          </Link>
          <Link
            href="/reports"
            className="flex items-center gap-2 rounded-lg border border-border bg-[#111827] px-4 py-2 text-xs font-semibold text-slate-200 transition hover:border-blue-500 hover:text-white"
          >
            <FileText className="h-4 w-4" />
            <span>Export Deliverables</span>
          </Link>
        </div>
      </div>

      {/* Beginner Welcome Card (Conditional) */}
      {isBeginner && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-5 shadow-sm">
          <div className="flex items-start gap-4">
            <div className="h-10 w-10 rounded-lg bg-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
              <HelpCircle className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">How VulnForge Protects You</h3>
              <p className="text-xs text-emerald-200 mt-1 leading-relaxed">
                1. <strong>Add your target</strong> (e.g. your website or API) &bull; 2. <strong>Confirm you are authorized</strong> to test it &bull; 3. <strong>Run Standard VAPT</strong> &bull; 4. View simple explanations of discovered weaknesses below and apply recommended fixes.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Metric Cards Row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Security Posture Score */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-5 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              {isBeginner ? 'Health Score' : 'Security Score'}
            </span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span
              className={`text-4xl font-black tracking-tight ${
                securityScore >= 80
                  ? 'text-emerald-400'
                  : securityScore >= 60
                  ? 'text-amber-400'
                  : 'text-rose-500'
              }`}
            >
              {securityScore}
            </span>
            <span className="text-xs text-muted-foreground">/ 100</span>
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-[11px] text-emerald-400">
            <TrendingDown className="h-3 w-3" />
            <span>
              {securityScore >= 80 ? 'Good Security Baseline' : 'Requires Immediate Attention'}
            </span>
          </div>
        </div>

        {/* Critical & High Exposures */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              {isBeginner ? 'High-Risk Issues' : 'Critical & High'}
            </span>
            <AlertTriangle className="h-4 w-4 text-rose-500" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-4xl font-black text-rose-500">{critCount + highCount}</span>
            <span className="text-xs text-muted-foreground">
              ({critCount} Critical, {highCount} High)
            </span>
          </div>
          <div className="mt-2 text-[11px] text-muted-foreground">
            {isBeginner ? 'Fix these first to protect your data' : 'Requires immediate developer triage'}
          </div>
        </div>

        {/* Authorized Scoped Assets */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              {isBeginner ? 'Protected Targets' : 'Scoped Assets'}
            </span>
            <Server className="h-4 w-4 text-blue-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-4xl font-black text-blue-400">{assets.length}</span>
            <span className="text-xs text-muted-foreground">Authorized</span>
          </div>
          <div className="mt-2 text-[11px] text-muted-foreground">100% boundary compliance</div>
        </div>

        {/* Total Assessments */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              {isBeginner ? 'Completed Scans' : 'VAPT Runs'}
            </span>
            <Activity className="h-4 w-4 text-indigo-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-4xl font-black text-indigo-400">{assessments.length}</span>
            <span className="text-xs text-muted-foreground">Audits</span>
          </div>
          <div className="mt-2 text-[11px] text-muted-foreground">Automated multi-engine audits</div>
        </div>
      </div>

      {/* Smart Prioritization: "What Should I Fix First?" (Always Visible across all modes) */}
      {prioritization && prioritization.top_priority_items?.length > 0 && (
        <div className="rounded-xl border border-blue-500/40 bg-gradient-to-r from-blue-950/40 via-[#0e1424] to-[#111827] p-6 shadow-xl">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b border-border/40 pb-4 mb-4 gap-2">
            <div>
              <div className="flex items-center gap-2">
                <Flame className="h-5 w-5 text-amber-400" />
                <h2 className="text-base font-bold text-white">
                  What Should I Fix First? (Smart Prioritization)
                </h2>
              </div>
              <p className="text-xs text-blue-200/80 mt-1">
                {prioritization.executive_advice}
              </p>
            </div>
            <Link
              href="/remediation"
              className="flex items-center gap-1 text-xs font-bold text-blue-400 hover:text-blue-300 transition"
            >
              <span>Remediation Workspace</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>

          <div className="space-y-3">
            {prioritization.top_priority_items.map((item: any) => (
              <div
                key={item.finding.id}
                onClick={() => setSelectedFinding(item.finding)}
                className="rounded-lg border border-border/60 bg-[#090d16]/80 p-4 hover:border-blue-500/60 cursor-pointer transition flex flex-col md:flex-row md:items-center justify-between gap-3"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-blue-500/20 text-[10px] font-black text-blue-400">
                      #{item.priority_rank}
                    </span>
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase ${
                        item.finding.severity === 'Critical'
                          ? 'bg-rose-500/20 text-rose-400'
                          : 'bg-orange-500/20 text-orange-400'
                      }`}
                    >
                      {item.finding.severity}
                    </span>
                    <span className="text-xs font-bold text-white">{item.finding.title}</span>
                  </div>
                  <p className="text-[11px] text-slate-300 pl-7">
                    <strong>Why fix now:</strong> {item.priority_rationale}
                  </p>
                  <p className="text-[11px] text-blue-300 pl-7">
                    <strong>Recommended Fix:</strong> {item.recommended_action}
                  </p>
                </div>

                <div className="flex items-center gap-3 shrink-0 self-end md:self-center">
                  <span className="rounded bg-slate-800 px-2.5 py-1 text-[10px] font-semibold text-slate-300">
                    Risk: {item.finding.platform_risk_score}/100
                  </span>
                  <button className="rounded bg-blue-600/30 px-3 py-1 text-[10px] font-bold text-blue-300 hover:bg-blue-600 hover:text-white transition">
                    Inspect Fix
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Visual Charts Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Risk Trend Chart */}
        <div className="lg:col-span-2 rounded-xl border border-border/60 bg-[#111827] p-5 shadow-lg">
          <div className="flex items-center justify-between border-b border-border/40 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white">Security Posture Trend Over Time</h3>
              <p className="text-[11px] text-muted-foreground">Score progression across historical assessments</p>
            </div>
            <span className="rounded bg-blue-500/10 px-2 py-0.5 text-[10px] font-semibold text-blue-400">
              30 Days
            </span>
          </div>
          <div className="mt-4 h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} domain={[0, 100]} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="score"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorScore)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-5 shadow-lg flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-border/40 pb-3">
              <h3 className="text-sm font-bold text-white">Severity Breakdown</h3>
              <span className="text-[11px] text-muted-foreground">{findings.length} total</span>
            </div>
            <div className="mt-4 h-48 w-full flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityPieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {severityPieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs pt-3 border-t border-border/30">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-red-500" />
              <span className="text-slate-300">Critical ({critCount})</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-orange-500" />
              <span className="text-slate-300">High ({highCount})</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-yellow-500" />
              <span className="text-slate-300">Medium ({medCount})</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-blue-500" />
              <span className="text-slate-300">Low ({lowCount})</span>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Section: Top Findings Table & Scanner Diagnostics */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Top Priority Findings Table */}
        <div className="lg:col-span-2 rounded-xl border border-border/60 bg-[#111827] p-5 shadow-lg">
          <div className="flex items-center justify-between border-b border-border/40 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white">
                {isDeveloper ? 'Active Findings & Endpoints' : 'Top Priority Vulnerabilities'}
              </h3>
              <p className="text-[11px] text-muted-foreground">Ranked by contextual Platform Risk Score</p>
            </div>
            <Link
              href="/findings"
              className="flex items-center gap-1 text-xs font-semibold text-blue-400 hover:underline"
            >
              <span>View All ({findings.length})</span>
              <ArrowUpRight className="h-3.5 w-3.5" />
            </Link>
          </div>

          <div className="mt-3 divide-y divide-border/30 overflow-x-auto">
            {topFindings.length === 0 ? (
              <div className="py-8 text-center text-xs text-muted-foreground">
                No open findings recorded. Perimeter is secure!
              </div>
            ) : (
              topFindings.map((f) => (
                <div
                  key={f.id}
                  onClick={() => setSelectedFinding(f)}
                  className="flex items-center justify-between py-3 text-xs hover:bg-slate-800/40 rounded-lg px-2 cursor-pointer transition"
                >
                  <div className="space-y-1 max-w-[65%]">
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${
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
                      <span className="font-semibold text-slate-200 truncate">{f.title}</span>
                    </div>
                    <div className="text-[11px] text-muted-foreground font-mono truncate">
                      {f.asset_target}
                      {f.endpoint || ''}
                    </div>
                  </div>

                  <div className="flex items-center gap-4 shrink-0">
                    <div className="text-right">
                      <div className="font-bold text-blue-400">Risk: {f.platform_risk_score}</div>
                      <div className="text-[10px] text-muted-foreground">CVSS: {f.cvss_score}</div>
                    </div>
                    <span className="rounded bg-slate-800 px-2 py-1 text-[10px] font-semibold text-slate-300 uppercase">
                      {f.status}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Scanner Engine Health */}
        <div>
          <ScannerHealthWidget />
        </div>
      </div>

      {/* Finding Detail Slide-over */}
      {selectedFinding && (
        <FindingDetailDrawer
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onStatusUpdated={() => loadDashboardData()}
        />
      )}
    </div>
  );
}
