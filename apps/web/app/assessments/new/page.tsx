'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Crosshair,
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  Play,
  ArrowRight,
  Info,
  Server,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';

const profiles = [
  {
    id: 'STANDARD_VAPT',
    name: 'Standard VAPT (Recommended)',
    desc: 'Balanced automated assessment combining DNS/TLS reconnaissance, Web vulnerability checks, and Network service discovery.',
    badge: 'Popular',
  },
  {
    id: 'QUICK_SCAN',
    name: 'Quick Perimeter Scan',
    desc: 'Fast reconnaissance and critical header/exposure checks in under 2 minutes.',
    badge: 'Fast',
  },
  {
    id: 'WEB_APPLICATION',
    name: 'Web Application Security Assessment',
    desc: 'Focused OWASP Top 10 web vulnerabilities (CORS, CSP, Insecure Cookies, Sensitive files, HTTP Methods).',
    badge: 'Deep Web',
  },
  {
    id: 'API_ASSESSMENT',
    name: 'API Security Assessment',
    desc: 'REST/GraphQL API endpoint inventory, security headers, parameter reflection, and token exposure tests.',
    badge: 'API Focused',
  },
  {
    id: 'NETWORK_ASSESSMENT',
    name: 'Network & Port Assessment',
    desc: 'Authorized network port enumeration and service banner detection with safe argument vectors.',
    badge: 'Infra',
  },
];

export default function NewAssessmentPage() {
  const router = useRouter();
  const { currentProject, user } = useAuth();
  const [assets, setAssets] = useState<any[]>([]);
  const [selectedTargets, setSelectedTargets] = useState<string[]>([]);
  const [customTarget, setCustomTarget] = useState('');
  const [selectedProfile, setSelectedProfile] = useState('STANDARD_VAPT');
  const [scanName, setScanName] = useState('');
  const [authorizedBy, setAuthorizedBy] = useState(user?.full_name || 'Alex Mercer');
  const [authConfirmed, setAuthConfirmed] = useState(false);
  const [scopeValidations, setScopeValidations] = useState<any[]>([]);
  const [validating, setValidating] = useState(false);
  const [launching, setLaunching] = useState(false);

  useEffect(() => {
    if (currentProject) {
      setScanName(`${currentProject.name} - Automated Security Assessment`);
      api.getAssets(currentProject.id).then((data) => {
        setAssets(data);
        if (data.length > 0) {
          setSelectedTargets(data.map((a) => a.target));
        }
      });
    }
  }, [currentProject]);

  const toggleTarget = (target: string) => {
    if (selectedTargets.includes(target)) {
      setSelectedTargets(selectedTargets.filter((t) => t !== target));
    } else {
      setSelectedTargets([...selectedTargets, target]);
    }
  };

  const handleAddCustomTarget = () => {
    if (customTarget.trim() && !selectedTargets.includes(customTarget.trim())) {
      setSelectedTargets([...selectedTargets, customTarget.trim()]);
      setCustomTarget('');
    }
  };

  const handleValidateScope = async () => {
    if (!currentProject || selectedTargets.length === 0) return;
    setValidating(true);
    try {
      const scopeData = await api.getScope(currentProject.id);
      const res = await api.validateScope({
        targets: selectedTargets,
        allowed_targets: scopeData.allowed_targets || selectedTargets,
        excluded_targets: scopeData.excluded_targets || [],
        allow_local_lab: scopeData.allow_local_lab ?? true,
      });
      setScopeValidations(res);
    } catch (err: any) {
      alert(`Scope validation error: ${err.message}`);
    } finally {
      setValidating(false);
    }
  };

  const handleLaunchAssessment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentProject) return;

    if (!authConfirmed) {
      alert('You must confirm target authorization before launching an assessment.');
      return;
    }

    if (selectedTargets.length === 0) {
      alert('Please select or specify at least one authorized target.');
      return;
    }

    setLaunching(true);
    try {
      // 1. Confirm authorization
      await api.confirmAuthorization({
        project_id: currentProject.id,
        authorized_by: authorizedBy,
        authorization_statement: 'I explicitly confirm that our organization owns or has written authorization to assess these targets.',
        target_scope: selectedTargets,
        confirmed: true,
      });

      // 2. Launch assessment
      const assessment = await api.createAssessment({
        project_id: currentProject.id,
        name: scanName,
        profile: selectedProfile,
        target_assets: selectedTargets,
        authorization_confirmed: true,
      });

      // 3. Redirect to live console
      router.push(`/assessments/${assessment.id}`);
    } catch (err: any) {
      alert(`Failed launching assessment: ${err.message}`);
      setLaunching(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-black text-white">Configure Security Assessment</h1>
        <p className="text-xs text-muted-foreground mt-1">
          Define assessment profile, select authorized targets, enforce scope boundaries, and confirm assessment authority.
        </p>
      </div>

      <form onSubmit={handleLaunchAssessment} className="space-y-6">
        {/* Step 1: Basic Info */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-6 shadow-lg space-y-4">
          <div className="flex items-center gap-2 border-b border-border/40 pb-3">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-blue-600 text-xs font-bold text-white">
              1
            </span>
            <h2 className="text-sm font-bold text-white">Assessment Parameters</h2>
          </div>

          <div>
            <label className="text-xs font-semibold text-slate-200">Assessment Name *</label>
            <input
              type="text"
              required
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
              className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-xs text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
            />
          </div>
        </div>

        {/* Step 2: Assessment Profile Selector */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-6 shadow-lg space-y-4">
          <div className="flex items-center gap-2 border-b border-border/40 pb-3">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-blue-600 text-xs font-bold text-white">
              2
            </span>
            <h2 className="text-sm font-bold text-white">Select Assessment Profile</h2>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {profiles.map((p) => (
              <div
                key={p.id}
                onClick={() => setSelectedProfile(p.id)}
                className={`cursor-pointer rounded-xl border p-4 transition ${
                  selectedProfile === p.id
                    ? 'border-blue-500 bg-blue-600/10 ring-1 ring-blue-500'
                    : 'border-border/60 bg-[#0b0f19] hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">{p.name}</span>
                  <span className="rounded bg-blue-500/20 px-2 py-0.5 text-[9px] font-bold text-blue-400">
                    {p.badge}
                  </span>
                </div>
                <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">{p.desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Step 3: Target Scope Selection */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-6 shadow-lg space-y-4">
          <div className="flex items-center justify-between border-b border-border/40 pb-3">
            <div className="flex items-center gap-2">
              <span className="flex h-6 w-6 items-center justify-center rounded-full bg-blue-600 text-xs font-bold text-white">
                3
              </span>
              <h2 className="text-sm font-bold text-white">Target Scope Selection</h2>
            </div>
            <button
              type="button"
              onClick={handleValidateScope}
              disabled={validating || selectedTargets.length === 0}
              className="rounded-lg border border-blue-500/40 bg-blue-950/30 px-3 py-1 text-xs font-semibold text-blue-300 transition hover:bg-blue-900/40 disabled:opacity-40"
            >
              {validating ? 'Validating...' : 'Simulate Scope Check'}
            </button>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-200">
              Select Authorized Targets ({selectedTargets.length} selected):
            </label>
            <div className="max-h-48 overflow-y-auto divide-y divide-border/30 rounded-lg border border-border bg-[#0b0f19] p-2">
              {assets.length === 0 ? (
                <div className="p-3 text-xs text-muted-foreground">
                  No registered assets found for this project. You can type a custom target below.
                </div>
              ) : (
                assets.map((a) => (
                  <label
                    key={a.id}
                    className="flex items-center gap-3 p-2 hover:bg-slate-800/30 cursor-pointer rounded text-xs"
                  >
                    <input
                      type="checkbox"
                      checked={selectedTargets.includes(a.target)}
                      onChange={() => toggleTarget(a.target)}
                      className="rounded border-border bg-slate-900 text-blue-600 focus:ring-blue-500"
                    />
                    <div className="flex-1">
                      <span className="font-semibold text-white">{a.target}</span>
                      <span className="ml-2 rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-muted-foreground">
                        {a.asset_type}
                      </span>
                    </div>
                  </label>
                ))
              )}
            </div>

            {/* Add manual target */}
            <div className="flex gap-2 pt-2">
              <input
                type="text"
                placeholder="Or add target: https://example.com"
                value={customTarget}
                onChange={(e) => setCustomTarget(e.target.value)}
                className="flex-1 rounded-lg border border-border bg-[#0b0f19] px-3 py-1.5 text-xs text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={handleAddCustomTarget}
                className="rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-700"
              >
                Add Target
              </button>
            </div>
          </div>

          {/* Scope Validation Results */}
          {scopeValidations.length > 0 && (
            <div className="rounded-lg border border-border/50 bg-[#0b0f19] p-3 text-xs space-y-1.5">
              <span className="font-semibold text-slate-300">Scope Pre-Flight Validation:</span>
              {scopeValidations.map((res, idx) => (
                <div key={idx} className="flex items-center justify-between text-[11px]">
                  <span className="font-mono text-slate-300">{res.target}</span>
                  {res.in_scope ? (
                    <span className="flex items-center gap-1 text-emerald-400 font-bold">
                      <CheckCircle2 className="h-3 w-3" />
                      <span>Authorized ({res.resolved_ips.join(', ')})</span>
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-rose-400 font-bold">
                      <AlertCircle className="h-3 w-3" />
                      <span>{res.message}</span>
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Step 4: Authorization Confirmation Gate */}
        <div className="rounded-xl border border-amber-500/40 bg-amber-950/10 p-6 shadow-lg space-y-4">
          <div className="flex items-center gap-2 border-b border-amber-500/30 pb-3">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-amber-600 text-xs font-bold text-white">
              4
            </span>
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-400" />
              <h2 className="text-sm font-bold text-white">Mandatory Authorization Gate</h2>
            </div>
          </div>

          <div className="text-xs leading-relaxed text-amber-200/90 bg-amber-950/20 p-3 rounded-lg border border-amber-500/20">
            <strong>CRITICAL LEGAL BOUNDARY:</strong> VulnForge enforces non-destructive, authorized security testing only.
            By proceeding, you attest under penalty of law that your organization owns or has explicit written authorization
            to conduct security assessment activities against all scoped targets.
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-slate-200">Authorized Lead / Assessor Name *</label>
              <input
                type="text"
                required
                value={authorizedBy}
                onChange={(e) => setAuthorizedBy(e.target.value)}
                className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-xs text-white focus:border-blue-500 focus:outline-none"
              />
            </div>
          </div>

          <label className="flex items-start gap-3 pt-2 cursor-pointer">
            <input
              type="checkbox"
              required
              checked={authConfirmed}
              onChange={(e) => setAuthConfirmed(e.target.checked)}
              className="mt-0.5 rounded border-border bg-slate-900 text-blue-600 focus:ring-blue-500"
            />
            <span className="text-xs font-medium text-slate-200 leading-snug">
              I certify authorization, scope allowlist compliance, and approve the start of this security assessment run.
            </span>
          </label>
        </div>

        {/* Launch Button */}
        <div className="flex justify-end gap-4 pt-2">
          <button
            type="button"
            onClick={() => router.push('/assessments')}
            className="rounded-lg border border-border px-5 py-2.5 text-xs font-medium text-slate-300 hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={launching || !authConfirmed || selectedTargets.length === 0}
            className="flex items-center gap-2 rounded-lg bg-blue-600 px-6 py-2.5 text-xs font-bold text-white shadow-lg shadow-blue-600/30 transition hover:bg-blue-500 disabled:opacity-40"
          >
            <Play className="h-4 w-4 fill-white" />
            <span>{launching ? 'Initializing Assessment...' : 'Start Authorized VAPT Assessment'}</span>
          </button>
        </div>
      </form>
    </div>
  );
}
