'use client';

import React, { useEffect, useState } from 'react';
import {
  Settings,
  Key,
  Webhook as WebhookIcon,
  ShieldCheck,
  Plus,
  Trash2,
  Copy,
  Check,
  Send,
  Users,
  Activity,
  Calendar,
  Clock,
  Radio,
  Cpu,
  Database,
  Layers,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';
import { ScannerHealthWidget } from '@/components/scanner-health-widget';

export default function SettingsPage() {
  const { currentOrg, currentProject, user } = useAuth();
  const [apiKeys, setApiKeys] = useState<any[]>([]);
  const [webhooks, setWebhooks] = useState<any[]>([]);
  const [members, setMembers] = useState<any[]>([]);
  const [schedules, setSchedules] = useState<any[]>([]);
  const [systemHealth, setSystemHealth] = useState<any>(null);
  
  // API Key creation
  const [keyName, setKeyName] = useState('');
  const [createdRawKey, setCreatedRawKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [creatingKey, setCreatingKey] = useState(false);

  // Webhook creation
  const [webhookUrl, setWebhookUrl] = useState('');
  const [creatingWebhook, setCreatingWebhook] = useState(false);

  // Schedule creation
  const [schedName, setSchedName] = useState('');
  const [schedFreq, setSchedFreq] = useState('WEEKLY');
  const [schedProfile, setSchedProfile] = useState('STANDARD_VAPT');
  const [creatingSched, setCreatingSched] = useState(false);

  const loadSettingsData = async () => {
    if (!currentOrg) return;
    try {
      const [keys, hooks, mems] = await Promise.all([
        api.getApiKeys(currentOrg.id),
        api.getWebhooks(currentOrg.id),
        api.getOrgMembers(currentOrg.id),
      ]);
      setApiKeys(keys);
      setWebhooks(hooks);
      setMembers(mems);

      if (currentProject) {
        try {
          const schedData = await api.getSchedules(currentProject.id);
          setSchedules(schedData);
        } catch (e) {
          console.warn('Schedules fetch', e);
        }
      }

      try {
        const healthData = await api.getDetailedHealth();
        setSystemHealth(healthData);
      } catch (e) {
        console.warn('Health fetch', e);
      }
    } catch (err) {
      console.error('Error loading settings', err);
    }
  };

  useEffect(() => {
    loadSettingsData();
  }, [currentOrg, currentProject]);

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentOrg || !keyName.trim()) return;
    setCreatingKey(true);
    try {
      const res = await api.createApiKey(currentOrg.id, {
        name: keyName,
        role: 'SECURITY_ANALYST',
      });
      setCreatedRawKey(res.raw_key);
      setKeyName('');
      await loadSettingsData();
    } catch (err: any) {
      alert(`Error generating API key: ${err.message}`);
    } finally {
      setCreatingKey(false);
    }
  };

  const handleDeleteApiKey = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this API key?')) return;
    try {
      await api.deleteApiKey(id);
      await loadSettingsData();
    } catch (err: any) {
      alert(`Error revoking API key: ${err.message}`);
    }
  };

  const handleCreateWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentOrg || !webhookUrl.trim()) return;
    setCreatingWebhook(true);
    try {
      await api.createWebhook(currentOrg.id, {
        url: webhookUrl,
        events: ['assessment.completed', 'finding.created'],
      });
      setWebhookUrl('');
      await loadSettingsData();
    } catch (err: any) {
      alert(`Error registering webhook: ${err.message}`);
    } finally {
      setCreatingWebhook(false);
    }
  };

  const handleCreateSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentProject || !schedName.trim()) return;
    setCreatingSched(true);
    try {
      await api.createSchedule(currentProject.id, {
        project_id: currentProject.id,
        name: schedName,
        profile: schedProfile,
        frequency: schedFreq,
        targets: [],
        is_active: true,
      });
      setSchedName('');
      await loadSettingsData();
    } catch (err: any) {
      alert(`Error creating schedule: ${err.message}`);
    } finally {
      setCreatingSched(false);
    }
  };

  const handleDeleteSchedule = async (id: string) => {
    if (!confirm('Delete this automated scan schedule?')) return;
    try {
      await api.deleteSchedule(id);
      await loadSettingsData();
    } catch (err: any) {
      alert(`Error deleting schedule: ${err.message}`);
    }
  };

  const handleCopyKey = () => {
    if (createdRawKey) {
      navigator.clipboard.writeText(createdRawKey);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 3000);
    }
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-black text-white">Platform Settings, Observability & Automation</h1>
        <p className="text-xs text-muted-foreground mt-1">
          Manage workspace settings, automated audit schedules, subsystem observability, API keys, and scanner engines for{' '}
          <span className="font-semibold text-slate-200">{currentOrg?.name}</span>
        </p>
      </div>

      {/* Grid of Sections */}
      <div className="space-y-6">
        {/* Subsystem Observability & Diagnostic Matrix */}
        {systemHealth && (
          <div className="rounded-xl border border-border/60 bg-[#111827] p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-border/40 pb-3">
              <div className="flex items-center gap-2">
                <Radio className="h-5 w-5 text-emerald-400 animate-pulse" />
                <h2 className="text-sm font-bold text-white">Platform Observability & Engine Health</h2>
              </div>
              <span className="rounded-full bg-emerald-500/20 px-2.5 py-0.5 text-[10px] font-bold text-emerald-400 uppercase">
                Status: {systemHealth.status}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {systemHealth.subsystems?.map((sub: any, idx: number) => (
                <div key={idx} className="rounded-lg border border-border/60 bg-[#090d16] p-3 text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{sub.name}</span>
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                        sub.status === 'HEALTHY'
                          ? 'bg-emerald-500/20 text-emerald-400'
                          : 'bg-amber-500/20 text-amber-400'
                      }`}
                    >
                      {sub.status}
                    </span>
                  </div>
                  <p className="text-[11px] text-muted-foreground">{sub.details}</p>
                  <div className="text-[10px] text-slate-400 font-mono">
                    Latency: {sub.latency_ms}ms &bull; {sub.version || 'v1.0'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Scheduled Assessments */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between border-b border-border/40 pb-3">
            <div className="flex items-center gap-2">
              <Calendar className="h-5 w-5 text-blue-400" />
              <h2 className="text-sm font-bold text-white">Scheduled Security Assessments</h2>
            </div>
            <span className="text-[11px] text-muted-foreground">Automated continuous perimeter audits</span>
          </div>

          <form onSubmit={handleCreateSchedule} className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs">
            <input
              type="text"
              required
              placeholder="Schedule Name (e.g. Weekly Production Audit)"
              value={schedName}
              onChange={(e) => setSchedName(e.target.value)}
              className="sm:col-span-2 rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
            />
            <select
              value={schedFreq}
              onChange={(e) => setSchedFreq(e.target.value)}
              className="rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white"
            >
              <option value="DAILY">Daily Scan</option>
              <option value="WEEKLY">Weekly Scan</option>
              <option value="MONTHLY">Monthly Scan</option>
            </select>
            <button
              type="submit"
              disabled={creatingSched || !schedName.trim()}
              className="rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white hover:bg-blue-500 disabled:opacity-40"
            >
              {creatingSched ? 'Scheduling...' : 'Create Schedule'}
            </button>
          </form>

          <div className="divide-y divide-border/30 rounded-lg border border-border/40 bg-[#0b0f19] text-xs">
            {schedules.length === 0 ? (
              <div className="p-4 text-center text-muted-foreground">No recurring schedules configured.</div>
            ) : (
              schedules.map((s) => (
                <div key={s.id} className="flex items-center justify-between p-3">
                  <div>
                    <div className="font-semibold text-white">{s.name}</div>
                    <div className="text-[11px] text-muted-foreground mt-0.5">
                      Frequency: {s.frequency} &bull; Next Run: {s.next_run_at ? new Date(s.next_run_at).toLocaleDateString() : 'Pending'}
                    </div>
                  </div>
                  <button
                    onClick={() => handleDeleteSchedule(s.id)}
                    className="rounded p-1 text-muted-foreground hover:bg-slate-800 hover:text-rose-400 transition"
                    title="Delete Schedule"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ))
            )}
          </div>
        </div>

        {/* API Keys Management */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between border-b border-border/40 pb-3">
            <div className="flex items-center gap-2">
              <Key className="h-5 w-5 text-blue-400" />
              <h2 className="text-sm font-bold text-white">Programmatic API Keys</h2>
            </div>
            <span className="text-[11px] text-muted-foreground">For CI/CD and automated pipelines</span>
          </div>

          {/* New key revealed alert */}
          {createdRawKey && (
            <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/20 p-4 text-xs space-y-2">
              <div className="font-bold text-emerald-400">API Key Created Successfully:</div>
              <div className="flex items-center gap-2">
                <code className="flex-1 rounded bg-[#050811] p-2 font-mono text-xs text-emerald-300 select-all border border-emerald-500/20">
                  {createdRawKey}
                </code>
                <button
                  onClick={handleCopyKey}
                  className="flex items-center gap-1 rounded bg-emerald-600 px-3 py-2 font-semibold text-white hover:bg-emerald-500"
                >
                  {copiedKey ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                  <span>{copiedKey ? 'Copied!' : 'Copy Key'}</span>
                </button>
              </div>
              <p className="text-[11px] text-muted-foreground">
                Copy this key now. For security reasons, it will not be displayed again.
              </p>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleCreateApiKey} className="flex gap-3 text-xs">
            <input
              type="text"
              required
              placeholder="API Key Name (e.g. GitHub Actions CI/CD Pipeline)"
              value={keyName}
              onChange={(e) => setKeyName(e.target.value)}
              className="flex-1 rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
            />
            <button
              type="submit"
              disabled={creatingKey || !keyName.trim()}
              className="rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white hover:bg-blue-500 disabled:opacity-40"
            >
              {creatingKey ? 'Generating...' : 'Create API Key'}
            </button>
          </form>

          {/* Keys list */}
          <div className="divide-y divide-border/30 rounded-lg border border-border/40 bg-[#0b0f19] text-xs">
            {apiKeys.length === 0 ? (
              <div className="p-4 text-center text-muted-foreground">No active API keys created.</div>
            ) : (
              apiKeys.map((k) => (
                <div key={k.id} className="flex items-center justify-between p-3">
                  <div>
                    <div className="font-semibold text-white">{k.name}</div>
                    <div className="font-mono text-[11px] text-muted-foreground mt-0.5">
                      Key: {k.key_preview} &bull; Role: {k.role} &bull; Created: {new Date(k.created_at).toLocaleDateString()}
                    </div>
                  </div>
                  <button
                    onClick={() => handleDeleteApiKey(k.id)}
                    className="rounded p-1 text-muted-foreground hover:bg-slate-800 hover:text-rose-400 transition"
                    title="Revoke Key"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Webhooks Management */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between border-b border-border/40 pb-3">
            <div className="flex items-center gap-2">
              <WebhookIcon className="h-5 w-5 text-indigo-400" />
              <h2 className="text-sm font-bold text-white">Event Webhooks</h2>
            </div>
            <span className="text-[11px] text-muted-foreground">Receive assessment alerts & notifications</span>
          </div>

          <form onSubmit={handleCreateWebhook} className="flex gap-3 text-xs">
            <input
              type="url"
              required
              placeholder="https://api.yourcompany.com/vulnforge-webhook"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              className="flex-1 rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
            />
            <button
              type="submit"
              disabled={creatingWebhook || !webhookUrl.trim()}
              className="rounded-lg bg-indigo-600 px-4 py-2 font-semibold text-white hover:bg-indigo-500 disabled:opacity-40"
            >
              {creatingWebhook ? 'Registering...' : 'Register Webhook'}
            </button>
          </form>

          <div className="divide-y divide-border/30 rounded-lg border border-border/40 bg-[#0b0f19] text-xs">
            {webhooks.length === 0 ? (
              <div className="p-4 text-center text-muted-foreground">No webhooks registered.</div>
            ) : (
              webhooks.map((w) => (
                <div key={w.id} className="flex items-center justify-between p-3">
                  <div>
                    <div className="font-mono text-white">{w.url}</div>
                    <div className="text-[11px] text-muted-foreground mt-0.5">
                      Events: {w.events?.join(', ')}
                    </div>
                  </div>
                  <span className="rounded bg-emerald-500/15 px-2 py-0.5 text-[10px] font-bold text-emerald-400 border border-emerald-500/30">
                    ACTIVE
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Team Members */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2 border-b border-border/40 pb-3">
            <Users className="h-5 w-5 text-emerald-400" />
            <h2 className="text-sm font-bold text-white">Organization Members & RBAC</h2>
          </div>

          <div className="divide-y divide-border/30 rounded-lg border border-border/40 bg-[#0b0f19] text-xs">
            {members.map((m) => (
              <div key={m.id} className="flex items-center justify-between p-3.5">
                <div>
                  <div className="font-bold text-white">{m.user_name}</div>
                  <div className="text-[11px] text-muted-foreground">{m.user_email}</div>
                </div>
                <span className="rounded bg-blue-500/15 px-2.5 py-0.5 text-[10px] font-bold text-blue-400 border border-blue-500/30 uppercase">
                  {m.role}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
