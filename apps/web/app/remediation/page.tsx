'use client';

import React, { useEffect, useState } from 'react';
import {
  CheckCircle2,
  Clock,
  AlertCircle,
  Plus,
  ArrowRight,
  ShieldCheck,
  Calendar,
  User,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';

export default function RemediationPage() {
  const { currentProject, user } = useAuth();
  const [tasks, setTasks] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedFindingId, setSelectedFindingId] = useState('');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState('High');
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    if (!currentProject) return;
    try {
      const [tData, fData] = await Promise.all([
        api.getRemediationTasks(currentProject.id),
        api.getFindings(currentProject.id),
      ]);
      setTasks(tData);
      setFindings(fData);
      if (fData.length > 0) setSelectedFindingId(fData[0].id);
    } catch (err) {
      console.error('Error loading remediation data', err);
    }
  };

  useEffect(() => {
    loadData();
  }, [currentProject]);

  const handleCreateTask = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFindingId || !title.trim()) return;
    setLoading(true);
    try {
      await api.createRemediationTask({
        finding_id: selectedFindingId,
        title,
        description: description || undefined,
        priority,
        assignee_id: user?.id,
      });
      await loadData();
      setIsModalOpen(false);
      setTitle('');
      setDescription('');
    } catch (err: any) {
      alert(`Error creating task: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateStatus = async (taskId: string, newStatus: string) => {
    try {
      await api.updateRemediationStatus(taskId, newStatus);
      await loadData();
    } catch (err: any) {
      alert(`Error updating task status: ${err.message}`);
    }
  };

  const openTasks = tasks.filter((t) => t.status === 'OPEN');
  const inProgressTasks = tasks.filter((t) => t.status === 'IN_PROGRESS');
  const resolvedTasks = tasks.filter((t) => t.status === 'RESOLVED' || t.status === 'VERIFIED');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Remediation Tracking Board</h1>
          <p className="text-xs text-muted-foreground mt-1">
            Assign, track, and verify remediation progress for{' '}
            <span className="font-semibold text-slate-200">{currentProject?.name}</span>
          </p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-blue-600/30 transition hover:bg-blue-500"
        >
          <Plus className="h-4 w-4" />
          <span>New Remediation Task</span>
        </button>
      </div>

      {/* Kanban Columns */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        {/* OPEN COLUMN */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-4 shadow-lg space-y-3">
          <div className="flex items-center justify-between border-b border-border/40 pb-2.5">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-red-500" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                Open ({openTasks.length})
              </h3>
            </div>
            <span className="text-[11px] text-muted-foreground">Action Required</span>
          </div>

          <div className="space-y-3">
            {openTasks.length === 0 ? (
              <div className="py-8 text-center text-xs text-muted-foreground">No open remediation tasks.</div>
            ) : (
              openTasks.map((t) => (
                <div key={t.id} className="rounded-lg border border-border/50 bg-[#0b0f19] p-3 text-xs space-y-2 shadow">
                  <div className="flex items-start justify-between">
                    <span className="rounded bg-red-500/20 px-2 py-0.5 text-[10px] font-bold text-red-400 border border-red-500/30">
                      {t.priority}
                    </span>
                    <button
                      onClick={() => handleUpdateStatus(t.id, 'IN_PROGRESS')}
                      className="text-[11px] font-semibold text-blue-400 hover:underline"
                    >
                      Start &rarr;
                    </button>
                  </div>
                  <h4 className="font-bold text-white leading-snug">{t.title}</h4>
                  {t.description && <p className="text-[11px] text-muted-foreground">{t.description}</p>}
                </div>
              ))
            )}
          </div>
        </div>

        {/* IN PROGRESS COLUMN */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-4 shadow-lg space-y-3">
          <div className="flex items-center justify-between border-b border-border/40 pb-2.5">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-amber-500" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                In Progress ({inProgressTasks.length})
              </h3>
            </div>
            <span className="text-[11px] text-muted-foreground">Being Fixed</span>
          </div>

          <div className="space-y-3">
            {inProgressTasks.length === 0 ? (
              <div className="py-8 text-center text-xs text-muted-foreground">No active work items.</div>
            ) : (
              inProgressTasks.map((t) => (
                <div key={t.id} className="rounded-lg border border-border/50 bg-[#0b0f19] p-3 text-xs space-y-2 shadow">
                  <div className="flex items-start justify-between">
                    <span className="rounded bg-amber-500/20 px-2 py-0.5 text-[10px] font-bold text-amber-400 border border-amber-500/30">
                      {t.priority}
                    </span>
                    <button
                      onClick={() => handleUpdateStatus(t.id, 'RESOLVED')}
                      className="text-[11px] font-semibold text-emerald-400 hover:underline"
                    >
                      Resolve &rarr;
                    </button>
                  </div>
                  <h4 className="font-bold text-white leading-snug">{t.title}</h4>
                  {t.description && <p className="text-[11px] text-muted-foreground">{t.description}</p>}
                </div>
              ))
            )}
          </div>
        </div>

        {/* RESOLVED / VERIFIED COLUMN */}
        <div className="rounded-xl border border-border/60 bg-[#111827] p-4 shadow-lg space-y-3">
          <div className="flex items-center justify-between border-b border-border/40 pb-2.5">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                Resolved & Verified ({resolvedTasks.length})
              </h3>
            </div>
            <span className="text-[11px] text-muted-foreground">Closed</span>
          </div>

          <div className="space-y-3">
            {resolvedTasks.length === 0 ? (
              <div className="py-8 text-center text-xs text-muted-foreground">No completed tasks yet.</div>
            ) : (
              resolvedTasks.map((t) => (
                <div key={t.id} className="rounded-lg border border-emerald-500/30 bg-emerald-950/10 p-3 text-xs space-y-2 shadow">
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1 text-[10px] font-bold text-emerald-400">
                      <CheckCircle2 className="h-3 w-3" />
                      <span>{t.status}</span>
                    </span>
                  </div>
                  <h4 className="font-bold text-white leading-snug">{t.title}</h4>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Create Task Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-border bg-[#111827] p-6 shadow-2xl">
            <h2 className="text-lg font-bold text-white">Create Remediation Task</h2>
            <p className="text-xs text-muted-foreground mt-1">
              Assign a developer task linked to a specific discovered vulnerability.
            </p>

            <form onSubmit={handleCreateTask} className="mt-4 space-y-4 text-xs">
              <div>
                <label className="font-semibold text-slate-200">Linked Finding *</label>
                <select
                  value={selectedFindingId}
                  onChange={(e) => setSelectedFindingId(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  {findings.map((f) => (
                    <option key={f.id} value={f.id}>
                      [{f.severity}] {f.title}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="font-semibold text-slate-200">Task Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Implement HSTS header in Nginx"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="font-semibold text-slate-200">Priority</label>
                <select
                  value={priority}
                  onChange={(e) => setPriority(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div>
                <label className="font-semibold text-slate-200">Description / Action Items</label>
                <textarea
                  rows={3}
                  placeholder="Specific developer guidance, files to touch, or PR requirements..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
                />
              </div>

              <div className="mt-6 flex justify-end gap-3 pt-3 border-t border-border/40">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="rounded-lg border border-border px-4 py-2 font-medium text-slate-300 hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
                >
                  {loading ? 'Creating...' : 'Create Task'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
