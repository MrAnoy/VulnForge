'use client';

import React, { useEffect, useState } from 'react';
import {
  FolderKanban,
  Plus,
  Server,
  AlertTriangle,
  ChevronRight,
  ShieldAlert,
  Trash2,
  Building2,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';

export default function ProjectsPage() {
  const { currentOrg, projects, refreshUserData, setCurrentProject } = useAuth();
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [name, setName] = useState('');
  const [clientName, setClientName] = useState('');
  const [description, setDescription] = useState('');
  const [environment, setEnvironment] = useState('Production');
  const [tags, setTags] = useState('Tier-1, Production, Web');
  const [loading, setLoading] = useState(false);

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentOrg || !name.trim()) return;
    setLoading(true);
    try {
      await api.createProject(currentOrg.id, {
        name,
        client_name: clientName || undefined,
        description: description || undefined,
        environment,
        tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
      });
      await refreshUserData();
      setIsModalOpen(false);
      setName('');
      setDescription('');
    } catch (err: any) {
      alert(`Error creating project: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteProject = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this security project? All associated assets and scan histories will be deleted.')) return;
    try {
      await api.deleteProject(id);
      await refreshUserData();
    } catch (err: any) {
      alert(`Error deleting project: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Security Projects</h1>
          <p className="text-xs text-muted-foreground mt-1">
            Manage assessment boundaries, target environments, and asset groups for{' '}
            <span className="font-semibold text-slate-200">{currentOrg?.name}</span>
          </p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-blue-600/30 transition hover:bg-blue-500"
        >
          <Plus className="h-4 w-4" />
          <span>New Security Project</span>
        </button>
      </div>

      {/* Projects Grid */}
      <div className="grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-3">
        {projects.map((p) => (
          <div
            key={p.id}
            onClick={() => setCurrentProject(p)}
            className="group relative cursor-pointer rounded-xl border border-border/60 bg-[#111827] p-5 shadow-lg transition hover:border-blue-500/50 hover:bg-[#131d31]"
          >
            <div className="flex items-start justify-between">
              <div>
                <span className="rounded bg-blue-500/10 px-2 py-0.5 text-[10px] font-semibold text-blue-400 border border-blue-500/20">
                  {p.environment}
                </span>
                <h3 className="mt-2 text-base font-bold text-white group-hover:text-blue-400 transition">
                  {p.name}
                </h3>
              </div>
              <button
                onClick={(e) => handleDeleteProject(p.id, e)}
                title="Delete Project"
                className="opacity-0 group-hover:opacity-100 p-1 text-muted-foreground hover:text-rose-400 transition"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-3 border-t border-border/30 pt-3 text-xs">
              <div>
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                  Security Score
                </div>
                <div className="text-lg font-extrabold text-blue-400">
                  {p.risk_score || 74.5} <span className="text-xs text-muted-foreground">/ 100</span>
                </div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                  Scope Context
                </div>
                <div className="text-xs font-semibold text-slate-300 mt-1">
                  {p.environment}
                </div>
              </div>
            </div>

            <div className="mt-4 flex items-center justify-between text-xs text-muted-foreground">
              <span>Select as Active Project</span>
              <ChevronRight className="h-4 w-4 group-hover:translate-x-1 transition text-blue-400" />
            </div>
          </div>
        ))}
      </div>

      {/* Create Project Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl border border-border bg-[#111827] p-6 shadow-2xl">
            <h2 className="text-lg font-bold text-white">Create Security Project</h2>
            <p className="text-xs text-muted-foreground mt-1">
              Define the scope, environment, and company for this assessment boundary.
            </p>

            <form onSubmit={handleCreateProject} className="mt-4 space-y-4 text-xs">
              <div>
                <label className="font-semibold text-slate-200">Project Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Core Banking Payment Gateway"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="font-semibold text-slate-200">Client / Company Name</label>
                <input
                  type="text"
                  placeholder="e.g. Acme Financial Services"
                  value={clientName}
                  onChange={(e) => setClientName(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="font-semibold text-slate-200">Target Environment</label>
                <select
                  value={environment}
                  onChange={(e) => setEnvironment(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="Production">Production</option>
                  <option value="Staging">Staging</option>
                  <option value="Development">Development</option>
                  <option value="Internal">Internal</option>
                  <option value="External">External</option>
                </select>
              </div>

              <div>
                <label className="font-semibold text-slate-200">Tags (comma separated)</label>
                <input
                  type="text"
                  placeholder="PCI-DSS, Production, Tier-1"
                  value={tags}
                  onChange={(e) => setTags(e.target.value)}
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
                  {loading ? 'Creating...' : 'Create Project'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
