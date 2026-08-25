'use client';

import React, { useEffect, useState } from 'react';
import {
  Server,
  Plus,
  Trash2,
  Globe,
  Link as LinkIcon,
  ShieldCheck,
  Cpu,
  Search,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';

export default function AssetsPage() {
  const { currentProject } = useAuth();
  const [assets, setAssets] = useState<any[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [target, setTarget] = useState('');
  const [assetType, setAssetType] = useState('URL');
  const [criticality, setCriticality] = useState('High');
  const [description, setDescription] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);

  const loadAssets = async () => {
    if (!currentProject) return;
    try {
      const data = await api.getAssets(currentProject.id);
      setAssets(data);
    } catch (err) {
      console.error('Failed loading assets', err);
    }
  };

  useEffect(() => {
    loadAssets();
  }, [currentProject]);

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentProject || !target.trim()) return;
    setLoading(true);
    try {
      await api.createAsset(currentProject.id, {
        target,
        asset_type: assetType,
        criticality,
        environment: currentProject.environment,
        description: description || undefined,
        tags: ['Authorized', criticality],
      });
      await loadAssets();
      setIsModalOpen(false);
      setTarget('');
      setDescription('');
    } catch (err: any) {
      alert(`Error adding asset: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteAsset = async (id: string) => {
    if (!confirm('Are you sure you want to remove this asset from scope?')) return;
    try {
      await api.deleteAsset(id);
      await loadAssets();
    } catch (err: any) {
      alert(`Error deleting asset: ${err.message}`);
    }
  };

  const filteredAssets = assets.filter(
    (a) =>
      a.target.toLowerCase().includes(search.toLowerCase()) ||
      a.asset_type.toLowerCase().includes(search.toLowerCase()) ||
      (a.service && a.service.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Authorized Asset Inventory</h1>
          <p className="text-xs text-muted-foreground mt-1">
            Registered endpoints and domains in scope for{' '}
            <span className="font-semibold text-slate-200">{currentProject?.name}</span>
          </p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-blue-600/30 transition hover:bg-blue-500"
        >
          <Plus className="h-4 w-4" />
          <span>Add Asset to Scope</span>
        </button>
      </div>

      {/* Filter / Search Bar */}
      <div className="flex items-center gap-3 rounded-xl border border-border/60 bg-[#111827] px-4 py-2.5">
        <Search className="h-4 w-4 text-muted-foreground" />
        <input
          type="text"
          placeholder="Filter assets by target URL, hostname, service, or type..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-transparent text-xs text-white placeholder-muted-foreground focus:outline-none"
        />
        <span className="text-[11px] text-muted-foreground shrink-0">{filteredAssets.length} asset(s)</span>
      </div>

      {/* Assets Table */}
      <div className="rounded-xl border border-border/60 bg-[#111827] shadow-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border/60 bg-[#0b0f19] text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-5 py-3.5">Target & Endpoint</th>
                <th className="px-5 py-3.5">Asset Type</th>
                <th className="px-5 py-3.5">Criticality</th>
                <th className="px-5 py-3.5">Discovered Tech / Service</th>
                <th className="px-5 py-3.5">Scope Status</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30">
              {filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted-foreground">
                    No assets in scope. Click "Add Asset to Scope" to register authorized targets.
                  </td>
                </tr>
              ) : (
                filteredAssets.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-800/30 transition">
                    <td className="px-5 py-4">
                      <div className="font-semibold text-white">{a.target}</div>
                      <div className="text-[11px] text-muted-foreground font-mono mt-0.5">
                        {a.hostname} {a.port ? `:${a.port}` : ''}
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-mono text-slate-300">
                        {a.asset_type}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${
                          a.criticality === 'Critical'
                            ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                            : a.criticality === 'High'
                            ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                            : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                        }`}
                      >
                        {a.criticality}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <div className="text-slate-300">{a.service || 'Probed during assessment'}</div>
                      {a.technologies && a.technologies.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {a.technologies.slice(0, 3).map((t: string, idx: number) => (
                            <span key={idx} className="rounded bg-blue-950/40 px-1.5 py-0.2 text-[9px] text-blue-300 border border-blue-500/20">
                              {t}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-5 py-4">
                      <span className="flex items-center gap-1 text-[11px] font-medium text-emerald-400">
                        <ShieldCheck className="h-3.5 w-3.5" />
                        <span>In Scope</span>
                      </span>
                    </td>
                    <td className="px-5 py-4 text-right">
                      <button
                        onClick={() => handleDeleteAsset(a.id)}
                        className="rounded p-1 text-muted-foreground hover:bg-slate-800 hover:text-rose-400 transition"
                        title="Remove Asset"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Asset Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-border bg-[#111827] p-6 shadow-2xl">
            <h2 className="text-lg font-bold text-white">Add Scoped Asset</h2>
            <p className="text-xs text-muted-foreground mt-1">
              Add an authorized target URL, domain, IP, or API endpoint to your scope allowlist.
            </p>

            <form onSubmit={handleCreateAsset} className="mt-4 space-y-4 text-xs">
              <div>
                <label className="font-semibold text-slate-200">Target URL / Host *</label>
                <input
                  type="text"
                  required
                  placeholder="https://api.example.com or 192.0.2.10"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="font-semibold text-slate-200">Asset Type</label>
                  <select
                    value={assetType}
                    onChange={(e) => setAssetType(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                  >
                    <option value="URL">URL</option>
                    <option value="API_ENDPOINT">API Endpoint</option>
                    <option value="DOMAIN">Domain</option>
                    <option value="IP">IP Address</option>
                    <option value="CIDR">CIDR Range</option>
                  </select>
                </div>
                <div>
                  <label className="font-semibold text-slate-200">Asset Criticality</label>
                  <select
                    value={criticality}
                    onChange={(e) => setCriticality(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-border bg-[#0b0f19] px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                  >
                    <option value="Critical">Critical (Tier 1)</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="font-semibold text-slate-200">Asset Description / Context</label>
                <input
                  type="text"
                  placeholder="e.g. Primary transaction submission API"
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
                  {loading ? 'Adding...' : 'Add to Scope'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
