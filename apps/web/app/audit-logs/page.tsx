'use client';

import React, { useEffect, useState } from 'react';
import {
  ScrollText,
  Shield,
  Clock,
  User,
  Activity,
  CheckCircle2,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';

export default function AuditLogsPage() {
  const { currentOrg } = useAuth();
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const loadAuditLogs = async () => {
    if (!currentOrg) return;
    setLoading(true);
    try {
      const data = await api.getAuditLogs(currentOrg.id);
      setLogs(data);
    } catch (err) {
      console.error('Error loading audit logs', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAuditLogs();
  }, [currentOrg]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-black text-white">Immutable Audit Ledger</h1>
        <p className="text-xs text-muted-foreground mt-1">
          Cryptographically hashed and append-only activity trail for{' '}
          <span className="font-semibold text-slate-200">{currentOrg?.name}</span>
        </p>
      </div>

      {/* Logs Table */}
      <div className="rounded-xl border border-border/60 bg-[#111827] shadow-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border/60 bg-[#0b0f19] text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-5 py-3.5">Action Event</th>
                <th className="px-5 py-3.5">Actor / User</th>
                <th className="px-5 py-3.5">Target Resource</th>
                <th className="px-5 py-3.5">Event Details</th>
                <th className="px-5 py-3.5">Timestamp (UTC)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30">
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-muted-foreground">
                    No audit records registered for this workspace yet.
                  </td>
                </tr>
              ) : (
                logs.map((l) => (
                  <tr key={l.id} className="hover:bg-slate-800/30 transition">
                    <td className="px-5 py-4">
                      <span className="rounded bg-blue-950/40 px-2 py-0.5 font-mono text-[10px] font-bold text-blue-300 border border-blue-500/20">
                        {l.action}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <div className="font-semibold text-white">{l.user_email || 'SYSTEM'}</div>
                    </td>
                    <td className="px-5 py-4 font-mono text-slate-300 text-[11px]">
                      {l.target_resource || 'Organization'}
                    </td>
                    <td className="px-5 py-4 font-mono text-[11px] text-slate-400 max-w-xs truncate">
                      {JSON.stringify(l.details)}
                    </td>
                    <td className="px-5 py-4 text-slate-400 text-[11px]">
                      {new Date(l.timestamp).toLocaleString()}
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
