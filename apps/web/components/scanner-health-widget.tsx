'use client';

import React, { useEffect, useState } from 'react';
import { CheckCircle2, AlertCircle, RefreshCw, Cpu } from 'lucide-react';
import { api } from '@/lib/api';

export function ScannerHealthWidget() {
  const [scanners, setScanners] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchHealth = async () => {
    try {
      setLoading(true);
      const data = await api.getScannerHealth();
      setScanners(data);
    } catch (err) {
      console.error('Failed fetching scanner health', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  return (
    <div className="rounded-xl border border-border/60 bg-[#111827] p-5 shadow-lg">
      <div className="flex items-center justify-between border-b border-border/40 pb-3">
        <div className="flex items-center gap-2">
          <Cpu className="h-4 w-4 text-blue-400" />
          <h3 className="text-sm font-bold text-white">Scanner Engine Subsystems</h3>
        </div>
        <button
          onClick={fetchHealth}
          className="rounded p-1 text-muted-foreground hover:bg-slate-800 hover:text-white"
          title="Refresh Diagnostics"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <div className="mt-3 divide-y divide-border/30">
        {scanners.map((s, idx) => (
          <div key={idx} className="flex items-start justify-between py-2.5 text-xs">
            <div>
              <div className="font-semibold text-slate-200">{s.name}</div>
              <div className="mt-0.5 text-[11px] text-muted-foreground">{s.details}</div>
            </div>
            <div className="ml-4 flex items-center gap-1.5 shrink-0">
              {s.available ? (
                <span className="flex items-center gap-1 rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-bold text-emerald-400 border border-emerald-500/30">
                  <CheckCircle2 className="h-3 w-3" />
                  <span>Available</span>
                </span>
              ) : (
                <span className="flex items-center gap-1 rounded-full bg-slate-800 px-2 py-0.5 text-[10px] font-medium text-slate-400 border border-slate-700">
                  <AlertCircle className="h-3 w-3" />
                  <span>Standby</span>
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
