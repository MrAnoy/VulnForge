'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import {
  Search,
  Crosshair,
  Server,
  AlertTriangle,
  FileText,
  Bot,
  Settings,
  FolderPlus,
  ShieldCheck,
  X,
} from 'lucide-react';

interface CommandItem {
  title: string;
  category: string;
  icon: any;
  action: () => void;
}

export function CommandPalette({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const router = useRouter();
  const [query, setQuery] = useState('');

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        onClose(); // Toggle or open
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const commands: CommandItem[] = [
    {
      title: 'Start New Authorized Assessment',
      category: 'Actions',
      icon: Crosshair,
      action: () => {
        router.push('/assessments/new');
        onClose();
      },
    },
    {
      title: 'Add New Target Asset',
      category: 'Actions',
      icon: Server,
      action: () => {
        router.push('/assets');
        onClose();
      },
    },
    {
      title: 'View Critical Vulnerabilities',
      category: 'Navigation',
      icon: AlertTriangle,
      action: () => {
        router.push('/findings?severity=Critical');
        onClose();
      },
    },
    {
      title: 'Generate Executive Security Report',
      category: 'Actions',
      icon: FileText,
      action: () => {
        router.push('/reports');
        onClose();
      },
    },
    {
      title: 'Open Security Copilot Chat',
      category: 'AI Assistant',
      icon: Bot,
      action: () => {
        router.push('/copilot');
        onClose();
      },
    },
    {
      title: 'Scanner Capability Diagnostics',
      category: 'System',
      icon: ShieldCheck,
      action: () => {
        router.push('/settings');
        onClose();
      },
    },
    {
      title: 'Create Security Project',
      category: 'Actions',
      icon: FolderPlus,
      action: () => {
        router.push('/projects');
        onClose();
      },
    },
  ];

  const filtered = commands.filter((c) =>
    c.title.toLowerCase().includes(query.toLowerCase()) ||
    c.category.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-24 backdrop-blur-sm">
      <div className="w-full max-w-xl rounded-xl border border-border/80 bg-[#111827] shadow-2xl overflow-hidden">
        {/* Search header */}
        <div className="flex items-center border-b border-border/60 px-4 py-3">
          <Search className="h-4 w-4 text-muted-foreground mr-3" />
          <input
            autoFocus
            type="text"
            placeholder="Type a command or search..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent text-sm text-white placeholder-muted-foreground focus:outline-none"
          />
          <button onClick={onClose} className="rounded p-1 text-muted-foreground hover:bg-slate-800 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Results */}
        <div className="max-h-80 overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-xs text-muted-foreground">
              No matching commands or destinations found.
            </div>
          ) : (
            filtered.map((item, idx) => (
              <button
                key={idx}
                onClick={item.action}
                className="flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-left text-xs transition hover:bg-blue-600/15 hover:text-blue-400 group"
              >
                <div className="flex items-center gap-3">
                  <item.icon className="h-4 w-4 text-muted-foreground group-hover:text-blue-400" />
                  <span className="font-medium text-slate-200 group-hover:text-white">{item.title}</span>
                </div>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-muted-foreground">
                  {item.category}
                </span>
              </button>
            ))
          )}
        </div>

        {/* Footer info */}
        <div className="border-t border-border/40 bg-[#0b0f19] px-4 py-2 text-[11px] text-muted-foreground flex justify-between">
          <span>Navigate with mouse or keyboard</span>
          <span>Press ESC to exit</span>
        </div>
      </div>
    </div>
  );
}
