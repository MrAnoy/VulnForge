'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Shield,
  LayoutDashboard,
  FolderKanban,
  Server,
  Crosshair,
  AlertTriangle,
  CheckCircle2,
  FileText,
  Bot,
  ScrollText,
  Settings,
  Activity,
  ChevronRight,
  ExternalLink,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Projects', href: '/projects', icon: FolderKanban },
  { name: 'Assets', href: '/assets', icon: Server },
  { name: 'Assessments', href: '/assessments', icon: Crosshair },
  { name: 'Findings', href: '/findings', icon: AlertTriangle },
  { name: 'Remediation', href: '/remediation', icon: CheckCircle2 },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Security Copilot', href: '/copilot', icon: Bot },
  { name: 'Audit Logs', href: '/audit-logs', icon: ScrollText },
  { name: 'Settings & API Keys', href: '/settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { currentProject, projects, setCurrentProject } = useAuth();

  return (
    <div className="flex h-screen w-64 flex-col border-r border-border/50 bg-[#0b0f19] text-foreground">
      {/* Brand Header */}
      <div className="flex h-16 items-center gap-3 border-b border-border/40 px-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600/20 text-blue-400 ring-1 ring-blue-500/30">
          <Shield className="h-5 w-5" />
        </div>
        <div>
          <span className="text-base font-bold tracking-tight text-white">VulnForge</span>
          <span className="ml-1.5 rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-blue-400 ring-1 ring-blue-500/20">
            PRO
          </span>
        </div>
      </div>

      {/* Active Project Selector */}
      <div className="border-b border-border/40 p-3">
        <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          Active Security Project
        </label>
        <select
          value={currentProject?.id || ''}
          onChange={(e) => {
            const found = projects.find((p) => p.id === e.target.value);
            if (found) setCurrentProject(found);
          }}
          className="mt-1.5 w-full rounded-md border border-border bg-[#111827] px-2.5 py-1.5 text-xs font-medium text-white focus:border-blue-500 focus:outline-none"
        >
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} ({p.environment})
            </option>
          ))}
        </select>
      </div>

      {/* Nav links */}
      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-3">
        {navigation.map((item) => {
          const isActive = pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href));
          return (
            <Link
              key={item.name}
              href={item.href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                isActive
                  ? 'bg-blue-600/15 text-blue-400 font-semibold ring-1 ring-blue-500/30'
                  : 'text-muted-foreground hover:bg-slate-800/40 hover:text-white'
              }`}
            >
              <item.icon className={`h-4 w-4 ${isActive ? 'text-blue-400' : 'text-muted-foreground'}`} />
              <span>{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* Footer / System Status */}
      <div className="border-t border-border/40 p-3">
        <Link
          href="/settings"
          className="flex items-center justify-between rounded-lg bg-emerald-950/20 px-3 py-2 text-xs font-medium text-emerald-400 ring-1 ring-emerald-500/30 hover:bg-emerald-950/30"
        >
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
            </span>
            <span>VAPT Engines Active</span>
          </div>
          <ChevronRight className="h-3.5 w-3.5 text-emerald-400" />
        </Link>
      </div>
    </div>
  );
}
