'use client';

import React from 'react';
import Link from 'next/link';
import {
  Search,
  Bot,
  User,
  LogOut,
  Building2,
  Sparkles,
  Layers,
  GraduationCap,
  Shield,
  Briefcase,
  Code,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { useViewMode, ViewMode } from '@/lib/view-mode-context';

export function Navbar({
  onOpenCommandPalette,
  onOpenCopilot,
}: {
  onOpenCommandPalette?: () => void;
  onOpenCopilot?: () => void;
}) {
  const { user, logout, switchDemoUser, currentOrg } = useAuth();
  const { mode, setMode } = useViewMode();

  const modeIcons = {
    beginner: <GraduationCap className="h-3 w-3 text-emerald-400" />,
    professional: <Shield className="h-3 w-3 text-blue-400" />,
    executive: <Briefcase className="h-3 w-3 text-amber-400" />,
    developer: <Code className="h-3 w-3 text-purple-400" />,
  };

  return (
    <header className="flex h-16 items-center justify-between border-b border-border/40 bg-[#0b0f19]/80 px-6 backdrop-blur-md">
      {/* Search / Command palette trigger */}
      <div className="flex items-center gap-3">
        <button
          onClick={onOpenCommandPalette}
          className="flex items-center gap-2 rounded-lg border border-border/60 bg-[#111827] px-3 py-1.5 text-xs text-muted-foreground transition hover:border-blue-500/50 hover:text-white"
        >
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <span>Quick search or command...</span>
          <kbd className="ml-4 rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-mono text-slate-400">
            Ctrl+K
          </kbd>
        </button>

        {currentOrg && (
          <div className="hidden items-center gap-1.5 text-xs text-muted-foreground sm:flex">
            <Building2 className="h-3.5 w-3.5 text-slate-400" />
            <span className="font-medium text-slate-200">{currentOrg.name}</span>
          </div>
        )}
      </div>

      {/* Right actions: View Mode Selector, Demo switchers, Copilot, User */}
      <div className="flex items-center gap-3">
        {/* Experience / View Mode Switcher */}
        <div className="flex items-center rounded-lg border border-border/60 bg-[#111827] p-0.5 text-[11px]">
          <span className="hidden px-2 font-medium text-muted-foreground lg:inline">View Mode:</span>
          {(['beginner', 'professional', 'executive', 'developer'] as ViewMode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`flex items-center gap-1 rounded px-2 py-1 transition capitalize ${
                mode === m
                  ? 'bg-blue-600 font-semibold text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
              title={`Switch to ${m} mode view`}
            >
              {modeIcons[m]}
              <span className="hidden md:inline">{m}</span>
            </button>
          ))}
        </div>

        {/* Preset Role Switcher */}
        <div className="hidden items-center rounded-lg border border-border/60 bg-[#111827] p-0.5 text-[11px] xl:flex">
          <span className="px-2 font-medium text-muted-foreground">Demo:</span>
          <button
            onClick={() => switchDemoUser('admin')}
            className={`rounded px-2 py-1 transition ${
              user?.email.includes('admin') ? 'bg-slate-700 font-semibold text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Admin
          </button>
          <button
            onClick={() => switchDemoUser('analyst')}
            className={`rounded px-2 py-1 transition ${
              user?.email.includes('analyst') ? 'bg-slate-700 font-semibold text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Analyst
          </button>
          <button
            onClick={() => switchDemoUser('viewer')}
            className={`rounded px-2 py-1 transition ${
              user?.email.includes('viewer') ? 'bg-slate-700 font-semibold text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Viewer
          </button>
        </div>

        {/* Security Copilot Quick Trigger */}
        <button
          onClick={onOpenCopilot}
          className="flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 px-3 py-1.5 text-xs font-semibold text-white shadow-lg shadow-blue-500/20 transition hover:opacity-90"
        >
          <Sparkles className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">AI Copilot</span>
        </button>

        {/* User Info & Logout */}
        {user ? (
          <div className="flex items-center gap-2 border-l border-border/40 pl-3">
            <div className="flex flex-col text-right">
              <span className="text-xs font-semibold text-slate-200">{user.full_name}</span>
              <span className="text-[10px] text-muted-foreground">{user.email}</span>
            </div>
            <button
              onClick={logout}
              title="Logout"
              className="rounded-lg p-1.5 text-muted-foreground hover:bg-slate-800 hover:text-rose-400"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        ) : (
          <Link
            href="/login"
            className="rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
          >
            Sign In
          </Link>
        )}
      </div>
    </header>
  );
}
