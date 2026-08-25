'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Shield,
  Lock,
  Mail,
  User,
  ArrowRight,
  Sparkles,
  KeyRound,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';

export default function LoginPage() {
  const router = useRouter();
  const { login, refreshUserData } = useAuth();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('admin@vulnforge.sec');
  const [password, setPassword] = useState('VulnForgeDemo2026!');
  const [fullName, setFullName] = useState('Alex Mercer');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      if (isRegister) {
        const res = await api.register({
          email,
          password,
          full_name: fullName,
        });
        login(res.access_token, res.user);
      } else {
        const res = await api.login({ email, password });
        login(res.access_token, res.user);
      }
      await refreshUserData();
      router.push('/');
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickDemoLogin = async (demoEmail: string) => {
    setEmail(demoEmail);
    setPassword('VulnForgeDemo2026!');
    setLoading(true);
    setError(null);
    try {
      const res = await api.login({ email: demoEmail, password: 'VulnForgeDemo2026!' });
      login(res.access_token, res.user);
      await refreshUserData();
      router.push('/');
    } catch (err: any) {
      setError(err.message || 'Quick login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-8rem)] flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-blue-600/20 text-blue-400 ring-1 ring-blue-500/30">
            <Shield className="h-6 w-6" />
          </div>
          <h1 className="text-2xl font-black tracking-tight text-white">VulnForge</h1>
          <p className="text-xs text-muted-foreground">
            Enterprise Automated VAPT & Security Assessment Platform
          </p>
        </div>

        {/* Auth Box */}
        <div className="rounded-2xl border border-border/60 bg-[#111827] p-8 shadow-2xl space-y-6">
          <div className="flex items-center justify-between border-b border-border/40 pb-3 text-xs">
            <span className="font-bold text-white">
              {isRegister ? 'Create Organization Account' : 'Authenticate to Console'}
            </span>
            <button
              onClick={() => {
                setIsRegister(!isRegister);
                setError(null);
              }}
              className="font-semibold text-blue-400 hover:underline"
            >
              {isRegister ? 'Existing User? Sign In' : 'New User? Register'}
            </button>
          </div>

          {error && (
            <div className="rounded-lg bg-red-950/30 border border-red-500/40 p-3 text-xs font-semibold text-red-400">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            {isRegister && (
              <div>
                <label className="font-semibold text-slate-200">Full Name</label>
                <div className="relative mt-1">
                  <User className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                  <input
                    type="text"
                    required
                    placeholder="Alex Mercer"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="w-full rounded-lg border border-border bg-[#0b0f19] pl-9 pr-3 py-2 text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
                  />
                </div>
              </div>
            )}

            <div>
              <label className="font-semibold text-slate-200">Corporate Email</label>
              <div className="relative mt-1">
                <Mail className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <input
                  type="email"
                  required
                  placeholder="admin@vulnforge.sec"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full rounded-lg border border-border bg-[#0b0f19] pl-9 pr-3 py-2 text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="font-semibold text-slate-200">Password</label>
              <div className="relative mt-1">
                <Lock className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <input
                  type="password"
                  required
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full rounded-lg border border-border bg-[#0b0f19] pl-9 pr-3 py-2 text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-blue-600 py-2.5 font-bold text-white shadow-lg shadow-blue-600/30 transition hover:bg-blue-500 disabled:opacity-50 mt-2"
            >
              <span>{loading ? 'Authenticating...' : isRegister ? 'Register & Access' : 'Sign In'}</span>
              <ArrowRight className="h-4 w-4" />
            </button>
          </form>

          {/* Quick Demo Switcher */}
          <div className="border-t border-border/40 pt-4 space-y-2">
            <div className="text-center text-[10px] uppercase tracking-wider font-semibold text-muted-foreground">
              Instant Demo Logins
            </div>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => handleQuickDemoLogin('admin@vulnforge.sec')}
                className="rounded-lg border border-border/60 bg-[#0b0f19] p-2 text-center transition hover:border-blue-500 hover:bg-blue-600/10"
              >
                <div className="font-bold text-white text-[11px]">Owner</div>
                <div className="text-[9px] text-muted-foreground">Admin</div>
              </button>
              <button
                type="button"
                onClick={() => handleQuickDemoLogin('analyst@vulnforge.sec')}
                className="rounded-lg border border-border/60 bg-[#0b0f19] p-2 text-center transition hover:border-blue-500 hover:bg-blue-600/10"
              >
                <div className="font-bold text-white text-[11px]">Analyst</div>
                <div className="text-[9px] text-muted-foreground">AppSec</div>
              </button>
              <button
                type="button"
                onClick={() => handleQuickDemoLogin('viewer@vulnforge.sec')}
                className="rounded-lg border border-border/60 bg-[#0b0f19] p-2 text-center transition hover:border-blue-500 hover:bg-blue-600/10"
              >
                <div className="font-bold text-white text-[11px]">Viewer</div>
                <div className="text-[9px] text-muted-foreground">Audit</div>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
