'use client';

import React from 'react';
import Link from 'next/link';
import {
  Shield,
  Zap,
  Target,
  FileCheck,
  CheckCircle2,
  Lock,
  ArrowRight,
  Activity,
  Layers,
  Terminal,
  Cpu,
  Sparkles,
  Search,
} from 'lucide-react';

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[#060911] text-slate-100 selection:bg-blue-600 selection:text-white">
      {/* Top Banner Navigation */}
      <header className="border-b border-border/30 bg-[#080d1a]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 shadow-md shadow-blue-500/20">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <span className="text-xl font-black tracking-tight text-white">
              Vuln<span className="text-blue-500">Forge</span>
            </span>
          </div>
          <div className="flex items-center gap-4">
            <Link
              href="/"
              className="text-xs font-semibold text-slate-300 hover:text-white transition"
            >
              Dashboard
            </Link>
            <Link
              href="/login"
              className="rounded-lg border border-border/80 bg-[#111827] px-4 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 transition"
            >
              Sign In
            </Link>
            <Link
              href="/assessments/new"
              className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-bold text-white shadow-lg shadow-blue-600/30 hover:bg-blue-500 transition"
            >
              Launch Assessment
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative overflow-hidden pt-20 pb-28 px-6">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_var(--tw-gradient-stops))] from-blue-900/20 via-transparent to-transparent pointer-events-none" />
        
        <div className="max-w-5xl mx-auto text-center relative z-10">
          <div className="inline-flex items-center gap-2 rounded-full border border-blue-500/30 bg-blue-500/10 px-3.5 py-1 text-xs font-semibold text-blue-400 mb-6">
            <Sparkles className="h-3.5 w-3.5" />
            Enterprise Automated VAPT & Continuous Security Assessment
          </div>

          <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white leading-[1.15] mb-6">
            Find Security Weaknesses <br />
            <span className="bg-gradient-to-r from-blue-400 via-indigo-300 to-cyan-400 bg-clip-text text-transparent">
              Before Attackers Do.
            </span>
          </h1>

          <p className="text-base sm:text-lg text-slate-400 max-w-3xl mx-auto mb-10 leading-relaxed">
            Automated, evidence-driven security assessments for modern applications, APIs, infrastructure, and authorized assets. Zero fake metrics, zero hallucination, pure verified vulnerability intelligence.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              href="/assessments/new"
              className="w-full sm:w-auto flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-8 py-3.5 text-sm font-bold text-white shadow-xl shadow-blue-600/30 hover:bg-blue-500 transition"
            >
              <span>Start Security Assessment</span>
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              href="/"
              className="w-full sm:w-auto flex items-center justify-center gap-2 rounded-xl border border-border bg-[#111827]/80 px-8 py-3.5 text-sm font-semibold text-slate-300 hover:text-white hover:bg-slate-800 transition"
            >
              <span>Explore Live Platform Demo</span>
            </Link>
          </div>
        </div>
      </section>

      {/* Feature Grid */}
      <section className="max-w-7xl mx-auto px-6 py-16 border-t border-border/30">
        <div className="text-center max-w-2xl mx-auto mb-14">
          <h2 className="text-2xl sm:text-3xl font-bold text-white mb-3">
            Engineered for Precision & Compliance
          </h2>
          <p className="text-sm text-slate-400">
            A complete defensive security lifecycle built on strict scope control, deterministic scoring, and verified technical proof.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card 1 */}
          <div className="rounded-2xl border border-border/60 bg-[#0e1424] p-6 hover:border-blue-500/40 transition">
            <div className="h-10 w-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 mb-4">
              <Target className="h-5 w-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Strict Scope & SSRF Gates</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Every target is validated against rigorous CIDR, domain, and private IP boundaries before any packets are dispatched. Never scan unintended infrastructure.
            </p>
          </div>

          {/* Card 2 */}
          <div className="rounded-2xl border border-border/60 bg-[#0e1424] p-6 hover:border-blue-500/40 transition">
            <div className="h-10 w-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 mb-4">
              <Layers className="h-5 w-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Cross-Scanner Correlation</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Nmap, Nuclei, OWASP ZAP, and custom Web security engines unified into single, deduplicated finding records with multi-scanner provenance.
            </p>
          </div>

          {/* Card 3 */}
          <div className="rounded-2xl border border-border/60 bg-[#0e1424] p-6 hover:border-blue-500/40 transition">
            <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-4">
              <FileCheck className="h-5 w-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Consulting Deliverables</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Generate branded Executive, Technical, and Developer reports in PDF, HTML, JSON, and CSV with customized white-labeling and classification tags.
            </p>
          </div>
        </div>
      </section>

      {/* Trust & Transparency Banner */}
      <section className="bg-[#0b101d] border-y border-border/40 py-12 px-6">
        <div className="max-w-5xl mx-auto flex flex-col md:flex-row items-center justify-between gap-8">
          <div>
            <h3 className="text-xl font-bold text-white mb-1">Evidence-First Transparency</h3>
            <p className="text-xs text-slate-400 max-w-xl">
              We never fabricate CVEs or simulate artificial AI scores. Every platform finding includes observed HTTP headers, request snippets, and exact reproduction steps.
            </p>
          </div>
          <Link
            href="/assessments/new"
            className="whitespace-nowrap rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 px-6 py-3 text-xs font-bold text-white shadow-lg hover:opacity-90 transition"
          >
            Launch Free Assessment
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="max-w-7xl mx-auto px-6 py-8 text-center text-xs text-slate-500">
        © 2026 VulnForge Security Platform &bull; Authorized Security Assessment Software.
      </footer>
    </div>
  );
}
