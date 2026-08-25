'use client';

import React, { useState } from 'react';
import {
  Bot,
  Send,
  Sparkles,
  ShieldCheck,
  ArrowRight,
  RefreshCw,
  Cpu,
  User,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  actions?: string[];
}

export default function CopilotPage() {
  const { currentProject } = useAuth();
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: `Welcome to **VulnForge Security Copilot**. I have loaded the vulnerability assessment data, perimeter telemetry, and normalized findings for **${currentProject?.name || 'your project'}**.\n\nHow can I assist your AppSec, DevSecOps, or engineering team today?`,
      actions: [
        'What are the 5 highest-risk findings?',
        'Summarize our security posture for leadership',
        'How do developers fix the CORS misconfiguration?',
        'Which vulnerabilities violate SOC 2 / PCI-DSS controls?',
      ],
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const sendMessage = async (text: string) => {
    if (!text.trim() || !currentProject) return;

    const userMsg: Message = { role: 'user', content: text };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const history = messages.map((m) => ({ role: m.role, content: m.content }));
      const res = await api.copilotChat({
        project_id: currentProject.id,
        message: text,
        chat_history: history,
      });

      const assistantMsg: Message = {
        role: 'assistant',
        content: res.answer,
        actions: res.suggested_actions,
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `⚠️ Failed to reach Copilot engine: ${err.message || 'Unknown error'}`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto h-[calc(100vh-8rem)] flex flex-col rounded-xl border border-border/60 bg-[#111827] shadow-2xl overflow-hidden">
      {/* Copilot Header */}
      <div className="flex items-center justify-between border-b border-border/40 bg-[#0b0f19] px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-600 text-white shadow-md">
            <Bot className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <span>Security Copilot Analyst</span>
              <span className="rounded bg-blue-500/20 px-2 py-0.5 text-[10px] font-bold text-blue-400">
                ACTIVE
              </span>
            </div>
            <div className="text-[11px] text-muted-foreground">
              Scope: <span className="font-semibold text-slate-300">{currentProject?.name}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Message Feed */}
      <div className="flex-1 space-y-4 overflow-y-auto p-6 text-xs">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex gap-3 ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            {m.role === 'assistant' && (
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-blue-600/20 text-blue-400 ring-1 ring-blue-500/30">
                <Bot className="h-3.5 w-3.5" />
              </div>
            )}

            <div className={`max-w-[85%] space-y-2`}>
              <div
                className={`rounded-xl px-4 py-3 leading-relaxed ${
                  m.role === 'user'
                    ? 'bg-blue-600 font-medium text-white shadow-md'
                    : 'border border-border/60 bg-[#0b0f19] text-slate-200 shadow'
                }`}
              >
                <div className="whitespace-pre-wrap">{m.content}</div>
              </div>

              {/* Action Prompt Chips */}
              {m.actions && m.actions.length > 0 && (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {m.actions.map((act, aIdx) => (
                    <button
                      key={aIdx}
                      onClick={() => sendMessage(act)}
                      className="flex items-center gap-1 rounded-full border border-blue-500/30 bg-blue-950/30 px-3 py-1 text-[11px] font-medium text-blue-300 transition hover:bg-blue-900/40"
                    >
                      <span>{act}</span>
                      <ArrowRight className="h-3 w-3" />
                    </button>
                  ))}
                </div>
              )}
            </div>

            {m.role === 'user' && (
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-800 text-slate-300">
                <User className="h-3.5 w-3.5" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground pl-10">
            <RefreshCw className="h-3.5 w-3.5 animate-spin text-blue-400" />
            <span>Analyzing normalized security evidence and synthesizing guidance...</span>
          </div>
        )}
      </div>

      {/* Input Bar */}
      <div className="border-t border-border/40 bg-[#0b0f19] p-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            sendMessage(input);
          }}
          className="flex items-center gap-3"
        >
          <input
            type="text"
            placeholder="Ask Copilot about vulnerability remediations, business impact, or code fixes..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={loading}
            className="flex-1 rounded-lg border border-border bg-[#111827] px-4 py-2.5 text-xs text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 text-white transition hover:bg-blue-500 disabled:opacity-40"
          >
            <Send className="h-4 w-4" />
          </button>
        </form>
        <div className="mt-2 text-center text-[10px] text-muted-foreground">
          Strictly confined to authorized project context &bull; Evidence-grounded vulnerability analysis
        </div>
      </div>
    </div>
  );
}
