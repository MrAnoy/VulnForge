'use client';

import React, { useState } from 'react';
import {
  Bot,
  X,
  Send,
  Sparkles,
  ShieldAlert,
  ArrowRight,
  RefreshCw,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  actions?: string[];
}

export function AICopilotDrawer({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { currentProject } = useAuth();
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: `Hello! I am your **VulnForge Security Copilot**. I have indexed the authorized findings for **${currentProject?.name || 'your project'}**.\n\nAsk me any question about your vulnerability surface, remediation guidance, or risk prioritization.`,
      actions: [
        'What are the top 5 critical security issues?',
        'Explain our business risk exposure',
        'How do developers fix missing headers?',
      ],
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

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
          content: `⚠️ Failed to query Security Copilot: ${err.message || 'Unknown error'}`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-border/80 bg-[#0f172a] shadow-2xl backdrop-blur-xl">
      {/* Header */}
      <div className="flex h-16 items-center justify-between border-b border-border/50 bg-[#0b0f19] px-5">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600/20 text-blue-400 ring-1 ring-blue-500/30">
            <Bot className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-1.5 text-sm font-bold text-white">
              <span>Security Copilot</span>
              <Sparkles className="h-3.5 w-3.5 text-blue-400" />
            </div>
            <div className="text-[11px] text-muted-foreground truncate max-w-[220px]">
              {currentProject?.name}
            </div>
          </div>
        </div>
        <button
          onClick={onClose}
          className="rounded-lg p-1.5 text-muted-foreground transition hover:bg-slate-800 hover:text-white"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 space-y-4 overflow-y-auto p-4 text-xs">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex flex-col ${m.role === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div
              className={`max-w-[90%] rounded-xl px-3.5 py-2.5 leading-relaxed ${
                m.role === 'user'
                  ? 'bg-blue-600 font-medium text-white'
                  : 'border border-border/60 bg-[#1e293b]/70 text-slate-200'
              }`}
            >
              <div className="whitespace-pre-wrap">{m.content}</div>
            </div>

            {/* Action Chips */}
            {m.actions && m.actions.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {m.actions.map((act, aIdx) => (
                  <button
                    key={aIdx}
                    onClick={() => sendMessage(act)}
                    className="flex items-center gap-1 rounded-full border border-blue-500/30 bg-blue-950/30 px-2.5 py-1 text-[10px] font-medium text-blue-300 transition hover:bg-blue-900/40"
                  >
                    <span>{act}</span>
                    <ArrowRight className="h-2.5 w-2.5" />
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <RefreshCw className="h-3.5 w-3.5 animate-spin text-blue-400" />
            <span>Analyzing normalized security data...</span>
          </div>
        )}
      </div>

      {/* Input bar */}
      <div className="border-t border-border/50 bg-[#0b0f19] p-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            sendMessage(input);
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            placeholder="Ask Copilot a security question..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={loading}
            className="flex-1 rounded-lg border border-border/60 bg-[#111827] px-3 py-2 text-xs text-white placeholder-muted-foreground focus:border-blue-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 text-white transition hover:bg-blue-500 disabled:opacity-40"
          >
            <Send className="h-3.5 w-3.5" />
          </button>
        </form>
        <div className="mt-1.5 text-center text-[10px] text-muted-foreground">
          Grounded in authorized project evidence &bull; Zero external hallucination
        </div>
      </div>
    </div>
  );
}
