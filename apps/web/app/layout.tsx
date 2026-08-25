'use client';

import React, { useState } from 'react';
import './globals.css';
import { AuthProvider } from '@/lib/auth-context';
import { ViewModeProvider } from '@/lib/view-mode-context';
import { Sidebar } from '@/components/layout/sidebar';
import { Navbar } from '@/components/layout/navbar';
import { CommandPalette } from '@/components/command-palette';
import { AICopilotDrawer } from '@/components/ai-copilot-drawer';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [copilotOpen, setCopilotOpen] = useState(false);

  return (
    <html lang="en" className="dark">
      <head>
        <title>VulnForge - Automated VAPT & Security Assessment Platform</title>
        <meta name="description" content="Production-Grade Automated VAPT & Security Assessment Platform" />
      </head>
      <body className="bg-[#090d16] text-foreground antialiased selection:bg-blue-600 selection:text-white">
        <AuthProvider>
          <ViewModeProvider>
            <div className="flex h-screen overflow-hidden">
              {/* Sidebar */}
              <Sidebar />

              {/* Main view area */}
              <div className="flex flex-1 flex-col overflow-hidden">
                <Navbar
                  onOpenCommandPalette={() => setCommandPaletteOpen(true)}
                  onOpenCopilot={() => setCopilotOpen(true)}
                />
                <main className="flex-1 overflow-y-auto p-6 bg-[#090d16]">
                  {children}
                </main>
              </div>
            </div>

            {/* Global Modals & Drawers */}
            <CommandPalette isOpen={commandPaletteOpen} onClose={() => setCommandPaletteOpen(false)} />
            <AICopilotDrawer isOpen={copilotOpen} onClose={() => setCopilotOpen(false)} />
          </ViewModeProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
