"use client";

import React, { useState } from "react";
import { X, Copy, MessageSquare, Check, ShieldAlert, AlertTriangle, Code, ChevronRight } from "lucide-react";

export interface FindingDetail {
  finding_id: string;
  category: string;
  severity: string;
  rule_id?: string;
  cwe?: string;
  owasp?: string;
  file: string;
  line: number;
  snippet: string;
  recommendation: string;
  reason?: string;
  is_exploitable?: boolean;
  exploitability_score?: number;
  exploit_scenario?: string;
  business_impact?: string;
  remediation_patch?: string;
}

interface FindingDrawerProps {
  finding: FindingDetail | null;
  isOpen: boolean;
  onClose: () => void;
  onDiscussInChat?: (finding: FindingDetail) => void;
}

export const FindingDrawer: React.FC<FindingDrawerProps> = ({
  finding,
  isOpen,
  onClose,
  onDiscussInChat,
}) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !finding) return null;

  const handleCopyAgentInstructions = () => {
    const prompt = `Fix security vulnerability in ${finding.file} at line ${finding.line}:\n` +
      `- Category: ${finding.category} (${finding.cwe || "Security"})\n` +
      `- Severity: ${finding.severity}\n` +
      `- Reason: ${finding.reason || "Vulnerable code pattern detected"}\n` +
      `- Recommendation: ${finding.recommendation}\n` +
      (finding.remediation_patch ? `- Suggested Patch:\n${finding.remediation_patch}\n` : "");

    navigator.clipboard.writeText(prompt);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadge = (severity: string) => {
    const s = severity.toLowerCase();
    if (s === "critical") return "bg-red-500/20 text-red-400 border-red-500/40";
    if (s === "high") return "bg-orange-500/20 text-orange-400 border-orange-500/40";
    if (s === "medium") return "bg-yellow-500/20 text-yellow-400 border-yellow-500/40";
    return "bg-blue-500/20 text-blue-400 border-blue-500/40";
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/40 backdrop-blur-md flex justify-end">
      <div className="w-full max-w-2xl glass-panel border-l border-white/10 text-slate-100 h-full overflow-y-auto flex flex-col shadow-[[-20px_0_40px_rgba(0,0,0,0.3)]] animate-in slide-in-from-right duration-300">
        
        {/* Header */}
        <div className="p-6 border-b border-white/10 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className={`px-2.5 py-0.5 text-xs font-semibold rounded-full border ${getSeverityBadge(finding.severity)}`}>
                {finding.severity}
              </span>
              {finding.cwe && (
                <span className="px-2 py-0.5 text-xs font-mono glass-card text-slate-300 rounded">
                  {finding.cwe}
                </span>
              )}
              {finding.is_exploitable && (
                <span className="px-2 py-0.5 text-xs font-semibold glass-card border border-red-500/30 text-red-400 rounded flex items-center gap-1">
                  <ShieldAlert className="w-3.5 h-3.5" /> Reachable
                </span>
              )}
            </div>
            <h2 className="text-xl font-bold text-slate-100">{finding.category}</h2>
            <p className="text-xs text-slate-400 font-mono mt-1">
              {finding.file}:{finding.line}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 flex-1 overflow-y-auto">
          
          {/* Exploitability Meter */}
          {finding.exploitability_score !== undefined && (
            <div className="glass-card p-4 rounded-xl">
              <div className="flex justify-between items-center mb-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Exploitability Feasibility Score</span>
                <span className="text-sm font-bold text-amber-400">{Math.round((finding.exploitability_score || 0) * 100)}%</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-gradient-to-r from-amber-500 to-red-500 h-full transition-all duration-500"
                  style={{ width: `${Math.round((finding.exploitability_score || 0) * 100)}%` }}
                />
              </div>
            </div>
          )}

          {/* Exploit Scenario Narrative */}
          {finding.exploit_scenario && (
            <div className="glass-card p-4 rounded-xl space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4" /> Exploit Scenario
              </h3>
              <p className="text-sm text-slate-300 leading-relaxed">{finding.exploit_scenario}</p>
            </div>
          )}

          {/* Code Snippet */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Code className="w-4 h-4" /> Vulnerable Snippet
            </h3>
            <pre className="p-4 rounded-xl glass-card text-xs font-mono text-slate-200 overflow-x-auto">
              <code>{finding.snippet}</code>
            </pre>
          </div>

          {/* Recommendation */}
          <div className="glass-card p-4 rounded-xl space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-emerald-400">Remediation Guidance</h3>
            <p className="text-sm text-slate-300 leading-relaxed">{finding.recommendation}</p>
          </div>

        </div>

        {/* Action Buttons Footer */}
        <div className="p-6 border-t border-white/10 glass-panel flex flex-wrap items-center justify-between gap-3">
          <button
            onClick={handleCopyAgentInstructions}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-100 font-medium text-xs border border-slate-700 transition"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            {copied ? "Instructions Copied!" : "Copy Agent Instructions"}
          </button>

          {onDiscussInChat && (
            <button
              onClick={() => onDiscussInChat(finding)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl glass-button bg-gradient-to-r from-blue-600/80 to-indigo-600/80 text-white font-semibold text-xs shadow-lg transition"
            >
              <MessageSquare className="w-4 h-4" />
              Discuss in Chat
            </button>
          )}
        </div>

      </div>
    </div>
  );
};

export default FindingDrawer;
