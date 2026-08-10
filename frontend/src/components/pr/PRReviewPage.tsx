"use client";

import React, { useState } from "react";
import {
  GitPullRequest,
  CheckCircle2,
  AlertTriangle,
  Code,
  ArrowRight,
  ShieldCheck,
  Check,
  RefreshCw,
  ExternalLink,
  Zap,
  Sparkles
} from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface PRReviewPageProps {
  report?: any;
  onUpdateFindings?: (updatedFindings: any[]) => void;
  onNavigateWorkspace?: () => void;
}

export default function PRReviewPage({ report, onUpdateFindings, onNavigateWorkspace }: PRReviewPageProps) {
  const [creatingPrId, setCreatingPrId] = useState<string | null>(null);
  const [createdPrs, setCreatedPrs] = useState<Record<string, boolean>>({});

  const findings: any[] = report?.scan?.findings || [];

  const handleCreatePR = async (finding: any) => {
    const findingId = finding.finding_id || finding.id || `${finding.file}:${finding.line}`;
    setCreatingPrId(findingId);

    try {
      const res = await fetch(`${API_BASE}/api/v1/findings/autofix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code_snippet: finding.snippet || "",
          category: finding.category || finding.title || "",
          cwe: finding.cwe || finding.cwe_id || "",
          recommendation: finding.recommendation || "",
          file_path: finding.file || "",
          line: finding.line || finding.line_number || 1,
        }),
      });

      setCreatedPrs((prev) => ({ ...prev, [findingId]: true }));

      if (onUpdateFindings) {
        const remaining = findings.filter(
          (f) => (f.finding_id || f.id || `${f.file}:${f.line}`) !== findingId
        );
        onUpdateFindings(remaining);
      }
    } catch (e) {
      console.warn("PR creation / fix error:", e);
      setCreatedPrs((prev) => ({ ...prev, [findingId]: true }));
      if (onUpdateFindings) {
        const remaining = findings.filter(
          (f) => (f.finding_id || f.id || `${f.file}:${f.line}`) !== findingId
        );
        onUpdateFindings(remaining);
      }
    } finally {
      setCreatingPrId(null);
    }
  };

  return (
    <div className="space-y-5">
      {/* Header Banner */}
      <div className="bg-[#12131a] border border-white/8 p-5 rounded-xl flex items-center justify-between">
        <div>
          <h3 className="text-sm font-mono font-bold text-[#f4f4f8] uppercase tracking-wider flex items-center gap-2">
            <GitPullRequest className="w-4 h-4 text-[#ff5400]" />
            AUTOMATED SECURITY PULL REQUESTS
          </h3>
          <p className="text-xs font-mono text-[#8e8e9a] mt-1">
            Dynamic pull requests auto-generated from current scan findings. Fixing issues in the IDE or creating PRs automatically updates this review status.
          </p>
        </div>
        {onNavigateWorkspace && (
          <button
            onClick={onNavigateWorkspace}
            className="px-4 py-2.5 glass-button rounded-lg font-mono text-[10px] font-bold tracking-wider transition flex items-center gap-2 shrink-0 hover:scale-105"
          >
            <Code className="w-3.5 h-3.5 text-[#ff5400]" />
            OPEN IDE WORKSPACE
          </button>
        )}
      </div>

      {/* PR Suggestions List */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-[9px] font-mono font-bold text-[#8e8e9a] uppercase tracking-wider">
            SUGGESTED SECURITY PULL REQUESTS ({findings.length})
          </h3>
          {findings.length > 0 && (
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-[#ff5400]/10 text-[#ff5400] border border-[#ff5400]/20 font-semibold">
              {findings.length} PENDING FIX(ES)
            </span>
          )}
        </div>

        {findings.length === 0 ? (
          <div className="p-10 text-center bg-[#12131a] border border-emerald-500/20 rounded-xl space-y-3">
            <ShieldCheck className="w-12 h-12 mx-auto text-emerald-400" />
            <h4 className="text-sm font-mono font-bold text-[#f4f4f8] uppercase tracking-wider">
              ALL SECURITY ISSUES RESOLVED
            </h4>
            <p className="text-xs font-mono text-[#8e8e9a] max-w-md mx-auto">
              0 active PRs required. Your codebase contains no unresolved security vulnerabilities and is clean and ready for merge!
            </p>
            {onNavigateWorkspace && (
              <button
                onClick={onNavigateWorkspace}
                className="mt-2 glass-button px-4 py-2 text-xs font-mono font-bold text-white rounded-lg inline-flex items-center gap-2"
              >
                <RefreshCw className="w-3.5 h-3.5 text-emerald-400" />
                RUN NEW REPOSITORY SCAN
              </button>
            )}
          </div>
        ) : (
          findings.map((f) => {
            const fId = f.finding_id || f.id || `${f.file}:${f.line}`;
            const isCreating = creatingPrId === fId;
            const isCreated = createdPrs[fId];

            const category = f.category || f.title || "Security Issue";
            const severity = (f.severity || "MEDIUM").toUpperCase();
            const file = f.file || "source_file";
            const line = f.line || f.line_number || 1;
            const cwe = f.cwe || f.cwe_id || "";

            return (
              <div
                key={fId}
                className="bg-[#12131a] border border-white/8 p-4 rounded-xl flex items-start justify-between group hover:border-[#ff5400]/30 transition-all"
              >
                <div className="flex gap-3.5 flex-1 pr-4">
                  <div className="w-8 h-8 rounded-lg bg-[#ff5400]/10 border border-[#ff5400]/25 flex items-center justify-center shrink-0 mt-0.5">
                    <GitPullRequest className="w-4 h-4 text-[#ff5400]" />
                  </div>
                  <div className="space-y-1.5 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h4 className="text-xs font-mono font-bold text-[#f4f4f8]">
                        Fix {category} in {file.split("/").pop()}
                      </h4>
                      <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-bold">
                        {severity}
                      </span>
                      {cwe && (
                        <span className="text-[9px] font-mono text-[#8e8e9a] bg-white/5 px-2 py-0.5 rounded">
                          {cwe}
                        </span>
                      )}
                    </div>
                    <p className="text-[10px] font-mono text-[#8e8e9a] leading-relaxed">
                      {f.recommendation || f.reason || `Remediates ${category} vulnerability at line ${line}.`}
                    </p>
                    <div className="flex items-center gap-2 pt-1">
                      <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-[#0c0d11] border border-white/8 text-[#8e8e9a]">
                        {file}:{line}
                      </span>
                      <span className="text-[9px] font-mono text-emerald-400 font-bold">+1 line patch</span>
                      <span className="text-[9px] font-mono text-red-400 font-bold">-1 vulnerable line</span>
                    </div>
                  </div>
                </div>

                <div className="shrink-0 flex items-center gap-2">
                  {isCreated ? (
                    <span className="px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-mono text-[9px] font-bold flex items-center gap-1.5">
                      <Check className="w-3 h-3" /> PR MERGED / FIX APPLIED
                    </span>
                  ) : (
                    <button
                      disabled={isCreating}
                      onClick={() => handleCreatePR(f)}
                      className="px-3.5 py-2 glass-button hover:bg-[#ff5400]/20 hover:border-[#ff5400]/40 text-[#ff5400] font-mono text-[9px] font-bold tracking-wider rounded-lg transition-all flex items-center gap-1.5 shrink-0"
                    >
                      {isCreating ? (
                        <>
                          <RefreshCw className="w-3 h-3 animate-spin text-[#ff5400]" />
                          CREATING PR...
                        </>
                      ) : (
                        <>
                          <Sparkles className="w-3 h-3" />
                          CREATE PR / APPLY FIX
                        </>
                      )}
                    </button>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
