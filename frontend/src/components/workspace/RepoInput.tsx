"use client";

import React, { useState } from "react";
import { Search, FolderGit2, Loader2, Play, CheckCircle2, Sparkles } from "lucide-react";

interface RepoInputProps {
  onScan: (target: string, isUrl: boolean, aiEnabled: boolean) => void;
  isScanning: boolean;
}

export default function RepoInput({ onScan, isScanning }: RepoInputProps) {
  const [target, setTarget] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    onScan(target.trim(), true, true);
  };

  return (
    <div className="w-full glass-card text-slate-100 rounded-xl overflow-hidden shadow-lg">
      <div className="p-4">
        <form onSubmit={handleSubmit} className="flex flex-wrap md:flex-nowrap items-end gap-4">
          <div className="flex-1 space-y-2">
            <label htmlFor="targetInput" className="text-sm font-semibold flex items-center gap-2">
              <FolderGit2 className="h-4 w-4 text-indigo-400" />
              GitHub Repository URL
            </label>
            <div className="relative flex items-center">
              <Search className="absolute left-3 h-4 w-4 text-slate-400" />
              <input
                id="targetInput"
                type="text"
                placeholder="https://github.com/user/repository"
                className="w-full h-10 pl-10 pr-3 rounded-md glass-input text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 disabled:opacity-50"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isScanning}
              />
            </div>
          </div>

          <div className="flex items-center gap-3 pb-1">
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold select-none shadow-sm">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              GitHub Repo URL
            </div>
            
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 text-xs font-semibold select-none shadow-sm">
              <Sparkles className="h-3.5 w-3.5 text-indigo-400" />
              AI Analysis Active
            </div>
          </div>

          <button 
            type="submit" 
            disabled={!target.trim() || isScanning}
            className="h-10 px-4 py-2 rounded-md flex items-center justify-center w-full md:w-32 glass-button text-white font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isScanning ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Scanning
              </>
            ) : (
              <>
                <Play className="mr-2 h-4 w-4" />
                Run Scan
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}

