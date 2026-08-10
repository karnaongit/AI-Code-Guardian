"use client";

import React, { useState, useEffect } from "react";
import { Search, FolderGit2, Folder, FileArchive, Loader2, Play, Sparkles, Upload } from "lucide-react";

export type SourceType = "local" | "zip" | "github";

export interface ScanOptions {
  sourceType: SourceType;
  target: string;
  zipFile?: File | null;
  aiEnabled: boolean;
}

interface RepoInputProps {
  onScan: (options: ScanOptions) => void;
  isScanning: boolean;
}

export default function RepoInput({ onScan, isScanning }: RepoInputProps) {
  const [sourceType, setSourceType] = useState<SourceType>("github");
  const [target, setTarget] = useState("");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [aiEnabled, setAiEnabled] = useState(false);

  useEffect(() => {
    try {
      const savedSource = sessionStorage.getItem("guardian_source_type") as SourceType | null;
      const savedTarget = sessionStorage.getItem("guardian_repo_target");
      const savedAi = sessionStorage.getItem("guardian_ai_enabled");

      if (savedSource) setSourceType(savedSource);
      if (savedTarget) setTarget(savedTarget);
      if (savedAi !== null) setAiEnabled(savedAi === "true");
    } catch (e) {
      console.warn("Failed to load RepoInput state from sessionStorage:", e);
    }
  }, []);

  const handleSourceTypeChange = (type: SourceType) => {
    setSourceType(type);
    try {
      sessionStorage.setItem("guardian_source_type", type);
    } catch (e) {}
  };

  const handleTargetChange = (val: string) => {
    setTarget(val);
    try {
      sessionStorage.setItem("guardian_repo_target", val);
    } catch (e) {}
  };

  const handleAiToggle = () => {
    const nextVal = !aiEnabled;
    setAiEnabled(nextVal);
    try {
      sessionStorage.setItem("guardian_ai_enabled", String(nextVal));
    } catch (e) {}
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (sourceType === "zip") {
      if (!zipFile) return;
      onScan({ sourceType: "zip", target: zipFile.name, zipFile, aiEnabled });
    } else {
      if (!target.trim()) return;
      onScan({ sourceType, target: target.trim(), aiEnabled });
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setZipFile(e.target.files[0]);
    }
  };

  const isSubmitDisabled = isScanning || (sourceType === "zip" ? !zipFile : !target.trim());

  return (
    <div className="w-full bg-[#12131a] border border-white/8 text-[#f4f4f8] rounded-xl overflow-hidden shadow-lg p-4 space-y-4">
      {/* Source Type Selector Tabs */}
      <div className="flex items-center justify-between flex-wrap gap-2 pb-2 border-b border-white/5">
        <div className="flex items-center gap-1.5 bg-[#0c0d11] p-1 rounded-lg border border-white/8">
          <button
            type="button"
            onClick={() => handleSourceTypeChange("local")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all ${
              sourceType === "local"
                ? "bg-[#ff5400] text-white font-bold shadow"
                : "text-[#8e8e9a] hover:text-white hover:bg-white/5"
            }`}
          >
            <Folder className="h-3.5 w-3.5" />
            Local Directory
          </button>

          <button
            type="button"
            onClick={() => handleSourceTypeChange("zip")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all ${
              sourceType === "zip"
                ? "bg-[#ff5400] text-white font-bold shadow"
                : "text-[#8e8e9a] hover:text-white hover:bg-white/5"
            }`}
          >
            <FileArchive className="h-3.5 w-3.5" />
            Upload ZIP Archive
          </button>

          <button
            type="button"
            onClick={() => handleSourceTypeChange("github")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all ${
              sourceType === "github"
                ? "bg-[#ff5400] text-white font-bold shadow"
                : "text-[#8e8e9a] hover:text-white hover:bg-white/5"
            }`}
          >
            <FolderGit2 className="h-3.5 w-3.5" />
            Clone GitHub Repo
          </button>
        </div>

        {/* AI Toggle Button */}
        <button
          type="button"
          onClick={handleAiToggle}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-[11px] font-mono font-semibold transition-all select-none ${
            aiEnabled
              ? "bg-[#ff5400]/15 border-[#ff5400]/40 text-[#ff5400]"
              : "bg-white/5 border-white/10 text-[#8e8e9a] hover:text-white"
          }`}
        >
          <Sparkles className="h-3.5 w-3.5" />
          AI REASONING: {aiEnabled ? "ENABLED" : "OFF"}
        </button>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="flex flex-wrap md:flex-nowrap items-end gap-4">
        <div className="flex-1 space-y-2">
          {sourceType === "local" && (
            <>
              <label htmlFor="localPathInput" className="text-[11px] font-mono font-semibold tracking-wider text-[#8e8e9a] uppercase flex items-center gap-2">
                <Folder className="h-3.5 w-3.5 text-[#ff5400]" />
                ABSOLUTE SYSTEM DIRECTORY PATH
              </label>
              <div className="relative flex items-center">
                <Search className="absolute left-3 h-3.5 w-3.5 text-[#8e8e9a]" />
                <input
                  id="localPathInput"
                  type="text"
                  placeholder="/Users/username/projects/my-app"
                  className="w-full h-10 pl-10 pr-3 rounded-lg glass-input text-sm font-mono placeholder:text-[#8e8e9a]/50 focus:outline-none disabled:opacity-50"
                  value={target}
                  onChange={(e) => handleTargetChange(e.target.value)}
                  disabled={isScanning}
                />
              </div>
            </>
          )}

          {sourceType === "zip" && (
            <>
              <label htmlFor="zipFileInput" className="text-[11px] font-mono font-semibold tracking-wider text-[#8e8e9a] uppercase flex items-center gap-2">
                <Upload className="h-3.5 w-3.5 text-[#ff5400]" />
                UPLOAD REPOSITORY ZIP ARCHIVE
              </label>
              <div className="relative flex items-center">
                <input
                  id="zipFileInput"
                  type="file"
                  accept=".zip"
                  onChange={handleFileChange}
                  disabled={isScanning}
                  className="w-full h-10 px-3 py-2 rounded-lg glass-input text-xs font-mono text-[#8e8e9a] file:mr-4 file:py-1 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-[#ff5400]/20 file:text-[#ff5400] hover:file:bg-[#ff5400]/30 cursor-pointer disabled:opacity-50"
                />
              </div>
            </>
          )}

          {sourceType === "github" && (
            <>
              <label htmlFor="githubUrlInput" className="text-[11px] font-mono font-semibold tracking-wider text-[#8e8e9a] uppercase flex items-center gap-2">
                <FolderGit2 className="h-3.5 w-3.5 text-[#ff5400]" />
                GITHUB REPOSITORY URL
              </label>
              <div className="relative flex items-center">
                <Search className="absolute left-3 h-3.5 w-3.5 text-[#8e8e9a]" />
                <input
                  id="githubUrlInput"
                  type="text"
                  placeholder="https://github.com/user/repository"
                  className="w-full h-10 pl-10 pr-3 rounded-lg glass-input text-sm font-mono placeholder:text-[#8e8e9a]/50 focus:outline-none disabled:opacity-50"
                  value={target}
                  onChange={(e) => handleTargetChange(e.target.value)}
                  disabled={isScanning}
                />
              </div>
            </>
          )}
        </div>

        {/* Submit Scan Button */}
        <button
          type="submit"
          disabled={isSubmitDisabled}
          className="h-10 px-5 py-2 rounded-lg flex items-center justify-center w-full md:w-36 glass-button font-mono text-xs font-bold tracking-wider transition-all disabled:opacity-40 disabled:cursor-not-allowed disabled:transform-none shrink-0"
        >
          {isScanning ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              SCANNING
            </>
          ) : (
            <>
              <Play className="mr-2 h-4 w-4" />
              RUN SCAN
            </>
          )}
        </button>
      </form>
    </div>
  );
}
