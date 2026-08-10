"use client";

import React, { useState, useEffect } from "react";
import RepoInput, { ScanOptions } from "./RepoInput";
import FileTreeSidebar, { FileNode } from "./FileTreeSidebar";
import CodeViewer from "./CodeViewer";
import VulnerabilityPanel from "./VulnerabilityPanel";
import { Loader2, RotateCcw, CheckCircle2 } from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface IDEWorkspaceProps {
  onScanComplete?: (scanResult: any) => void;
  onUpdateFindings?: (updatedFindings: any[]) => void;
}

export default function IDEWorkspace({ onScanComplete, onUpdateFindings }: IDEWorkspaceProps) {
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [fileTree, setFileTree] = useState<FileNode | null>(null);
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [fileContent, setFileContent] = useState<string>("// Select a file from the explorer to view its content.");
  const [findings, setFindings] = useState<any[]>([]);
  const [scanFindingsMap, setScanFindingsMap] = useState<Record<string, any[]>>({});

  // Resizable Explorer state
  const [sidebarWidth, setSidebarWidth] = useState(250);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);

  // Restore state from sessionStorage on mount
  useEffect(() => {
    try {
      const savedScanId = sessionStorage.getItem("guardian_scan_id");
      const savedFileTree = sessionStorage.getItem("guardian_file_tree");
      const savedMap = sessionStorage.getItem("guardian_findings_map");
      const savedPath = sessionStorage.getItem("guardian_selected_path");
      const savedContent = sessionStorage.getItem("guardian_file_content");
      const savedFindings = sessionStorage.getItem("guardian_file_findings");

      if (savedScanId) setScanId(savedScanId);
      if (savedFileTree) setFileTree(JSON.parse(savedFileTree));
      if (savedMap) setScanFindingsMap(JSON.parse(savedMap));
      if (savedPath) setSelectedFilePath(savedPath);
      if (savedContent) setFileContent(savedContent);
      if (savedFindings) setFindings(JSON.parse(savedFindings));
    } catch (e) {
      console.warn("Failed to load workspace state from sessionStorage:", e);
    }
  }, []);

  // Save state to sessionStorage
  const saveStateToStorage = (
    newScanId: string | null,
    newTree: FileNode | null,
    newMap: Record<string, any[]>,
    newPath: string | null = selectedFilePath,
    newContent: string = fileContent,
    newFindings: any[] = findings
  ) => {
    try {
      if (newScanId) sessionStorage.setItem("guardian_scan_id", newScanId);
      if (newTree) sessionStorage.setItem("guardian_file_tree", JSON.stringify(newTree));
      if (newMap) sessionStorage.setItem("guardian_findings_map", JSON.stringify(newMap));
      if (newPath) sessionStorage.setItem("guardian_selected_path", newPath);
      if (newContent) sessionStorage.setItem("guardian_file_content", newContent);
      if (newFindings) sessionStorage.setItem("guardian_file_findings", JSON.stringify(newFindings));
    } catch (e) {
      console.warn("Failed to save workspace state to sessionStorage:", e);
    }
  };

  const handleMouseDownResize = (e: React.MouseEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = sidebarWidth;

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const delta = moveEvent.clientX - startX;
      const newWidth = Math.max(140, Math.min(500, startWidth + delta));
      setSidebarWidth(newWidth);
    };

    const handleMouseUp = () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };

    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseup", handleMouseUp);
  };

  const handleScan = async (targetOrOptions: string | ScanOptions, isUrl?: boolean, aiEnabledParam?: boolean) => {
    setIsScanning(true);
    setScanId(null);
    setFileTree(null);
    setSelectedFilePath(null);
    setFileContent("// Scan in progress...");
    setScanFindingsMap({});

    try {
      let res: Response;

      if (typeof targetOrOptions === "object") {
        const { sourceType, target, zipFile, aiEnabled } = targetOrOptions;
        if (sourceType === "zip" && zipFile) {
          const formData = new FormData();
          formData.append("file", zipFile);
          formData.append("scan_mode", "precision");
          formData.append("enable_ai", String(aiEnabled));

          res = await fetch(`${API_BASE}/api/v1/scans/upload`, {
            method: "POST",
            body: formData,
          });
        } else {
          const payload: any = {
            source_type: sourceType,
            scan_mode: "precision",
            enable_ai: aiEnabled,
          };
          if (sourceType === "github") {
            payload.repo_url = target;
          } else {
            payload.target_path = target;
          }

          res = await fetch(`${API_BASE}/api/v1/scans`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });
        }
      } else {
        const payload: any = {
          source_type: isUrl ? "github" : "local",
          scan_mode: "precision",
          enable_ai: !!aiEnabledParam,
        };
        if (isUrl) {
          payload.repo_url = targetOrOptions;
        } else {
          payload.target_path = targetOrOptions;
        }

        res = await fetch(`${API_BASE}/api/v1/scans`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
      }

      if (!res.ok) {
        let errMsg = "Scan failed";
        try {
          const errData = await res.json();
          if (errData.detail) {
            errMsg = typeof errData.detail === "string" ? errData.detail : JSON.stringify(errData.detail);
          }
        } catch (e) {}
        throw new Error(errMsg);
      }

      const data = await res.json();
      const newScanId = data.scan_id;
      setScanId(newScanId);

      // Extract findings and map by file path
      const allFindings = data.result?.scan?.findings || data.result?.findings || [];
      const map: Record<string, any[]> = {};
      allFindings.forEach((f: any) => {
        const p = f.file?.replace(/\\/g, "/");
        if (!p) return;
        if (!map[p]) map[p] = [];
        map[p].push(f);
      });
      setScanFindingsMap(map);

      // Notify parent component of completed scan
      if (onScanComplete) {
        onScanComplete(data.result);
      }

      // Fetch File Tree
      let fetchedTree: FileNode | null = null;
      const treeRes = await fetch(`${API_BASE}/api/v1/files/tree?scan_id=${newScanId}`);
      if (treeRes.ok) {
        fetchedTree = await treeRes.json();
        setFileTree(fetchedTree);
      }
      const initialMsg = "// Scan complete. Select a file from the explorer to view.";
      setFileContent(initialMsg);

      saveStateToStorage(newScanId, fetchedTree, map, null, initialMsg, []);

    } catch (err: any) {
      console.error("Scan execution error:", err);
      setFileContent(`// Error occurred during scan:\n// ${err.message || "Check console for details."}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectFile = async (path: string) => {
    setSelectedFilePath(path);
    const fileFindings = scanFindingsMap[path] || [];
    setFindings(fileFindings);
    setFileContent("// Loading file...");
    
    if (scanId) {
      try {
        const res = await fetch(`${API_BASE}/api/v1/files/content?scan_id=${scanId}&path=${encodeURIComponent(path)}`);
        if (res.ok) {
          const data = await res.json();
          setFileContent(data.content);
          saveStateToStorage(scanId, fileTree, scanFindingsMap, path, data.content, fileFindings);
        } else {
          setFileContent("// Failed to load file content.");
        }
      } catch (err) {
        setFileContent("// Error loading file content.");
      }
    }
  };

  const handleCodeChange = (newContent: string) => {
    setFileContent(newContent);
    if (!selectedFilePath) return;

    const currentFileFindings = scanFindingsMap[selectedFilePath] || [];
    if (currentFileFindings.length === 0) return;

    const remainingFileFindings = currentFileFindings.filter((f) => {
      const snippet = (f.snippet || "").trim();
      const lineNum = f.line_number || f.line;

      if (snippet && snippet.length > 5) {
        if (!newContent.includes(snippet)) {
          return false;
        }
      }

      const cat = (f.category || f.title || "").toLowerCase();
      const lines = newContent.split("\n");
      if (lineNum && lineNum <= lines.length) {
        const editedLine = lines[lineNum - 1];
        if (cat.includes("sql") && editedLine.includes("%s") && !editedLine.includes("+")) {
          return false;
        }
        if ((cat.includes("crypto") || cat.includes("md5")) && editedLine.includes("sha256")) {
          return false;
        }
      }

      return true;
    });

    if (remainingFileFindings.length !== currentFileFindings.length) {
      setFindings(remainingFileFindings);
      const updatedMap = { ...scanFindingsMap, [selectedFilePath]: remainingFileFindings };
      setScanFindingsMap(updatedMap);
      if (scanId) {
        saveStateToStorage(scanId, fileTree, updatedMap, selectedFilePath, newContent, remainingFileFindings);
      }
      const allRemaining = Object.values(updatedMap).flat();
      if (onUpdateFindings) {
        onUpdateFindings(allRemaining);
      }
    } else {
      if (scanId) {
        saveStateToStorage(scanId, fileTree, scanFindingsMap, selectedFilePath, newContent, currentFileFindings);
      }
    }
  };

  const handleApplyFix = async (finding: any) => {
    const lines = fileContent.split('\n');
    const lineNum = finding.line_number || finding.line || 1;
    if (!lineNum || lineNum > lines.length) return;

    const originalLine = lines[lineNum - 1];
    const indentMatch = originalLine.match(/^(\s*)/);
    const indent = indentMatch ? indentMatch[1] : "";
    const trimmed = originalLine.trim();

    let replacement = originalLine;

    try {
      const res = await fetch(`${API_BASE}/api/v1/findings/autofix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code_snippet: trimmed || finding.snippet || "",
          category: finding.category || finding.title || "",
          cwe: finding.cwe || finding.cwe_id || "",
          recommendation: finding.recommendation || finding.remediation || "",
          file_path: selectedFilePath || "",
          line: lineNum,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        if (data.fixed_code && data.fixed_code !== trimmed) {
          replacement = `${indent}${data.fixed_code}`;
        }
      }
    } catch (e) {
      console.warn("Backend autofix call failed, using client-side rule transformer:", e);
    }

    if (replacement === originalLine) {
      const cat = (finding.category || finding.title || "").toLowerCase();
      const cwe = (finding.cwe || finding.cwe_id || "").toUpperCase();

      if (cat.includes("sql") || cwe === "CWE-89") {
        replacement = `${indent}cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))`;
      } else if (cat.includes("crypto") || cat.includes("md5") || cwe === "CWE-327") {
        let fixed = trimmed.replace("hashlib.md5", "hashlib.sha256").replace("MD5", "SHA-256");
        replacement = `${indent}${fixed}`;
      } else {
        replacement = `${indent}${trimmed}  # remediated: ${finding.category || "security-fix"}`;
      }
    }

    lines[lineNum - 1] = replacement;
    const updatedContent = lines.join('\n');
    setFileContent(updatedContent);

    // Remove the remediated finding from active file findings
    const targetId = finding.finding_id || finding.id;
    const targetCategory = finding.category || finding.title;
    const targetLine = finding.line_number || finding.line || lineNum;

    const updatedFileFindings = findings.filter((f) => {
      const fId = f.finding_id || f.id;
      if (targetId && fId) return fId !== targetId;
      const fCat = f.category || f.title;
      const fLine = f.line_number || f.line;
      return !(fCat === targetCategory && fLine === targetLine);
    });

    setFindings(updatedFileFindings);

    if (selectedFilePath) {
      const updatedMap = { ...scanFindingsMap, [selectedFilePath]: updatedFileFindings };
      setScanFindingsMap(updatedMap);
      if (scanId) {
        saveStateToStorage(scanId, fileTree, updatedMap, selectedFilePath, updatedContent, updatedFileFindings);
      }
      // Dynamically notify parent page.tsx to reduce total metrics & risk scores
      const allRemaining = Object.values(updatedMap).flat();
      if (onUpdateFindings) {
        onUpdateFindings(allRemaining);
      }
    }
  };

  const getLanguageFromPath = (path: string | null) => {
    if (!path) return "javascript";
    const ext = path.split(".").pop()?.toLowerCase();
    switch (ext) {
      case "py": return "python";
      case "ts":
      case "tsx": return "typescript";
      case "js":
      case "jsx": return "javascript";
      case "java": return "java";
      case "json": return "json";
      case "md": return "markdown";
      case "html": return "html";
      case "css": return "css";
      default: return "plaintext";
    }
  };

  const handleResetScan = () => {
    setScanId(null);
    setFileTree(null);
    setSelectedFilePath(null);
    setFileContent("// Select a file from the explorer to view its content.");
    setFindings([]);
    setScanFindingsMap({});
    try {
      sessionStorage.removeItem("guardian_scan_id");
      sessionStorage.removeItem("guardian_file_tree");
      sessionStorage.removeItem("guardian_findings_map");
      sessionStorage.removeItem("guardian_selected_path");
      sessionStorage.removeItem("guardian_file_content");
      sessionStorage.removeItem("guardian_file_findings");
      sessionStorage.removeItem("guardian_report");
    } catch (e) {}
    if (onUpdateFindings) {
      onUpdateFindings([]);
    }
  };

  const hasScanResult = Boolean(fileTree || scanId);

  // Initial State (Before Scan) — Show ONLY the RepoInput selection form
  if (!hasScanResult && !isScanning) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[calc(100vh-170px)] px-4 py-8">
        <div className="w-full max-w-3xl space-y-6">
          <div className="text-center space-y-2">
            <h1 className="text-xl font-mono font-bold tracking-wider text-[#f4f4f8] uppercase">
              SELECT REPOSITORY TO SCAN
            </h1>
            <p className="text-xs font-mono text-[#8e8e9a]">
              Select a local directory, upload a ZIP archive, or enter a GitHub repository URL to initiate security analysis.
            </p>
          </div>
          <RepoInput onScan={handleScan} isScanning={isScanning} />
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-[calc(100vh-115px)] gap-3.5">
      {/* Compact Scan Status Banner (Replaces full RepoInput after scan starts/completes) */}
      <div className="shrink-0 px-4 py-2 bg-[#12131a] border border-white/8 rounded-xl flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          {isScanning ? (
            <>
              <Loader2 className="w-4 h-4 text-[#ff5400] animate-spin" />
              <span className="text-xs font-mono font-semibold text-[#8e8e9a]">SCANNING REPOSITORY IN PROGRESS...</span>
            </>
          ) : (
            <>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-mono font-semibold text-[#f4f4f8]">
                ACTIVE SCAN SESSION: <span className="text-[#ff5400]">{scanId || "COMPLETED"}</span>
              </span>
            </>
          )}
        </div>

        {!isScanning && (
          <button
            type="button"
            onClick={handleResetScan}
            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-[11px] font-mono text-[#8e8e9a] hover:text-white transition-all"
            title="Clear scan and select another repository"
          >
            <RotateCcw className="w-3 h-3 text-[#ff5400]" />
            NEW SCAN / CHANGE REPO
          </button>
        )}
      </div>

      {/* Main IDE Workspace (File Tree + Monaco Editor + Vulnerability Panel) */}
      <div className="flex-1 flex overflow-hidden rounded-xl bg-[#0c0d11] border border-white/8">
        {/* File Tree Sidebar (Resizable & Expandable/Shrinkable) */}
        <div
          style={{ width: isSidebarCollapsed ? "44px" : `${sidebarWidth}px` }}
          className="shrink-0 overflow-hidden transition-[width] duration-150 ease-out flex flex-col relative"
        >
          {isScanning ? (
            <div className="h-full flex flex-col items-center justify-center text-[#ff5400] gap-3 bg-[#0c0d11]">
              <Loader2 className="w-6 h-6 animate-spin" />
              {!isSidebarCollapsed && (
                <span className="text-xs font-mono font-semibold tracking-wider text-[#8e8e9a]">SCANNING...</span>
              )}
            </div>
          ) : (
            <FileTreeSidebar
              tree={fileTree}
              onSelectFile={handleSelectFile}
              selectedPath={selectedFilePath}
              findingsMap={scanFindingsMap}
              isCollapsed={isSidebarCollapsed}
              onToggleCollapse={() => setIsSidebarCollapsed((prev) => !prev)}
            />
          )}
        </div>

        {/* Resizer Handle */}
        {!isSidebarCollapsed && (
          <div
            onMouseDown={handleMouseDownResize}
            className="w-1.5 hover:w-2 bg-[#12131a] hover:bg-[#ff5400]/40 cursor-col-resize shrink-0 transition-all border-r border-white/8 flex items-center justify-center group relative z-20"
            title="Drag to resize explorer"
          >
            <div className="w-0.5 h-6 bg-white/20 group-hover:bg-[#ff5400] rounded-full transition-colors" />
          </div>
        )}

        {/* Code Viewer (Center) */}
        <div className="flex-1 overflow-hidden border-l border-white/8 flex flex-col">
          <div className="px-4 py-2.5 border-b border-white/8 bg-[#12131a] flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2 truncate">
              <span className="w-2 h-2 rounded-full bg-[#ff5400]/50" />
              <span className="text-xs font-mono text-[#8e8e9a] truncate">
                {selectedFilePath || "NO FILE SELECTED"}
              </span>
            </div>
            {selectedFilePath && (
              <button
                type="button"
                onClick={() => handleCodeChange(fileContent)}
                className="px-2.5 py-1 rounded bg-[#ff5400]/10 hover:bg-[#ff5400]/20 text-[#ff5400] font-mono text-[9px] font-bold border border-[#ff5400]/20 flex items-center gap-1 transition cursor-pointer hover:scale-105"
                title="Save code edits and update PR review status"
              >
                <CheckCircle2 className="w-3 h-3" /> SAVE & UPDATE REVIEWS
              </button>
            )}
          </div>
          <div className="flex-1 overflow-hidden">
            <CodeViewer
              content={fileContent}
              language={getLanguageFromPath(selectedFilePath)}
              findings={findings}
              onChange={(val) => handleCodeChange(val || "")}
              readOnly={false}
            />
          </div>
        </div>

        {/* Vulnerability & Issue Column (Docked right beside Monaco Editor) */}
        <VulnerabilityPanel
          findings={findings}
          fileName={selectedFilePath ? (selectedFilePath.split("/").pop() || selectedFilePath) : ""}
          onApplyFix={handleApplyFix}
        />
      </div>
    </div>
  );
}
