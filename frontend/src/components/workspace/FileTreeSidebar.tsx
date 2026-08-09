"use client";

import React, { useState } from "react";
import {
  ChevronRight,
  ChevronDown,
  File,
  Folder,
  ShieldAlert,
  ShieldX,
  ShieldCheck,
  Shield,
  PanelLeftClose,
  PanelLeftOpen,
  AlertTriangle,
  Bug,
} from "lucide-react";

export interface FileNode {
  name: string;
  path: string;
  type: "file" | "directory";
  children?: FileNode[];
  has_vulnerabilities?: boolean;
  vulnerability_count?: number;
  max_severity?: string | null;
}

interface FileTreeSidebarProps {
  tree: FileNode | null;
  onSelectFile: (path: string) => void;
  selectedPath?: string | null;
  findingsMap?: Record<string, any[]>;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
}

const getSeverityIcon = (severity: string | null | undefined, count: number = 0) => {
  if (!severity || count === 0) return null;
  switch (severity.toUpperCase()) {
    case "CRITICAL": return <ShieldAlert className="w-3 h-3 text-red-400 shrink-0" />;
    case "HIGH":     return <ShieldX     className="w-3 h-3 text-[#ff5400] shrink-0" />;
    case "MEDIUM":   return <Shield      className="w-3 h-3 text-yellow-400 shrink-0" />;
    case "LOW":      return <ShieldCheck className="w-3 h-3 text-emerald-400 shrink-0" />;
    default:         return <Shield      className="w-3 h-3 text-[#8e8e9a] shrink-0" />;
  }
};

const getNodeFindings = (node: FileNode, map?: Record<string, any[]>): any[] => {
  if (!map) return [];
  if (node.type === "file") {
    const norm = node.path.replace(/\\/g, "/");
    return map[norm] || map[node.path] || [];
  }
  let acc: any[] = [];
  if (node.children) {
    for (const child of node.children) {
      acc = acc.concat(getNodeFindings(child, map));
    }
  }
  return acc;
};

const TreeNode = ({
  node,
  level = 0,
  onSelectFile,
  selectedPath,
  findingsMap,
}: {
  node: FileNode;
  level?: number;
  onSelectFile: (path: string) => void;
  selectedPath?: string | null;
  findingsMap?: Record<string, any[]>;
}) => {
  const [isOpen, setIsOpen] = useState(true);
  const isSelected = selectedPath === node.path && node.type === "file";
  const nodeFindings = getNodeFindings(node, findingsMap);
  const totalCount = nodeFindings.length || node.vulnerability_count || 0;

  const handleToggle = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (node.type === "directory") {
      setIsOpen(!isOpen);
    } else {
      onSelectFile(node.path);
    }
  };

  return (
    <div className="relative group/treeitem">
      <div
        className={`flex items-center py-1.5 px-2 cursor-pointer rounded-sm group transition-colors relative ${
          isSelected
            ? "bg-[#ff5400]/12 text-[#ff5400] border-l-2 border-l-[#ff5400]"
            : "text-[#8e8e9a] hover:bg-white/6 hover:text-[#f4f4f8]"
        }`}
        style={{ paddingLeft: `${level * 12 + 8}px` }}
        onClick={handleToggle}
      >
        <span className="w-4 h-4 mr-1 shrink-0 flex items-center justify-center">
          {node.type === "directory" && (
            isOpen
              ? <ChevronDown  className="w-3 h-3 text-[#8e8e9a]" />
              : <ChevronRight className="w-3 h-3 text-[#8e8e9a]" />
          )}
        </span>

        <span className="mr-2 shrink-0">
          {node.type === "directory" ? (
            <Folder className={`w-3.5 h-3.5 ${totalCount > 0 ? "text-[#ff5400]" : "text-[#8e8e9a]"}`} />
          ) : (
            <File className={`w-3.5 h-3.5 ${totalCount > 0 ? "text-[#ff5400]" : "text-[#8e8e9a]"}`} />
          )}
        </span>

        <span className="truncate text-xs mr-2 flex-1 font-mono group-hover:text-[#f4f4f8] transition-colors">
          {node.name}
        </span>

        {totalCount > 0 && (
          <div className="flex items-center gap-1 shrink-0 bg-[#0c0d11] px-1.5 py-0.5 rounded border border-white/10 group-hover:border-[#ff5400]/40 transition-colors">
            {getSeverityIcon(node.max_severity || (nodeFindings[0]?.severity), totalCount)}
            <span className="text-[9px] font-mono font-bold text-[#ff5400]">{totalCount}</span>
          </div>
        )}
      </div>

      {/* ── Hover Vulnerability Card ─────────────────────────────── */}
      {totalCount > 0 && (
        <div className="hidden group-hover/treeitem:block absolute left-full top-0 ml-2 z-50 w-72 p-3 bg-[#12131a]/95 backdrop-blur-md border border-[#ff5400]/30 rounded-xl shadow-[0_10px_30px_rgba(0,0,0,0.8)] pointer-events-none animate-in fade-in-0 zoom-in-95 duration-150">
          <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-2">
            <div className="flex items-center gap-1.5 font-mono text-[11px] font-bold text-[#f4f4f8]">
              <Bug className="w-3.5 h-3.5 text-[#ff5400]" />
              <span className="truncate max-w-[160px]">{node.name}</span>
            </div>
            <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 font-mono text-[10px] font-bold border border-red-500/30">
              {totalCount} {totalCount === 1 ? "Issue" : "Issues"}
            </span>
          </div>

          <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
            {nodeFindings.slice(0, 3).map((f: any, idx: number) => {
              const sevUpper = (f.severity || "HIGH").toUpperCase();
              const sevColor = sevUpper === "CRITICAL" ? "text-red-400 bg-red-500/10 border-red-500/20"
                : sevUpper === "HIGH" ? "text-[#ff5400] bg-[#ff5400]/10 border-[#ff5400]/20"
                : "text-amber-400 bg-amber-500/10 border-amber-500/20";
              return (
                <div key={idx} className="p-2 rounded bg-white/4 border border-white/6 space-y-1 text-[10px] font-mono">
                  <div className="flex items-center justify-between text-[#f4f4f8] font-bold">
                    <span className="text-[#f4f4f8] truncate max-w-[160px]">{f.category || f.title || "Vulnerability"}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[8px] border font-bold ${sevColor}`}>
                      {f.severity || "HIGH"}
                    </span>
                  </div>
                  <div className="text-[#8e8e9a] text-[9px] flex items-center justify-between">
                    <span>{f.cwe || f.cwe_id || "OWASP"}</span>
                    {f.line && <span className="text-[#ff5400]">Line {f.line}</span>}
                  </div>
                  <p className="text-[#8e8e9a] text-[9px] line-clamp-2 leading-tight">
                    {f.reason || f.recommendation || f.snippet || "Identified security vulnerability."}
                  </p>
                </div>
              );
            })}
            {totalCount > 3 && (
              <div className="text-[9px] font-mono text-[#8e8e9a] text-center pt-1">
                +{totalCount - 3} more vulnerabilities in this item
              </div>
            )}
          </div>
        </div>
      )}

      {/* Render directory children */}
      {node.type === "directory" && isOpen && node.children && (
        <div>
          {node.children.map((child, i) => (
            <TreeNode
              key={`${child.path}-${i}`}
              node={child}
              level={level + 1}
              onSelectFile={onSelectFile}
              selectedPath={selectedPath}
              findingsMap={findingsMap}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export default function FileTreeSidebar({
  tree,
  onSelectFile,
  selectedPath,
  findingsMap,
  isCollapsed = false,
  onToggleCollapse,
}: FileTreeSidebarProps) {
  if (isCollapsed) {
    return (
      <div className="h-full bg-[#0c0d11] border-r border-white/8 flex flex-col items-center py-3 gap-4">
        <button
          onClick={onToggleCollapse}
          className="p-1.5 rounded-lg text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/8 transition-colors"
          title="Expand Explorer Sidebar"
        >
          <PanelLeftOpen className="w-4 h-4 text-[#ff5400]" />
        </button>
        <div className="rotate-90 text-[9px] font-mono font-bold tracking-[0.25em] text-[#8e8e9a] uppercase mt-4 whitespace-nowrap">
          EXPLORER
        </div>
      </div>
    );
  }

  if (!tree) {
    return (
      <div className="h-full flex flex-col bg-[#0c0d11] border-r border-white/8">
        <div className="p-2.5 border-b border-white/8 bg-[#12131a] flex items-center justify-between">
          <h3 className="text-[10px] font-mono font-semibold text-[#8e8e9a] uppercase tracking-[0.2em]">
            EXPLORER
          </h3>
          {onToggleCollapse && (
            <button
              onClick={onToggleCollapse}
              className="p-1 rounded text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/8 transition-colors"
              title="Shrink Explorer Sidebar"
            >
              <PanelLeftClose className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
        <div className="flex-1 flex items-center justify-center p-4 text-center">
          <p className="text-xs font-mono text-[#8e8e9a]">Run a scan to view the repository file tree.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full bg-[#0c0d11] border-r border-white/8 flex flex-col overflow-hidden">
      <div className="p-2.5 border-b border-white/8 bg-[#12131a] flex items-center justify-between shrink-0">
        <h3 className="text-[10px] font-mono font-semibold text-[#8e8e9a] uppercase tracking-[0.2em] flex items-center gap-2">
          <Folder className="w-3.5 h-3.5 text-[#ff5400]" />
          EXPLORER
        </h3>
        {onToggleCollapse && (
          <button
            onClick={onToggleCollapse}
            className="p-1 rounded text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/8 transition-colors"
            title="Shrink / Collapse Explorer Sidebar"
          >
            <PanelLeftClose className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
      <div className="flex-1 overflow-y-auto py-2">
        <TreeNode
          node={tree}
          onSelectFile={onSelectFile}
          selectedPath={selectedPath}
          findingsMap={findingsMap}
        />
      </div>
    </div>
  );
}
