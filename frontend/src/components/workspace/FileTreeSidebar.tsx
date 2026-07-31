"use client";

import React, { useState } from "react";
import { ChevronRight, ChevronDown, File, Folder, ShieldAlert, ShieldX, ShieldCheck, Shield } from "lucide-react";

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
}

const getSeverityIcon = (severity: string | null | undefined, count: number = 0) => {
  if (!severity || count === 0) return null;
  switch (severity.toUpperCase()) {
    case "CRITICAL": return <ShieldAlert className="w-3.5 h-3.5 text-red-500 shrink-0" />;
    case "HIGH": return <ShieldX className="w-3.5 h-3.5 text-orange-500 shrink-0" />;
    case "MEDIUM": return <Shield className="w-3.5 h-3.5 text-yellow-500 shrink-0" />;
    case "LOW": return <ShieldCheck className="w-3.5 h-3.5 text-blue-400 shrink-0" />;
    default: return <Shield className="w-3.5 h-3.5 text-slate-400 shrink-0" />;
  }
};

const TreeNode = ({ node, level = 0, onSelectFile, selectedPath }: { node: FileNode, level?: number, onSelectFile: (path: string) => void, selectedPath?: string | null }) => {
  const [isOpen, setIsOpen] = useState(true);
  const isSelected = selectedPath === node.path && node.type === "file";

  const handleToggle = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (node.type === "directory") {
      setIsOpen(!isOpen);
    } else {
      onSelectFile(node.path);
    }
  };

  return (
    <div>
      <div
        className={`flex items-center py-1.5 px-2 hover:bg-white/10 cursor-pointer rounded-sm group ${isSelected ? "glass-card text-indigo-300 border border-indigo-500/30" : "text-slate-300"}`}
        style={{ paddingLeft: `${level * 12 + 8}px` }}
        onClick={handleToggle}
      >
        <span className="w-4 h-4 mr-1 shrink-0 flex items-center justify-center">
          {node.type === "directory" && (
            isOpen ? <ChevronDown className="w-3.5 h-3.5 text-slate-500" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
          )}
        </span>
        
        <span className="mr-2 shrink-0">
          {node.type === "directory" ? (
            <Folder className={`w-4 h-4 ${node.has_vulnerabilities ? "text-red-400" : "text-indigo-400"}`} />
          ) : (
            <File className={`w-4 h-4 ${node.has_vulnerabilities ? "text-red-400" : "text-slate-400"}`} />
          )}
        </span>
        
        <span className="truncate text-sm mr-2 flex-1 group-hover:text-white transition-colors">{node.name}</span>
        
        {node.has_vulnerabilities && node.vulnerability_count! > 0 && (
          <div className="flex items-center gap-1.5 shrink-0 glass-panel px-1.5 py-0.5 rounded-full">
            {getSeverityIcon(node.max_severity, node.vulnerability_count)}
            <span className="text-[10px] font-medium font-mono text-slate-300">{node.vulnerability_count}</span>
          </div>
        )}
      </div>

      {node.type === "directory" && isOpen && node.children && (
        <div>
          {node.children.map((child, i) => (
            <TreeNode key={`${child.path}-${i}`} node={child} level={level + 1} onSelectFile={onSelectFile} selectedPath={selectedPath} />
          ))}
        </div>
      )}
    </div>
  );
};

export default function FileTreeSidebar({ tree, onSelectFile, selectedPath }: FileTreeSidebarProps) {
  if (!tree) {
    return (
      <div className="h-full flex items-center justify-center text-slate-500 glass-panel border-r border-white/10 p-4 text-center">
        <p className="text-sm">Run a scan to view the repository file tree.</p>
      </div>
    );
  }

  return (
    <div className="h-full glass-panel border-r border-white/10 flex flex-col overflow-hidden">
      <div className="p-3 border-b border-white/10 glass-card">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Explorer</h3>
      </div>
      <div className="flex-1 overflow-y-auto py-2">
        <TreeNode node={tree} onSelectFile={onSelectFile} selectedPath={selectedPath} />
      </div>
    </div>
  );
}
