"use client";

import React, { useState } from "react";
import {
  ChevronRight,
  ChevronDown,
  Folder,
  FolderOpen,
  FileCode,
  ShieldAlert,
  ShieldX,
  AlertTriangle,
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
}

/* Helper to get file risk badge styling */
const getFileRiskStyle = (severity?: string | null, count: number = 0) => {
  if (!severity || count === 0) return { bg: "", text: "text-[#94A3B8]", icon: null };
  const s = severity.toUpperCase();
  if (s === "CRITICAL") {
    return {
      bg: "bg-red-500/15 hover:bg-red-500/20 text-red-300 border-l-2 border-red-500 font-semibold",
      text: "text-red-300 font-semibold",
      icon: <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />,
    };
  }
  if (s === "HIGH") {
    return {
      bg: "bg-orange-500/15 hover:bg-orange-500/20 text-orange-300 border-l-2 border-orange-500 font-semibold",
      text: "text-orange-300 font-semibold",
      icon: <ShieldX className="w-3.5 h-3.5 text-orange-400 shrink-0" />,
    };
  }
  if (s === "MEDIUM") {
    return {
      bg: "bg-amber-500/10 hover:bg-amber-500/15 text-amber-300 border-l-2 border-amber-500",
      text: "text-amber-300",
      icon: <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />,
    };
  }
  return { bg: "", text: "text-[#94A3B8]", icon: null };
};

const TreeNode = ({
  node,
  level = 0,
  onSelectFile,
  selectedPath,
}: {
  node: FileNode;
  level?: number;
  onSelectFile: (path: string) => void;
  selectedPath?: string | null;
}) => {
  const [isOpen, setIsOpen] = useState(true);
  const isSelected = selectedPath === node.path && node.type === "file";
  const riskStyle = getFileRiskStyle(node.max_severity, node.vulnerability_count || 0);

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
        className={`flex items-center py-1.5 px-2 cursor-pointer select-none rounded-md transition-all duration-150 my-0.5 ${
          isSelected
            ? "bg-[#1E293B] text-white border-l-2 border-[#FF5E1E] shadow-sm"
            : riskStyle.bg || "hover:bg-white/5 text-[#94A3B8] hover:text-white"
        }`}
        style={{ paddingLeft: `${level * 14 + 10}px` }}
        onClick={handleToggle}
      >
        {/* Chevron for directories */}
        <span className="w-4 h-4 mr-1 shrink-0 flex items-center justify-center">
          {node.type === "directory" && (
            isOpen ? (
              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
            )
          )}
        </span>

        {/* Directory or File Icon */}
        <span className="mr-2 shrink-0">
          {node.type === "directory" ? (
            isOpen ? (
              <FolderOpen className="w-4 h-4 text-[#E2E8F0]" />
            ) : (
              <Folder className="w-4 h-4 text-[#94A3B8]" />
            )
          ) : (
            riskStyle.icon || <FileCode className="w-4 h-4 text-slate-400" />
          )}
        </span>

        {/* File / Folder Name */}
        <span className={`truncate text-[12px] font-mono flex-1 ${riskStyle.text}`}>
          {node.name}
        </span>
      </div>

      {node.type === "directory" && isOpen && node.children && (
        <div>
          {node.children.map((child, i) => (
            <TreeNode
              key={`${child.path}-${i}`}
              node={child}
              level={level + 1}
              onSelectFile={onSelectFile}
              selectedPath={selectedPath}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export default function FileTreeSidebar({ tree, onSelectFile, selectedPath }: FileTreeSidebarProps) {
  if (!tree) {
    return (
      <div className="h-full flex flex-col items-center justify-center bg-[#111726] p-4 text-center">
        <p className="text-xs font-mono text-slate-400">Run a scan to view the file tree.</p>
      </div>
    );
  }

  return (
    <div className="h-full bg-[#111726] flex flex-col overflow-hidden">
      {/* File Explorer Header */}
      <div className="px-4 py-3 border-b border-slate-800/80 bg-[#090D16] flex items-center justify-between">
        <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-300">
          File Explorer
        </span>
        <span className="text-[10px] font-mono text-slate-500">Risk Sorted</span>
      </div>

      {/* Directory Tree */}
      <div className="flex-1 overflow-y-auto p-2" style={{ scrollbarWidth: "thin", scrollbarColor: "rgba(148,163,184,0.15) transparent" }}>
        <TreeNode node={tree} onSelectFile={onSelectFile} selectedPath={selectedPath} />
      </div>
    </div>
  );
}
