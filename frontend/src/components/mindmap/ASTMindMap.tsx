"use client";

import React, { useEffect, useState } from "react";
import CodeMindMap from "./CodeMindMap";
import { MindMapData } from "./types";
import { Loader2, AlertCircle } from "lucide-react";

interface ASTMindMapProps {
  scanId?: string | null;
  fallbackData?: MindMapData;
}

export const ASTMindMap: React.FC<ASTMindMapProps> = ({ scanId, fallbackData = { nodes: [], edges: [] } }) => {
  const [astData, setAstData] = useState<MindMapData | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) {
      setAstData(null);
      return;
    }

    let isMounted = true;
    setIsLoading(true);
    setError(null);

    fetch(`http://localhost:8000/api/v1/files/ast?scan_id=${encodeURIComponent(scanId)}&max_depth=3`)
      .then(async (res) => {
        if (!res.ok) {
          throw new Error(`AST API error: ${res.statusText}`);
        }
        return res.json();
      })
      .then((data: MindMapData) => {
        if (isMounted) {
          if (data && Array.isArray(data.nodes) && data.nodes.length > 0) {
            setAstData(data);
          } else {
            setAstData(null);
          }
        }
      })
      .catch((err) => {
        if (isMounted) {
          console.warn("Could not fetch AST from backend, falling back to local mindmap data:", err);
          setError("Using local file tree mind map (Backend AST endpoint unavailable).");
          setAstData(null);
        }
      })
      .finally(() => {
        if (isMounted) {
          setIsLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [scanId]);

  if (isLoading) {
    return (
      <div className="w-full h-[650px] glass-panel rounded-2xl flex flex-col items-center justify-center text-blue-400 gap-3 border border-slate-800">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
        <span className="text-sm font-semibold tracking-wide text-slate-300">
          Transforming Backend AST & Building React Flow Mind Map...
        </span>
      </div>
    );
  }

  const finalData = astData && astData.nodes && astData.nodes.length > 0 ? astData : fallbackData;

  return (
    <div className="w-full flex flex-col gap-2">
      {error && (
        <div className="px-4 py-2 bg-amber-500/10 border border-amber-500/20 rounded-lg flex items-center gap-2 text-xs text-amber-400">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
      <CodeMindMap data={finalData} isLoading={false} />
    </div>
  );
};

export default ASTMindMap;
