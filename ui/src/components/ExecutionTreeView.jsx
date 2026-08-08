import React, { useState, useMemo } from 'react';
import { ChevronRight, ChevronDown, FileCode, AlertTriangle, ArrowRight, Server, Code2, Layers } from 'lucide-react';

const getIcon = (type, isDanger) => {
  const nodeType = type?.toLowerCase();
  if (nodeType === 'finding') return <AlertTriangle className="text-red-500 w-4 h-4 shrink-0" />;
  if (nodeType === 'file') return <FileCode className={isDanger ? "text-red-400 w-4 h-4 shrink-0" : "text-blue-400 w-4 h-4 shrink-0"} />;
  if (nodeType === 'class') return <Layers className={isDanger ? "text-purple-400 w-4 h-4 shrink-0" : "text-purple-500 w-4 h-4 shrink-0"} />;
  if (nodeType === 'function') return <Code2 className={isDanger ? "text-amber-400 w-4 h-4 shrink-0" : "text-amber-500 w-4 h-4 shrink-0"} />;
  if (nodeType === 'call') return <ArrowRight className={isDanger ? "text-green-400 w-4 h-4 shrink-0" : "text-green-500 w-4 h-4 shrink-0"} />;
  return <Code2 className="text-gray-400 w-4 h-4 shrink-0" />;
};

const ExecutionTreeNode = ({ node, level = 0, onNodeSelect, defaultExpanded = false, isPathToFinding = false }) => {
  const [expanded, setExpanded] = useState(defaultExpanded || level === 0 || isPathToFinding);
  
  if (!node) return null;
  
  const isLeaf = !node.children || node.children.length === 0;
  const isFinding = node.type === 'Finding' || node.node_type === 'Finding';

  const handleToggle = (e) => {
    e.stopPropagation();
    setExpanded(!expanded);
  };

  const handleSelect = (e) => {
    e.stopPropagation();
    onNodeSelect(node); // Pass complete node object!
    if (!isLeaf && !isFinding) {
      setExpanded(!expanded);
    }
  };

  let name = node.label || node.name;
  if (isFinding) {
    const title = node.metadata?.title;
    const category = node.metadata?.category;
    const ruleId = node.metadata?.rule_id || node.label || node.name || '';
    const isCode = (str) => !str || str === ruleId || str.startsWith('SEC-') || str.startsWith('SEC_') || str === 'CUSTOM';
    
    if (title && !isCode(title)) {
      name = title;
    } else if (node.metadata?.matched_rule && !isCode(node.metadata.matched_rule)) {
      name = node.metadata.matched_rule;
    } else if (node.metadata?.rule_name && !isCode(node.metadata.rule_name)) {
      name = node.metadata.rule_name;
    } else if (category && category !== 'Unknown') {
      name = category;
    } else {
      name = title || ruleId || type;
    }
  }

  const type = node.node_type || node.type;

  // Visual cues: Red for finding or paths that eventually reach a finding
  const isDanger = isFinding || isPathToFinding;

  return (
    <div className="font-mono text-sm select-none">
      <div 
        className={`flex items-center py-2 cursor-pointer hover:bg-gray-800/50 rounded transition-colors ${isDanger ? 'text-red-400 font-semibold bg-red-950/10' : 'text-gray-300'}`}
        onClick={handleSelect}
        style={{ paddingLeft: `${level * 24 + 8}px`, paddingRight: '8px' }}
      >
        <div className="w-6 flex justify-center items-center shrink-0 text-gray-500 hover:text-gray-300" onClick={handleToggle}>
          {!isLeaf ? (expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />) : <span className="w-4" />}
        </div>
        
        <div className="mr-3 shrink-0 flex items-center">
          {getIcon(type, isDanger)}
        </div>
        
        <div className="flex-1 truncate flex items-center gap-2">
          <span className="truncate text-[15px]">{name}</span>
          {isFinding && <span className="text-[10px] uppercase tracking-wider text-red-500 border border-red-900/50 bg-red-900/20 px-1.5 py-0.5 rounded-sm shrink-0">VULNERABILITY</span>}
          {!isFinding && type && type !== 'File' && <span className="text-[9px] uppercase tracking-wider text-gray-500 border border-gray-850 px-1 py-0.2 rounded-sm shrink-0 font-sans">{type}</span>}
        </div>
      </div>
      
      {/* Children elements */}
      {expanded && !isLeaf && (
        <div className="relative">
          {/* Vertical guide line */}
          <div className={`absolute left-0 top-0 bottom-0 w-px ${isDanger ? 'bg-red-900/30' : 'bg-gray-850'}`} style={{ marginLeft: `${level * 24 + 19}px` }} />
          {node.children.map((child, idx) => {
             const childLeadsToFinding = (function hasFinding(n) {
                if (!n) return false;
                if (n.type === 'Finding' || n.node_type === 'Finding') return true;
                if (n.children && n.children.length > 0) {
                  return n.children.some(hasFinding);
                }
                return false;
             })(child);
             
             return (
              <ExecutionTreeNode 
                key={`${child.id || child.node_id}-${idx}`} 
                node={child} 
                level={level + 1} 
                onNodeSelect={onNodeSelect}
                defaultExpanded={defaultExpanded}
                isPathToFinding={childLeadsToFinding}
              />
            )
          })}
        </div>
      )}
    </div>
  );
};

export default function ExecutionTreeView({ report, selectedNode, onNodeSelect, selectedEntryPointId }) {
  const executionTree = useMemo(() => {
    if (!report) return null;

    const type = selectedNode?.type || selectedNode?.node_type;
    
    if (selectedNode && type === 'Finding') {
      const findingId = selectedNode.id || selectedNode.node_id || selectedNode.finding_id;
      if (report.execution_views && report.execution_views[findingId]) {
        return report.execution_views[findingId];
      }
    }
    
    if (selectedEntryPointId && report.global_execution_views) {
        return report.global_execution_views[selectedEntryPointId];
    }
    
    return null;

  }, [report, selectedNode, selectedEntryPointId]);

  if (!executionTree || Object.keys(executionTree).length === 0) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center text-gray-500 bg-[#1e1e1e] p-8 text-center space-y-4">
        <ArrowRight className="w-12 h-12 text-gray-700" />
        <div>
          <h3 className="text-lg font-medium text-gray-300 mb-2">Global Execution Tree</h3>
          <p className="max-w-md">
            No execution paths or vulnerabilities found in this repository.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-[#1e1e1e]">
      <div className="p-3 border-b border-gray-800 flex items-center justify-between shrink-0 bg-[#252526]">
        <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-widest flex items-center gap-2">
          <Server size={14} /> Execution Tree Trace
        </h2>
      </div>
      <div className="flex-1 overflow-y-auto py-4 px-2 bg-[#1e1e1e]">
        <ExecutionTreeNode 
          node={executionTree} 
          onNodeSelect={onNodeSelect} 
          defaultExpanded={true} 
          isPathToFinding={(function hasFinding(n) {
               if (!n) return false;
               if (n.type === 'Finding' || n.node_type === 'Finding') return true;
               if (n.children && n.children.length > 0) {
                 return n.children.some(hasFinding);
               }
               return false;
          })(executionTree)}
        />
      </div>
    </div>
  );
}
