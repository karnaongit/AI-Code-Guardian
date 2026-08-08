import { useState, useMemo } from 'react';
import {
  Folder,
  FileCode2,
  ChevronRight,
  ChevronDown,
  AlertTriangle,
  Layers,
  Braces,
  GitBranch
} from 'lucide-react';

// Fix C+F: semantically distinct icon per node type.
// Only Finding icons carry severity color. All others use their base color.
const getSevColor = (sev) => {
  switch (sev?.toLowerCase()) {
    case 'critical': return 'text-red-500';
    case 'high':     return 'text-orange-500';
    case 'medium':   return 'text-yellow-500';
    case 'low':      return 'text-blue-400';
    default:         return null;
  }
};

const getIcon = (type, maxSev) => {
  // Only Finding icon is colored by severity
  if (type === 'Finding') {
    const col = getSevColor(maxSev) || 'text-red-500';
    return <AlertTriangle className={col} size={14} />;
  }
  if (type === 'Repository') return <GitBranch className="text-blue-400" size={15} />;
  if (type === 'Folder')     return <Folder className="text-blue-400" size={15} />;
  if (type === 'File')       return <FileCode2 className="text-gray-400" size={15} />;
  if (type === 'Class')      return <Layers className="text-purple-400" size={14} />;
  if (type === 'Function')   return <Braces className="text-amber-400" size={14} />;
  return <FileCode2 className="text-gray-400" size={15} />;
};

// Helper to extract semantic children of File nodes from structure_view
const buildFileSemanticMap = (node, map = {}) => {
  if (!node) return map;
  const nodeType = node.type || node.node_type;
  if (nodeType === 'File') {
    map[node.id] = node.children || [];
  } else if (node.children) {
    node.children.forEach(child => buildFileSemanticMap(child, map));
  }
  return map;
};

function TreeNode({ node, onSelect, selectedId, fileSemanticMap, level = 0 }) {
  // nodeType must be derived before useState so the initial expansion value is correct.
  const nodeType = node?.type || node?.node_type || 'Unknown';

  // Repository and Folder auto-expand so the file list is immediately visible
  // (VS Code / IntelliJ behavior). File and semantic nodes start collapsed.
  const [expanded, setExpanded] = useState(
    nodeType === 'Repository' || nodeType === 'Folder'
  );

  if (!node) return null;

  const isSelected = selectedId === node.id;
  
  const maxSev = node.metadata?.maxSeverity || 'None';

  // Fix A: Finding uses title (human-readable), never category/rule_id.
  // Fix B: File shows basename only, not full path.
  let displayName;
  if (nodeType === 'Finding') {
    const title = node.metadata?.title;
    const category = node.metadata?.category;
    const ruleId = node.metadata?.rule_id || node.label || node.name || '';
    const isCode = (str) => !str || str === ruleId || str.startsWith('SEC-') || str.startsWith('SEC_') || str === 'CUSTOM';
    if (title && !isCode(title)) {
      displayName = title;
    } else if (node.metadata?.matched_rule && !isCode(node.metadata.matched_rule)) {
      displayName = node.metadata.matched_rule;
    } else if (node.metadata?.rule_name && !isCode(node.metadata.rule_name)) {
      displayName = node.metadata.rule_name;
    } else if (category && category !== 'Unknown') {
      displayName = category;
    } else {
      displayName = title || ruleId || nodeType;
    }
  } else if (nodeType === 'File') {
    const fullPath = node.metadata?.path || node.label || node.name || '';
    displayName = fullPath.split(/[/\\]/).pop() || fullPath;
  } else {
    displayName = node.metadata?.name || node.label || node.name || nodeType;
  }

  // Fix D: Chevron ONLY toggles. Row click selects (and also expands if not a Finding).
  // This prevents the double-toggle that occurred when both fired together.
  const handleToggle = (e) => {
    e.stopPropagation();
    setExpanded(prev => !prev);
  };

  const handleSelect = (e) => {
    e.stopPropagation();
    if (nodeType !== 'Finding') {
      setExpanded(prev => !prev);
    }
    onSelect(node);
  };

  // Fix E: text severity color ONLY on Finding nodes.
  // Ancestor nodes (File, Class, Function, Folder) keep neutral text.
  const textColorClass = nodeType === 'Finding'
    ? (getSevColor(maxSev) || 'text-red-500')
    : 'text-gray-300';

  const displayChildren = nodeType === 'File'
    ? (fileSemanticMap?.[node.id] || [])
    : (node.children || []);

  const hasChildren = nodeType !== 'Finding' && displayChildren.length > 0;

  return (
    <div className="text-sm select-none">
      <div
        className={`flex items-center py-0.5 rounded cursor-pointer ${isSelected ? 'bg-blue-900/40 border-l-2 border-blue-500' : 'hover:bg-gray-800/50'} ${textColorClass}`}
        onClick={handleSelect}
        style={{ paddingLeft: `${level * 14 + 4}px`, paddingRight: '8px' }}
      >
        {/* Chevron — toggle only, separate from row select (Fix D) */}
        <div
          className="w-4 h-4 flex justify-center items-center shrink-0 rounded text-gray-600 hover:text-gray-300 mr-1"
          onClick={handleToggle}
        >
          {hasChildren
            ? (expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />)
            : <span className="w-3 h-3 block" />}
        </div>

        <div className="mr-1.5 shrink-0 flex items-center">
          {getIcon(nodeType, maxSev)}
        </div>

        <span className={`truncate leading-5 ${isSelected ? 'text-white font-medium' : ''}`}>
          {displayName}
        </span>

        {/* Severity dot on File rows — signals a vulnerability exists without
            requiring the user to expand into semantic children */}
        {nodeType === 'File' && maxSev !== 'None' && (
          <span className={`ml-auto shrink-0 w-2 h-2 rounded-full ${
            maxSev === 'Critical' ? 'bg-red-500' :
            maxSev === 'High'     ? 'bg-orange-500' :
            maxSev === 'Medium'   ? 'bg-yellow-500' : 'bg-blue-400'
          }`} title={`${maxSev} severity finding`} />
        )}
      </div>

      {expanded && hasChildren && (
        <div>
          {displayChildren.map((child, idx) => (
            <TreeNode
              key={`${child.id}-${idx}`}
              node={child}
              onSelect={onSelect}
              selectedId={selectedId}
              fileSemanticMap={fileSemanticMap}
              level={level + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function RepositoryTree({ report, onNodeSelect, selectedNodeId }) {
  if (!report || (!report.directory_view && !report.structure_view)) {
    return (
      <div className="flex-1 flex items-center justify-center text-gray-500 p-4 text-center">
        Select or scan a repository to view its intelligence tree.
      </div>
    );
  }

  const directoryTree = useMemo(() => {
    let tree = report.directory_view || report.structure_view;
    if (Array.isArray(tree)) tree = tree[0];
    return tree;
  }, [report.directory_view, report.structure_view]);

  const fileSemanticMap = useMemo(() => {
    const map = {};
    if (!report?.structure_view) return map;

    const traverse = (node) => {
      if (!node) return;
      const type = node.type || node.node_type;
      if (type === 'File') {
        const path = node.metadata?.path || node.label || node.name || '';
        map[node.id] = node.children || [];
        if (path) {
          map[path] = node.children || [];
        }
      }
      if (node.children) {
        node.children.forEach(traverse);
      }
    };

    let root = report.structure_view;
    if (Array.isArray(root)) root = root[0];
    traverse(root);
    return map;
  }, [report.structure_view]);

  return (
    <div className="flex flex-col h-full bg-[#18181b]">
      <div className="p-3 border-b border-gray-800 bg-[#18181b] flex items-center shrink-0">
        <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-widest">Explorer</h2>
      </div>
      
      <div className="flex-1 overflow-y-auto py-2">
        {directoryTree ? (
          <TreeNode 
            node={directoryTree} 
            onSelect={onNodeSelect} 
            selectedId={selectedNodeId}
            fileSemanticMap={fileSemanticMap}
          />
        ) : (
          <div className="p-4 text-gray-500 text-sm text-center">No valid source files found.</div>
        )}
      </div>
    </div>
  );
}
