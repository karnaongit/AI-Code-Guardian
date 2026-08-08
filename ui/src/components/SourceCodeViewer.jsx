import { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Terminal, GitCommit, FileCode } from 'lucide-react';

export default function SourceCodeViewer({ selectedNode, repoName, report }) {
  const [fileContent, setFileContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  const contentRef = useRef(null);

  // Extract relevant info from the node
  const nodeType = selectedNode?.type || selectedNode?.node_type;
  
  // Initialize variables
  let filePath = '';
  let lineNum = null;
  let findingSnippet = '';
  let executionPath = null;
  
  const findPathInStructure = (nodes, targetId, currentFilePath = null) => {
    if (!nodes) return null;
    for (const node of (Array.isArray(nodes) ? nodes : [nodes])) {
      const type = node.type || node.node_type;
      let path = currentFilePath;
      if (type === 'File') {
        path = node.metadata?.path || node.properties?.path || node.label || node.name;
      }
      
      if (node.id === targetId) {
        return path || node.metadata?.path || node.properties?.path || node.metadata?.file || node.properties?.file;
      }
      if (node.children) {
        const found = findPathInStructure(node.children, targetId, path);
        if (found) return found;
      }
    }
    return null;
  };

  if (selectedNode) {
    if (nodeType === 'File') {
      filePath = selectedNode.metadata?.path || selectedNode.properties?.path || selectedNode.label || selectedNode.name;
    } else if (nodeType === 'Finding') {
      filePath = selectedNode.metadata?.file || selectedNode.properties?.file || '';
      lineNum = selectedNode.metadata?.line || selectedNode.properties?.line;
      findingSnippet = selectedNode.metadata?.snippet || selectedNode.properties?.snippet;
      
      if (report?.execution_views && report.execution_views[selectedNode.id]) {
        executionPath = report.execution_views[selectedNode.id];
      }
    } else {
      filePath = selectedNode.metadata?.file || selectedNode.properties?.file || selectedNode.metadata?.path;
      if (!filePath && report?.structure_view) {
        // Fallback: lookup in structure_view to find where this node lives
        const foundPath = findPathInStructure(report.structure_view, selectedNode.id);
        if (foundPath) filePath = foundPath;
      }
      lineNum = selectedNode.metadata?.line || selectedNode.properties?.line;
      findingSnippet = selectedNode.metadata?.snippet || selectedNode.properties?.snippet;
    }
  }

  useEffect(() => {
    if (!filePath || !repoName) {
      setFileContent('');
      return;
    }

    const fetchFile = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await axios.post('/analysis/file', { 
          repo_name: repoName, 
          file_path: filePath 
        });
        setFileContent(response.data.content);
      } catch (err) {
        console.error("Failed to fetch file:", err);
        setError("Failed to load source code.");
      } finally {
        setLoading(false);
      }
    };

    fetchFile();
  }, [filePath, repoName]);

  // Scroll to line if provided
  useEffect(() => {
    if (lineNum && contentRef.current) {
      const lineElement = contentRef.current.querySelector(`[data-line="${lineNum}"]`);
      if (lineElement) {
        lineElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
  }, [fileContent, lineNum]);

  if (!selectedNode) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center text-gray-500 bg-[#1e1e1e]">
        <Terminal size={48} className="mb-4 opacity-20" />
        <p>Select a file, function, or finding in the intelligence tree.</p>
      </div>
    );
  }

  const lines = fileContent ? fileContent.split('\n') : [];

  const renderExecutionPath = (node) => {
    if (!node) return null;
    return (
      <div className="ml-4 pl-4 border-l-2 border-gray-700 relative">
        <div className="absolute -left-[9px] top-1 w-4 h-4 rounded-full bg-gray-800 border-2 border-gray-600 flex items-center justify-center">
          <GitCommit size={10} className="text-gray-400" />
        </div>
        <div className="py-1">
          <span className="text-xs text-gray-400 uppercase font-bold mr-2">{node.type}</span>
          <span className="text-sm font-mono text-gray-200">{node.label}</span>
        </div>
        {node.children && node.children.length > 0 && (
          <div>
            {node.children.map((child, idx) => (
              <div key={idx}>{renderExecutionPath(child)}</div>
            ))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-[#1e1e1e] overflow-hidden">
      {/* Header Tabs */}
      <div className="flex items-center h-10 bg-[#2d2d2d] border-b border-gray-900 px-2 shrink-0 justify-between">
        <div className="flex items-center gap-2 px-4 py-2 bg-[#1e1e1e] border-t-2 border-blue-500 text-sm text-gray-300">
          <FileCode size={14} className="text-blue-400" />
          <span className="font-mono">{filePath || selectedNode.label || selectedNode.name}</span>
        </div>
        {nodeType === 'Finding' && report && (
          <button 
            onClick={() => window.dispatchEvent(new CustomEvent('open-investigation'))}
            className="mr-2 px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded flex items-center gap-1 transition-colors shadow-sm"
          >
            Investigate with AI
          </button>
        )}
      </div>

      <div className="flex-1 flex overflow-hidden">
        
        {/* Source Code Area */}
        <div className="flex-1 overflow-auto" ref={contentRef}>
          {loading ? (
            <div className="p-8 text-gray-500 font-mono text-sm">Loading source code...</div>
          ) : error ? (
            <div className="p-8 text-red-400 font-mono text-sm">{error}</div>
          ) : fileContent ? (
            <div className="py-4">
              {lines.map((lineText, i) => {
                const currentLineNum = i + 1;
                const isVulnerable = lineNum === currentLineNum;
                // Basic matching for snippet if lineNum is missing
                const isSnippetMatch = !lineNum && findingSnippet && lineText.includes(findingSnippet.split('\n')[0]);
                const highlight = isVulnerable || isSnippetMatch;
                
                return (
                  <div 
                    key={i} 
                    data-line={currentLineNum}
                    className={`flex text-sm font-mono whitespace-pre hover:bg-gray-800/50 ${highlight ? 'bg-red-900/30' : ''}`}
                  >
                    <div className={`w-12 shrink-0 text-right pr-4 select-none ${highlight ? 'text-red-400 border-r-2 border-red-500' : 'text-gray-600 border-r border-gray-800'}`}>
                      {currentLineNum}
                    </div>
                    <div className={`pl-4 ${highlight ? 'text-red-200' : 'text-gray-300'}`}>
                      {lineText || ' '}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="p-8 text-gray-500 font-mono text-sm">
              No source code available for this node.
              {findingSnippet && (
                <div className="mt-4 p-4 bg-gray-900 rounded border border-gray-800 text-gray-300 whitespace-pre-wrap">
                  <div className="text-xs text-gray-500 mb-2 uppercase">Snippet</div>
                  {findingSnippet}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Execution Path Area (if applicable) */}
        {executionPath && (
          <div className="w-1/3 bg-[#252526] border-l border-gray-800 flex flex-col shrink-0">
            <div className="p-3 border-b border-gray-800 bg-[#2d2d2d] text-xs font-semibold text-gray-400 uppercase tracking-wider">
              Execution Path
            </div>
            <div className="flex-1 overflow-auto p-4">
              {renderExecutionPath(executionPath)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
