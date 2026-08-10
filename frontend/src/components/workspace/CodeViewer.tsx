"use client";

import React, { useRef, useEffect } from "react";
import Editor, { useMonaco } from "@monaco-editor/react";
import { Loader2 } from "lucide-react";

interface CodeViewerProps {
  content: string;
  language?: string;
  findings?: any[];
  onChange?: (value: string | undefined) => void;
  readOnly?: boolean;
}

const getSecureCodeFix = (finding: any): string => {
  if (finding.fixed_code) return finding.fixed_code.trim();

  const snippet = (finding.snippet || finding.code_snippet || "").trim();
  const cat = (finding.category || finding.title || "").toLowerCase();
  const cwe = (finding.cwe || finding.cwe_id || "").toUpperCase();

  if (snippet) {
    if (cat.includes("sql") || cwe === "CWE-89") {
      if (snippet.includes("+")) {
        const fixed = snippet.replace(/execute\s*\(\s*(["\'].*?)(?:\s*\+\s*)([a-zA-Z0-9_.]+)(?:\s*\))?/i, 'execute($1%s", ($2,))');
        if (fixed !== snippet) return fixed;
      }
      return 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))';
    }

    if (cat.includes("crypto") || cat.includes("md5") || cat.includes("sha1") || cwe === "CWE-327") {
      let fixed = snippet.replace(/hashlib\.md5/gi, "hashlib.sha256")
                        .replace(/hashlib\.sha1/gi, "hashlib.sha256")
                        .replace(/MD5/gi, "SHA-256");
      if (fixed !== snippet) return fixed;
    }

    if (cat.includes("tls") || cat.includes("ssl") || cat.includes("verify") || cwe === "CWE-295") {
      let fixed = snippet.replace(/verify\s*=\s*False/gi, "verify=True")
                        .replace(/_create_unverified_context/gi, "create_default_context");
      if (fixed !== snippet) return fixed;
    }

    if (cat.includes("secret") || cat.includes("password") || cwe === "CWE-798") {
      const match = snippet.match(/^([a-zA-Z0-9_]+)\s*=\s*["\'].*?["\']/);
      if (match) {
        const varName = match[1];
        return `${varName} = os.getenv("${varName.toUpperCase()}", "")`;
      }
    }

    if (cat.includes("random") || cwe === "CWE-330") {
      let fixed = snippet.replace(/random\.random\(\)/gi, "secrets.token_hex(16)")
                        .replace(/random\.randint/gi, "secrets.randbelow");
      if (fixed !== snippet) return fixed;
    }
  }

  // Fallbacks
  if (cat.includes("sql") || cwe === "CWE-89") return 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))';
  if (cat.includes("crypto") || cwe === "CWE-327") return 'cipher = hashlib.sha256(secret_key.encode()).hexdigest()';
  if (cat.includes("secret") || cwe === "CWE-798") return 'SECRET_KEY = os.getenv("SECRET_KEY", "")';
  if (cat.includes("tls") || cwe === "CWE-295") return 'requests.get(url, verify=True)';
  if (cat.includes("random") || cwe === "CWE-330") return 'token = secrets.randbelow(9000) + 1000';

  return (finding.recommendation || finding.remediation || "Follow security best practices").split("\n")[0];
};

export default function CodeViewer({ content, language = "javascript", findings = [], onChange, readOnly = false }: CodeViewerProps) {
  const monaco = useMonaco();
  const editorRef = useRef<any>(null);
  const decorationsRef = useRef<string[]>([]);

  useEffect(() => {
    if (monaco && editorRef.current) {
      const editor = editorRef.current;
      const model = editor.getModel();
      if (!model) return;

      // Disable squiggly markers completely (no squiggly lines!)
      monaco.editor.setModelMarkers(model, "vulnerabilities", []);

      // Render Code Coverage line highlighting, scrollbar markers & inline secure replacement code
      const newDecorations = findings.map((f) => {
        const targetLine = Math.min(model.getLineCount(), Math.max(1, f.line || f.line_number || 1));
        const fixedCode = getSecureCodeFix(f);

        return {
          range: new monaco.Range(targetLine, 1, targetLine, model.getLineMaxColumn(targetLine)),
          options: {
            isWholeLine: true,
            className: "monaco-vulnerable-line-coverage",
            linesDecorationsClassName: "monaco-vulnerable-gutter-marker",
            overviewRuler: {
              color: "#ff5400",
              position: monaco.editor.OverviewRulerLane.Full,
            },
            after: {
              content: `   💡 REPLACEMENT CODE: ${fixedCode}`,
              inlineClassName: "monaco-inline-fix-banner",
            },
          },
        };
      });

      decorationsRef.current = editor.deltaDecorations(decorationsRef.current, newDecorations);

      // Automatically reveal and center the vulnerability line in Monaco Editor viewport
      if (findings.length > 0) {
        const firstFinding = findings[0];
        const targetLine = Math.min(model.getLineCount(), Math.max(1, firstFinding.line || firstFinding.line_number || 1));
        
        setTimeout(() => {
          try {
            editor.revealLineInCenter(targetLine);
            editor.setPosition({ lineNumber: targetLine, column: 1 });
          } catch (e) {}
        }, 50);
      }
    }
  }, [monaco, findings, content]);

  return (
    <div className="h-full w-full bg-[#1e1e1e] flex flex-col relative">
      {/* Code Coverage & Inline Fix CSS overrides for Monaco Editor */}
      <style jsx global>{`
        .monaco-vulnerable-line-coverage {
          background-color: rgba(239, 68, 68, 0.22) !important;
          border-left: 3px solid #ff5400 !important;
        }
        .monaco-vulnerable-gutter-marker {
          background: #ff5400 !important;
          width: 4px !important;
          margin-left: 2px !important;
        }
        .monaco-inline-fix-banner {
          color: #34d399 !important;
          font-family: 'JetBrains Mono', 'Fira Code', monospace !important;
          font-size: 11px !important;
          font-weight: 600 !important;
          background-color: rgba(6, 78, 59, 0.6) !important;
          border: 1px solid rgba(52, 211, 153, 0.4) !important;
          padding: 2px 8px !important;
          border-radius: 4px !important;
          margin-left: 12px !important;
          display: inline-block !important;
        }
      `}</style>

      <div className="flex-1 overflow-hidden relative">
        <Editor
          height="100%"
          language={language}
          theme="vs-dark"
          value={content}
          onChange={onChange}
          options={{
            readOnly: readOnly,
            minimap: { enabled: true },
            scrollBeyondLastLine: false,
            fontSize: 14,
            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
            wordWrap: "on",
            renderWhitespace: "selection",
            glyphMargin: true,
            overviewRulerLanes: 3,
            overviewRulerBorder: true,
          }}
          onMount={(editor) => {
            editorRef.current = editor;
          }}
          loading={
            <div className="flex items-center justify-center h-full text-slate-400">
              <Loader2 className="w-6 h-6 animate-spin mr-2" />
              Loading editor...
            </div>
          }
        />
      </div>
    </div>
  );
}
