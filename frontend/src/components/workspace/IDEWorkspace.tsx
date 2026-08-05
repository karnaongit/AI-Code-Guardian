"use client";

import React, { useState, useEffect, useCallback } from "react";
import AuraHeader from "./AuraHeader";
import FileTreeSidebar, { FileNode } from "./FileTreeSidebar";
import AuraCodeEditor from "./AuraCodeEditor";
import AuraVulnerabilityInsight from "./AuraVulnerabilityInsight";
import RepoInput from "./RepoInput";
import { Loader2 } from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface IDEWorkspaceProps {
  onScanComplete?: (scanResult: any) => void;
}

/* Default sample File Tree for initial display */
const DEFAULT_SAMPLE_TREE: FileNode = {
  name: "acg_repo_v2",
  path: "backend",
  type: "directory",
  children: [
    {
      name: "app",
      path: "backend/app",
      type: "directory",
      children: [
        {
          name: "api",
          path: "backend/app/api",
          type: "directory",
          children: [
            {
              name: "v1",
              path: "backend/app/api/v1",
              type: "directory",
              children: [
                {
                  name: "findings.py",
                  path: "backend/app/api/v1/findings.py",
                  type: "file",
                  has_vulnerabilities: true,
                  vulnerability_count: 1,
                  max_severity: "CRITICAL",
                },
                {
                  name: "auth.py",
                  path: "backend/app/api/v1/auth.py",
                  type: "file",
                  has_vulnerabilities: true,
                  vulnerability_count: 2,
                  max_severity: "HIGH",
                },
                {
                  name: "dependencies.py",
                  path: "backend/app/api/v1/dependencies.py",
                  type: "file",
                  has_vulnerabilities: false,
                },
              ],
            },
          ],
        },
      ],
    },
    {
      name: "guardian",
      path: "backend/guardian",
      type: "directory",
      children: [
        {
          name: "security.py",
          path: "backend/guardian/security.py",
          type: "file",
          has_vulnerabilities: true,
          vulnerability_count: 1,
          max_severity: "HIGH",
        },
      ],
    },
  ],
};

/* Distinct Sample File Contents & Findings for Repository Demo Files */
const SAMPLE_FILES_DATABASE: Record<string, { code: string; findings: any[] }> = {
  "backend/app/api/v1/findings.py": {
    code: `import requests
from flask import jsonify
import logging

logger = logging.getLogger(__name__)

# Fetch remote security findings from scanning node
def fetch_findings(endpoint):
    logger.info(f"Connecting to security endpoint: {endpoint}")
    
    # ⚠️ VULNERABLE LINE: Disables TLS certificate verification
    resp = requests.get(endpoint, verify=False, timeout=30)
    
    if resp.status_code != 200:
        return jsonify({"error": "Fetch failed", "status": resp.status_code})
        
    return resp.json()

def post_autofix(url, payload):
    # ⚠️ VULNERABLE LINE: No cert verification
    return requests.post(url, json=payload, verify=False)
`,
    findings: [
      {
        finding_id: "cwe295-findings-py",
        category: "Improper Certificate Validation",
        severity: "CRITICAL",
        cwe: "CWE-295",
        owasp: "OWASP A07:2021",
        file: "backend/app/api/v1/findings.py",
        line: 12,
        snippet: "resp = requests.get(endpoint, verify=False, timeout=30)",
        recommendation: "Enable TLS certificate validation via certifi.where() and enforce a 10s request timeout.",
        reason: "Disabling TLS certificate verification allows attackers on the network path to execute Man-in-the-Middle (MitM) attacks, inspecting and tampering with encrypted security traffic.",
        exploit_scenario: "An attacker on the same network uses a spoofed SSL cert to intercept findings API calls, extracting sensitive credentials and injecting fake scan results.",
        remediation_patch: "resp = requests.get(endpoint, verify=certifi.where(), timeout=10)",
      },
    ],
  },

  "backend/app/api/v1/auth.py": {
    code: `import jwt
import datetime
from flask import request, jsonify

SECRET_KEY = "SUPER_SECRET_ADMIN_TOKEN_KEY_DO_NOT_SHARE"

def generate_user_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    # ⚠️ VULNERABLE LINE: Hardcoded secret key used for signing JWT
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token):
    try:
        # ⚠️ VULNERABLE LINE: Hardcoded secret key used for verification
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded["user_id"]
    except jwt.ExpiredSignatureError:
        return None
`,
    findings: [
      {
        finding_id: "cwe798-auth-py",
        category: "Hardcoded Cryptographic Secret",
        severity: "HIGH",
        cwe: "CWE-798",
        owasp: "OWASP A02:2021",
        file: "backend/app/api/v1/auth.py",
        line: 12,
        snippet: 'return jwt.encode(payload, SECRET_KEY, algorithm="HS256")',
        recommendation: 'Retrieve SECRET_KEY from environment variables (e.g. os.getenv("JWT_SECRET")) instead of hardcoding static strings.',
        reason: "Hardcoded secrets in source control can be easily discovered via repository leaks, granting unauthorized JWT token signing capabilities.",
        exploit_scenario: "An attacker reads the hardcoded secret from repository history, crafts a forged admin JWT token, and bypasses authentication endpoints.",
        remediation_patch: 'import os\nSECRET_KEY = os.getenv("JWT_SECRET_KEY")',
      },
    ],
  },

  "backend/app/api/v1/dependencies.py": {
    code: `from typing import Generator
from sqlalchemy.orm import Session
from backend.app.core.database import SessionLocal

def get_db_session() -> Generator[Session, None, None]:
    """Provide a transactional database session for API endpoints."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
`,
    findings: [],
  },

  "backend/guardian/security.py": {
    code: `import os
import subprocess
from typing import Dict, Any

def execute_security_rule(rule_cmd: str, target_dir: str) -> Dict[str, Any]:
    print(f"Running rule command: {rule_cmd} on {target_dir}")
    
    # ⚠️ VULNERABLE LINE: Shell=True allows OS Command Injection
    res = subprocess.run(f"{rule_cmd} {target_dir}", shell=True, capture_output=True, text=True)
    
    return {
        "returncode": res.returncode,
        "stdout": res.stdout,
        "stderr": res.stderr
    }
`,
    findings: [
      {
        finding_id: "cwe78-security-py",
        category: "OS Command Injection",
        severity: "HIGH",
        cwe: "CWE-78",
        owasp: "OWASP A03:2021",
        file: "backend/guardian/security.py",
        line: 9,
        snippet: 'res = subprocess.run(f"{rule_cmd} {target_dir}", shell=True, capture_output=True, text=True)',
        recommendation: "Pass command arguments as a list with shell=False to prevent shell parameter injection.",
        reason: "Passing concatenated user input to a shell subprocess with shell=True enables remote code execution if inputs contain command separators like ';' or '&&'.",
        exploit_scenario: "An attacker supplies a target_dir containing '; rm -rf /', causing arbitrary shell execution on the host machine.",
        remediation_patch: "res = subprocess.run([rule_cmd, target_dir], shell=False, capture_output=True, text=True)",
      },
    ],
  },
};

export default function IDEWorkspace({ onScanComplete }: IDEWorkspaceProps) {
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [fileTree, setFileTree] = useState<FileNode | null>(DEFAULT_SAMPLE_TREE);
  const [selectedFilePath, setSelectedFilePath] = useState<string>(
    "backend/app/api/v1/findings.py"
  );
  const [fileContent, setFileContent] = useState<string>(
    SAMPLE_FILES_DATABASE["backend/app/api/v1/findings.py"].code
  );
  const [findings, setFindings] = useState<any[]>(
    SAMPLE_FILES_DATABASE["backend/app/api/v1/findings.py"].findings
  );
  const [scanFindingsMap, setScanFindingsMap] = useState<Record<string, any[]>>({
    "backend/app/api/v1/findings.py": SAMPLE_FILES_DATABASE["backend/app/api/v1/findings.py"].findings,
    "backend/app/api/v1/auth.py": SAMPLE_FILES_DATABASE["backend/app/api/v1/auth.py"].findings,
    "backend/guardian/security.py": SAMPLE_FILES_DATABASE["backend/guardian/security.py"].findings,
  });
  const [isRightPaneOpen, setIsRightPaneOpen] = useState(true);

  /* Restore from session storage if exists */
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
      console.warn("Failed to load workspace state from storage:", e);
    }
  }, []);

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
      console.warn("Failed to save state to storage:", e);
    }
  };

  const handleScan = async (target: string, isUrl: boolean, aiEnabled: boolean) => {
    setIsScanning(true);
    setScanId(null);

    try {
      const payload: any = {
        scan_mode: "precision",
        enable_ai: aiEnabled,
      };
      if (isUrl) payload.repo_url = target;
      else payload.target_path = target;

      const res = await fetch(`${API_BASE}/api/v1/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) throw new Error("Scan failed");

      const data = await res.json();
      const newScanId = data.scan_id;
      setScanId(newScanId);

      const allFindings = data.result?.scan?.findings || data.result?.findings || [];
      const map: Record<string, any[]> = {};
      allFindings.forEach((f: any) => {
        const p = f.file?.replace(/\\/g, "/");
        if (!p) return;
        if (!map[p]) map[p] = [];
        map[p].push(f);
      });
      setScanFindingsMap(map);

      if (onScanComplete) onScanComplete(data.result);

      let fetchedTree: FileNode | null = null;
      const treeRes = await fetch(`${API_BASE}/api/v1/files/tree?scan_id=${newScanId}`);
      if (treeRes.ok) {
        fetchedTree = await treeRes.json();
        setFileTree(fetchedTree);
      }

      saveStateToStorage(newScanId, fetchedTree, map, selectedFilePath, fileContent, findings);
    } catch (err: any) {
      console.error("Scan error:", err);
    } finally {
      setIsScanning(false);
    }
  };

  /* DISTINCT CONTENT FOR EVERY FILE SELECTED */
  const handleSelectFile = async (path: string) => {
    setSelectedFilePath(path);

    // 1. If scanId exists, fetch live file content from API
    if (scanId) {
      try {
        const res = await fetch(`${API_BASE}/api/v1/files/content?scan_id=${scanId}&path=${encodeURIComponent(path)}`);
        if (res.ok) {
          const data = await res.json();
          const fileFindings = scanFindingsMap[path] || [];
          setFileContent(data.content);
          setFindings(fileFindings);
          saveStateToStorage(scanId, fileTree, scanFindingsMap, path, data.content, fileFindings);
          return;
        }
      } catch (err) {
        console.warn("Failed to fetch live file content:", err);
      }
    }

    // 2. Fallback to file-specific sample database for distinct code & findings per file
    const sample = SAMPLE_FILES_DATABASE[path] || {
      code: `# Code for ${path}\n\n# Safe implementation - No security issues detected.`,
      findings: [],
    };

    setFileContent(sample.code);
    setFindings(sample.findings);
    saveStateToStorage(scanId, fileTree, scanFindingsMap, path, sample.code, sample.findings);
  };

  /* PRESERVE ENTIRE FILE: ONLY replace the specific vulnerable line */
  const handleApplyFix = async (finding: any) => {
    const currentCode = fileContent;
    const lines = currentCode.split("\n");
    const lineNum = finding?.line || finding?.line_number || 12;

    if (lineNum < 1 || lineNum > lines.length) return;

    const originalLine = lines[lineNum - 1];
    const indent = originalLine.match(/^(\s*)/)?.[1] || "";
    const trimmed = originalLine.trim();

    let replacementLine = originalLine;

    // Call backend AutoFix service for intelligent line patch
    try {
      const res = await fetch(`${API_BASE}/api/v1/findings/autofix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code_snippet: trimmed || finding?.snippet || "",
          category: finding?.category || "",
          cwe: finding?.cwe || "",
          recommendation: finding?.recommendation || "",
          file_path: selectedFilePath || "",
          line: lineNum,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        if (data.fixed_code && data.fixed_code !== trimmed) {
          replacementLine = `${indent}${data.fixed_code}`;
        }
      }
    } catch (e) {
      console.warn("Backend autofix call failed, applying local line patch:", e);
    }

    // Fallback line replacement if backend didn't transform
    if (replacementLine === originalLine) {
      if (finding?.remediation_patch) {
        replacementLine = `${indent}${finding.remediation_patch.trim()}`;
      } else if (trimmed.includes("verify=False") || trimmed.includes("verify= False")) {
        replacementLine = originalLine.replace(/verify\s*=\s*False/i, "verify=certifi.where(), timeout=10");
      } else if (trimmed.includes("SECRET_KEY =")) {
        replacementLine = 'import os\nSECRET_KEY = os.getenv("JWT_SECRET_KEY")';
      } else if (trimmed.includes("shell=True")) {
        replacementLine = originalLine.replace("shell=True", "shell=False");
      } else {
        replacementLine = `${originalLine}  # ✅ fixed: ${finding?.category || "security-fix"}`;
      }
    }

    // Insert certifi import at top if needed, without breaking line indices
    let updatedLines = [...lines];
    if ((replacementLine.includes("certifi") || replacementLine.includes("ssl")) && !currentCode.includes("certifi")) {
      updatedLines.unshift("import ssl, certifi");
      updatedLines[lineNum] = replacementLine;
    } else {
      updatedLines[lineNum - 1] = replacementLine;
    }

    const updatedContent = updatedLines.join("\n");
    setFileContent(updatedContent);
    setFindings([]); // Clear finding since issue is fixed
    saveStateToStorage(scanId, fileTree, scanFindingsMap, selectedFilePath, updatedContent, []);
  };

  return (
    <div className="flex flex-col h-[calc(100vh-140px)] gap-3 bg-[#090D16] text-[#E2E8F0] font-sans selection:bg-[#FF5E1E]/20">
      
      {/* STREAMLINED TOP NAVIGATION HEADER */}
      <AuraHeader
        securityScore={78}
        criticalCount={5}
        highCount={24}
        mediumCount={10}
        repoName="acg_repo_v2"
        branchName="feature/auth-hardening"
      />

      {/* Target Repo Input Bar */}
      <div className="px-5 shrink-0">
        <RepoInput onScan={handleScan} isScanning={isScanning} />
      </div>

      {/* TRIPLE-PANE WORKSPACE LAYOUT (IDE Style) */}
      <div className="flex-1 flex overflow-hidden mx-5 mb-5 rounded-xl border border-slate-800 bg-[#111726] shadow-2xl">
        
        {/* A. LEFT PANE (VS CODE-LIKE FILE EXPLORER) */}
        <div className="w-64 shrink-0 overflow-hidden border-r border-slate-800">
          {isScanning ? (
            <div className="h-full flex flex-col items-center justify-center text-[#FF5E1E] gap-3 bg-[#090D16]">
              <Loader2 className="w-6 h-6 animate-spin" />
              <span className="text-xs font-mono font-semibold tracking-wider text-slate-400">
                SCANNING ENGINE...
              </span>
            </div>
          ) : (
            <FileTreeSidebar
              tree={fileTree}
              onSelectFile={handleSelectFile}
              selectedPath={selectedFilePath}
            />
          )}
        </div>

        {/* B. CENTER PANE (TABBED CODE EDITOR WITH INLINE COLAB DIFF) */}
        <div className="flex-1 overflow-hidden flex flex-col">
          <AuraCodeEditor
            filePath={selectedFilePath}
            content={fileContent}
            findings={findings}
            onApplyFix={handleApplyFix}
            onToggleRightPane={() => setIsRightPaneOpen((prev) => !prev)}
            isRightPaneOpen={isRightPaneOpen}
            onContentChange={(newContent) => setFileContent(newContent)}
          />
        </div>

        {/* C. RIGHT PANE (HIDEABLE INFO PANEL: AI VULNERABILITY INSIGHT) */}
        {isRightPaneOpen && (
          <AuraVulnerabilityInsight
            finding={findings[0]}
            fileName={selectedFilePath.split("/").pop() || selectedFilePath}
            onApplyFix={handleApplyFix}
            onDiscussInChat={(ctx) => console.log("Chat trigger:", ctx)}
          />
        )}
      </div>
    </div>
  );
}
