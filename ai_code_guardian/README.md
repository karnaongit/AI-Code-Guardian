# AI Code Guardian

AI-powered static security analysis with business-intent-aware risk scoring,
per the Master Design Document architecture.

## Structure
```
ai_code_guardian/
├── core/
│   ├── models.py              # Finding / ScanResult data model (UAST-ready)
│   ├── security_rule_engine.py # Python (AST+taint) & Java (regex-bridge) detectors
│   └── risk_scoring.py        # Day-7 Composite Risk Score formula
├── dashboard/
│   └── app.py                 # Streamlit dashboard (Day 8)
├── tests/
│   └── test_security_rule_engine.py
├── data/
│   └── Security_Rules.json    # Rule catalog (recommendations per category)
└── main.py                    # CLI: python main.py scan <path>
```

## Quickstart
```bash
pip install -r requirements.txt
python main.py scan ./my_project --out report.json
streamlit run dashboard/app.py
```

## What's implemented
- Python: real `ast`-module parsing with per-function taint tracking
  (source -> sink, sanitiser-aware) for SQL Injection, Command Injection,
  Insecure Deserialization, plus entropy-gated Hardcoded Secret detection.
- Java: regex bridge (pending full Tree-sitter UAST wiring) covering SQL
  Injection, XSS, Hardcoded Secret, Weak Crypto, Broken Authentication,
  Path Traversal, Sensitive Logging — with Shannon-entropy filtering
  (threshold 2.8) and a self-reference guard so constants like
  `SMTP_PASSWORD = "SMTP_PASSWORD"` aren't flagged as secrets.
- Stable SHA-1 `finding_id` for incremental-scan deduplication.
- Risk Scoring Engine implementing the CRS / Risk_PR / Overall_Risk formula
  and the Merge Approval Logic decision table from the design doc.
- Streamlit dashboard: scan trigger, severity/category charts, findings
  table, merge-decision banner.

## What's still a stub (next milestones)
- Tree-sitter UAST wiring for Java (currently regex bridge).
- Business Intent module (BERT alignment, NER acceptance-criteria
  extraction) — `alignment_score` is currently a manual/CLI input.
- Quantum Vulnerability Detector (RSA/ECC/DH inventory + PQC mapping).
- GitHub/GitLab webhook + Checks API integration.
- Live CVSS/EPSS feeds for the Risk Scorer (currently severity-derived defaults).

Validated against apache/fineract (5,286 Java files): correctly suppresses
the constant-name false positives seen in the naive regex version while
still catching the real `X509TrustManager`/`trustAllCerts` TLS-bypass
findings with full Severity -> Risk Score -> Merge Decision traceability.
