# AI Code Guardian 2.0

Repository-agnostic, AI-powered application security platform.
SAST · IaC scanning · dependency analysis · quantum readiness ·
business-intent detection · risk scoring — 100% local processing.

## Quick start
```bash
pip install -e .           # or: pip install pyyaml
python -m guardian scan /path/to/any/repo --format json sarif html --out-dir reports/
python -m guardian detect /path/to/repo   # repository profile only
python -m guardian intent /path/to/repo   # business-domain verdict only
```

CI gating:
```bash
python -m guardian scan . --format sarif --fail-on-severity High
```
Exit code 1 when findings at/above the threshold exist; upload the
`.sarif` to GitHub/GitLab code scanning.

## Configuration
Copy `config/default.yaml`, edit, pass with `--config`. Every analyzer is
a toggle; nothing is hardcoded to any repository.

## Dashboard
```bash
pip install .[dashboard]
streamlit run dashboard/app.py
```

## AI layer (optional — NVIDIA Nemotron)
```bash
pip install .[ai]
cp .env.example .env          # then set NVIDIA_API_KEY=nvapi-...
```
Get a key at [build.nvidia.com](https://build.nvidia.com/). Inference runs on
NVIDIA Nemotron; **embeddings run locally** (sentence-transformers) so your
repository is never bulk-uploaded. Scanning works fully without a key — the
AI layer only adds explanation, triage, and chat.

> ⚠️ Nemotron is a hosted API: code selected for analysis leaves your network.
> Secrets are redacted before transmission (`guardian/llm/guardrails.py`).

## Tests
```bash
pip install .[dev] && python -m pytest tests/ -q   # 111 tests
```

See `ARCHITECTURE.md` for the full design.
