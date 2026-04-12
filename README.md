# CWE Secure Insight Web App

A secure, read-only web application that analyzes the provided CWE datasets:
- `data/677.xml` as the primary catalog (Weakness Base Elements)
- `data/1435.xml` as the official 2025 Top 25 overlay

The application computes a **derived prioritization score** for each security-relevant CWE by analyzing structured attributes from the XML, then displays the results through a small web application.

## Security goals built into the code
- Safe XML parsing with `defusedxml`
- Read-only local data loading from fixed application paths
- No hard-coded credentials, API keys, or secrets
- Strict validation and whitelisting for query parameters
- Server-rendered templates with auto-escaping
- Security response headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Debug mode disabled by default
- Excludes quality-only / prohibited-mapping entries from default analysis

## Scoring model
Each security-relevant CWE gets a derived score out of 100 using these attributes when present:
- Likelihood of exploit
- Common consequences
- Applicable platforms / prevalence
- Detection method effectiveness
- Potential mitigation effectiveness or absence of clear mitigations
- Relationship density (related weaknesses, CAPEC links)
- Real-world evidence (observed examples)
- Introduction breadth (architecture, design, implementation, operations, testing)
- Top 25 membership bonus

This is a **prioritization heuristic**, not an official MITRE severity rating.

## Quick start

### Local
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m app.cli build-index --input data/677.xml --top25 data/1435.xml --output output/cwe_index.json
python run.py
```

Open:
- http://127.0.0.1:8000/
- http://127.0.0.1:8000/rankings
- http://127.0.0.1:8000/summary

### Docker
```bash
docker build -t cwe-secure-insight .
docker run --rm -p 8000:8000 cwe-secure-insight
```

## Useful screenshots for the report appendix
- Home dashboard
- Rankings page
- One CWE detail page
- Summary JSON at `/summary`
- Terminal output from the `build-index` command

## CLI
Build the index:
```bash
python -m app.cli build-index --input data/677.xml --top25 data/1435.xml --output output/cwe_index.json
```
