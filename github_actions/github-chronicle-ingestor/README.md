# GitHub Audit Log Ingestor for Chronicle

This module ingests GitHub audit logs into **Google Chronicle** using the Unstructured Ingestion API.

---

## 🔍 What It Does

- Fetches GitHub organization audit logs using the GitHub REST API
- Tracks last run timestamp to avoid duplicate ingestion
- Sends logs to Chronicle for security analysis and correlation
- Supports GitHub Actions automation or local execution

---

## 🛠 Requirements

- Python 3.7+
- GitHub Actions enabled
- Required GitHub Secrets:
  - `GITHUB_AUDIT_TOKEN`
  - `GITHUB_AUDIT_URL` (e.g., `https://api.github.com/orgs/myorg/audit-log`)
  - `CHRONICLE_CUSTOMER_ID`
  - `CHRONICLE_REGION`
  - `CHRONICLE_NAMESPACE` (optional)
  - `CHRONICLE_CREDENTIALS_JSON` (base64-encoded Chronicle SA key)

---

## ⚙ GitHub Actions Workflow

Location: `.github/workflows/github.yml`

This workflow:
- Runs **manually only**
- Installs dependencies
- Writes Chronicle credentials
- Executes the GitHub ingestion script

---

## 🧪 Running Locally

```bash
export GITHUB_AUDIT_TOKEN=...
export GITHUB_AUDIT_URL=https://api.github.com/orgs/myorg/audit-log
export CHRONICLE_CUSTOMER_ID=...
export CHRONICLE_REGION=...
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/chronicle_sa.json

python main.py --creds-file /path/to/chronicle_sa.json
```

---

## 📄 Notes

- Script stores a local `.github_audit_last_run.json` file to track last successful ingestion
- Fetches only events from the last run (default: 24 hours ago if no file exists)
- Use cases include tracking repository, team, and user-level events for security monitoring

---

## 🤝 Contributions

Feel free to open an issue or submit a PR to improve the ingestor!

