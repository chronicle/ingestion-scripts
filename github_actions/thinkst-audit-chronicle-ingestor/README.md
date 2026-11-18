# Thinkst Canary Audit Log Ingestor for Chronicle

This module ingests audit logs from **Thinkst Canary** into **Google Chronicle** using the Unstructured Ingestion API.

---

## 🔍 What It Does

- Fetches audit trail logs from a Thinkst Canary Console
- Filters events since the last successful run
- Sends logs to Chronicle for detection and investigation
- Tracks ingestion history using a local timestamp file

---

## 🛠 Requirements

- Python 3.7+
- Valid Thinkst Canary API credentials
- GitHub Secrets:
  - `CANARY_CONSOLE_ID`
  - `CANARY_AUTH_TOKEN`
  - `CHRONICLE_CUSTOMER_ID`
  - `CHRONICLE_REGION`
  - `CHRONICLE_NAMESPACE` (optional)
  - `CHRONICLE_CREDENTIALS_JSON` (base64-encoded)

---

## ⚙ GitHub Actions Workflow

Location: `.github/workflows/thinkst-canary.yml`

This workflow:
- Is **manual-only**
- Uses GitHub secrets to authenticate to Thinkst and Chronicle
- Calls the script to ingest new audit logs on demand

---

## 🧪 Running Locally

```bash
export CANARY_CONSOLE_ID=your-console-id
export CANARY_AUTH_TOKEN=your-auth-token
export CHRONICLE_CUSTOMER_ID=...
export CHRONICLE_REGION=...
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/chronicle_sa.json

python main.py --creds-file /path/to/chronicle_sa.json
```

---

## 📄 Notes

- Uses `.canary_last_run.json` to avoid duplicate ingestion
- Date format must match `"%Y-%m-%d %H:%M:%S UTC+0000"` expected by Thinkst
- Designed for Thinkst customers that want centralized log correlation in Chronicle

---

## 🤝 Contributions

Have a feature request or bug fix? Open a pull request or issue!


