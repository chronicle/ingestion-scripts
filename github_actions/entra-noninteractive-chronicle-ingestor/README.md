# Microsoft Entra Non-Interactive Sign-In Ingestor

This module is a custom Python-based ingestion script designed to forward non-interactive sign-in events from **Microsoft Entra ID** (formerly Azure AD) into **Google Chronicle** using the Unstructured Ingestion API.

---

## 🔍 What It Does

- Authenticates to Microsoft Graph API (Beta)
- Fetches **non-interactive sign-in events** (e.g., service principal or daemon access)
- Parses, normalizes, and forwards logs to Chronicle
- Executes via GitHub Actions on a scheduled or manual basis

> 🔎 **Note:** Chronicle currently provides native ingestion only for **interactive** Entra sign-ins. This script fills a critical visibility gap for service-based or daemon-based sign-ins, improving auditability and detection coverage.

---

## 📂 Included Script

### `main.py`

This script:
- Retrieves an OAuth2 token using Microsoft client credentials
- Queries Microsoft Graph Beta API for sign-ins filtered by `signInEventTypes eq 'nonInteractiveUser'`
- Uses `common/ingest.py` to send the data to Chronicle’s Unstructured Ingestion API

---

## 🛠 Requirements

- Python 3.7+
- GitHub repository with GitHub Actions enabled
- Microsoft Graph API access via:
  - `GRAPH_TENANT_ID`
  - `GRAPH_CLIENT_ID`
  - `GRAPH_CLIENT_SECRET`
- Chronicle access:
  - `CHRONICLE_CUSTOMER_ID`
  - `CHRONICLE_REGION`
  - `CHRONICLE_NAMESPACE` (optional)
  - `CHRONICLE_CREDENTIALS_JSON` (Base64-encoded service account JSON)

---

## 🔐 GitHub Secrets

Store these values in your GitHub repository’s **Secrets**:

- `GRAPH_CLIENT_ID`
- `GRAPH_CLIENT_SECRET`
- `GRAPH_TENANT_ID`
- `CHRONICLE_CUSTOMER_ID`
- `CHRONICLE_REGION`
- `CHRONICLE_NAMESPACE`
- `CHRONICLE_CREDENTIALS_JSON`

These variables are referenced in both the ingestion script and GitHub Actions workflow.

---

## ⚙ GitHub Actions Workflow

The repo includes a GitHub Actions workflow at:

```
.github/workflows/entra.yml
```

This workflow:
- Installs dependencies
- Decodes the Chronicle credentials
- Runs the Entra ingestion script

It runs:
- **Every 15 minutes** via `cron`
- **Manually** via `workflow_dispatch`

---

## 🧪 Running Locally

To test locally, export your environment variables and run:

```bash
export GRAPH_CLIENT_ID=...
export GRAPH_CLIENT_SECRET=...
export GRAPH_TENANT_ID=...
export CHRONICLE_CUSTOMER_ID=...
export CHRONICLE_REGION=...
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/chronicle_sa.json

python main.py --creds-file /path/to/chronicle_sa.json
```

---

## 📄 Notes

- Uses the **Microsoft Graph Beta API** — subject to schema changes
- The default filter fetches only **non-interactive** sign-in events
- Intended for users who need deeper visibility into Entra usage beyond native Chronicle coverage

---

## 🤝 Contributions

Want to enhance this module or add support for other Entra sign-in types? Open a PR or submit an issue!
