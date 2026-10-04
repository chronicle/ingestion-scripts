# Snowflake Audit Log Ingestor for Chronicle

This module ingests audit logs from Snowflake's ACCOUNT_USAGE views into **Google Chronicle**.

---

## 🔍 What It Does

- Connects to Snowflake using secure credentials
- Fetches data from key `ACCOUNT_USAGE` views like `LOGIN_HISTORY`, `QUERY_HISTORY`, and more
- Transforms and ingests logs into Chronicle using the Unstructured Ingestion API

---

## 🛠 Requirements

- Python 3.7+
- Snowflake account with access to `SNOWFLAKE.ACCOUNT_USAGE`
- GitHub Secrets:
  - `SNOWFLAKE_USER`
  - `SNOWFLAKE_PASSWORD`
  - `SNOWFLAKE_ACCOUNT`
  - `SNOWFLAKE_WAREHOUSE`
  - `SNOWFLAKE_ROLE`
  - `CHRONICLE_CUSTOMER_ID`
  - `CHRONICLE_REGION`
  - `CHRONICLE_NAMESPACE` (optional)
  - `CHRONICLE_CREDENTIALS_JSON` (base64-encoded)

---

## ⚙ GitHub Actions Workflow

Location: `.github/workflows/snowflake.yml`

This workflow:
- Runs **manually only**
- Uses secrets for Snowflake and Chronicle access
- Executes the ingestion script on demand

---

## 🧪 Running Locally

```bash
export SNOWFLAKE_USER=...
export SNOWFLAKE_PASSWORD=...
export SNOWFLAKE_ACCOUNT=...
export SNOWFLAKE_WAREHOUSE=...
export SNOWFLAKE_ROLE=...
export CHRONICLE_CUSTOMER_ID=...
export CHRONICLE_REGION=...
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/chronicle_sa.json

python main.py --creds-file /path/to/chronicle_sa.json
```

---

## 📄 Notes

- Each view is queried independently using a fixed 15-minute lookback window
- Ingested logs include a `"log_source"` field to identify the originating view
- Date/time fields are serialized to ISO format for Chronicle compatibility

---

## 🤝 Contributions

Have improvements or additional views to include? Submit a PR or open an issue!


