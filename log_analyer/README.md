# GuestProxyAgent Log Analyzer

Auto-detect potential bugs in [GuestProxyAgent](https://github.com/Azure/GuestProxyAgent) code by analyzing Kusto logs with rule-based detectors (exceptions, restarts, latency anomalies).

## Quick Start

### Local JSONL Testing

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -v
cd .\src
python -m guestproxy_analyzer.cli tests/sample_logs.jsonl
```

### Connect to Kusto (Azure Data Explorer)

#### Option A: Managed Identity (Azure VM / App Service)
```powershell
cd .\log_analyer\src
python -m guestproxy_analyzer.cli `
  --kusto-start-time "2026-03-02" `
  --kusto-end-time "2026-03-03" `
  --kusto-chunk-minutes 10 `
  --kusto-max-rows 2000 `
  --use-managed-identity
```

#### Option B: Service Principal (Local Dev)
```powershell
$env:KUSTO_CLIENT_ID = "<your-app-id>"
$env:KUSTO_CLIENT_SECRET = "<your-app-secret>"
$env:KUSTO_TENANT_ID = "<your-tenant-id>"
cd .\log_analyer\src

python -m guestproxy_analyzer.cli `
  --kusto-cluster https://mycluster.westus.kusto.windows.net `
  --kusto-db GuestProxyAgentMetrics
```

## Detectors

- **Exceptions**: Finds errors, critical logs, and stack traces
- **Restarts**: Detects service restarts or kills
- **Latency**: Flags operations exceeding 1000ms threshold

## Next Steps

- Add custom detectors for memory leaks, connection pool exhaustion, or performance regressions
- Set up ML-based anomaly detection on latency and error rate trends
- Integrate with alerting (e.g., Teams, PagerDuty)
