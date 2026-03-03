import json
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

try:
    from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
    from azure.identity import (
        DefaultAzureCredential,
        ClientSecretCredential,
        ManagedIdentityCredential,
        DeviceCodeCredential,
        ChainedTokenCredential,
    )
    _KUSTO_AVAILABLE = True
except Exception:
    _KUSTO_AVAILABLE = False


def build_guest_proxy_agent_query(
    hours: int = 24,
    table: str = "GuestProxyAgentLogs",
    version: str = None,
    max_rows: int = 2000,
    start_time: str = None,
    end_time: str = None,
) -> str:
    """Build a Kusto query to fetch GuestProxyAgent logs with exceptions and errors.
    
    Args:
        hours: Look back this many hours
        table: Log table name (often 'GuestProxyAgentLogs' or similar in your cluster)
        version: GuestProxyAgent version (optional)
        max_rows: Maximum rows to return (limits memory and payload)
        start_time: Optional ISO datetime (inclusive), e.g. 2026-02-24T00:00:00Z
        end_time: Optional ISO datetime (exclusive), e.g. 2026-02-24T06:00:00Z
    Returns:
        KQL query string
    """
    def _kql_str(value: str) -> str:
        return value.replace('"', '\\"')

    version_filter = ""
    if version:
        version_filter = f'| where tostring(column_ifexists("GAVersion", "")) startswith "{version}"\n'

    if start_time or end_time:
        start_clause = f'_ts >= todatetime("{_kql_str(start_time)}")' if start_time else "true"
        end_clause = f'_ts < todatetime("{_kql_str(end_time)}")' if end_time else "true"
        time_filter = f"| where isnotnull(_ts) and {start_clause} and {end_clause}"
    else:
        time_filter = f"| where isnotnull(_ts) and _ts >= ago({hours}h)"

    return f"""
{table}
| extend _ts=coalesce(todatetime(column_ifexists("TIMESTAMP", datetime(null))), todatetime(column_ifexists("Timestamp", datetime(null))))
{time_filter}
| where tostring(column_ifexists("ExecutionMode", "")) == "ProxyAgent"
{version_filter}| project _ts,
          GAVersion=tostring(column_ifexists("GAVersion", "")),
          Region=tostring(column_ifexists("Region", "")),
          Cluster=tostring(column_ifexists("Cluster", "")),
          CapabilityUsed=tostring(column_ifexists("CapabilityUsed", "")),
          Context1=tostring(column_ifexists("Context1", "")),
          Context2=tostring(column_ifexists("Context2", "")),
          Context3=tostring(column_ifexists("Context3", "")),
          TaskName=tostring(column_ifexists("TaskName", "")),
          RawMessage=tostring(column_ifexists("Message", ""))
| take {max_rows}
| extend PreciseTimeStamp=coalesce(todatetime(Context2), _ts),
         ProxyAgentVersion=GAVersion,
         Message=coalesce(Context1, RawMessage),
         module_name=Context3,
         task=TaskName,
         Level=CapabilityUsed,
         responseStatus=tostring(parse_json(coalesce(Context1, RawMessage)).responseStatus)
| where not(task == "log_connection_summary" and responseStatus == "200 OK")
| project PreciseTimeStamp, ProxyAgentVersion, Region, Cluster, Level, module_name, task, Message
| order by PreciseTimeStamp desc
"""


def _parse_iso8601(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fetch_kusto_logs_in_chunks(
    cluster: str,
    database: str,
    table: str,
    chunk_minutes: int,
    client_id: str = None,
    client_secret: str = None,
    authority_id: str = None,
    use_managed_identity: bool = False,
    hours: int = 24,
    version: str = None,
    max_rows: int = 2000,
    start_time: str = None,
    end_time: str = None,
) -> List[Dict[str, Any]]:
    """Fetch Kusto logs in time chunks to reduce query memory/transport failures."""
    if chunk_minutes <= 0:
        raise ValueError("chunk_minutes must be > 0")

    if start_time or end_time:
        range_start = _parse_iso8601(start_time) if start_time else (_parse_iso8601(end_time) - timedelta(hours=hours))
        range_end = _parse_iso8601(end_time) if end_time else datetime.now(timezone.utc)
    else:
        range_end = datetime.now(timezone.utc)
        range_start = range_end - timedelta(hours=hours)

    if range_start >= range_end:
        raise ValueError("start_time must be earlier than end_time")

    step = timedelta(minutes=chunk_minutes)
    all_rows: List[Dict[str, Any]] = []
    cursor = range_start

    while cursor < range_end:
        chunk_end = min(cursor + step, range_end)
        query = build_guest_proxy_agent_query(
            table=table,
            version=version,
            max_rows=max_rows,
            start_time=cursor.isoformat().replace("+00:00", "Z"),
            end_time=chunk_end.isoformat().replace("+00:00", "Z"),
        )
        chunk_rows = fetch_kusto_logs(
            cluster=cluster,
            database=database,
            query=query,
            client_id=client_id,
            client_secret=client_secret,
            authority_id=authority_id,
            use_managed_identity=use_managed_identity,
        )
        all_rows.extend(chunk_rows)
        print(f"Fetched {len(chunk_rows)} rows from {cursor.isoformat()} to {chunk_end.isoformat()}")
        cursor = chunk_end

    return all_rows


def fetch_kusto_logs(
    cluster: str,
    database: str,
    query: str,
    client_id: str = None,
    client_secret: str = None,
    authority_id: str = None,
    use_managed_identity: bool = False
) -> List[Dict[str, Any]]:
    """Fetch logs from Azure Data Explorer (Kusto).
    
    Authentication priority:
    1. Managed Identity (if use_managed_identity=True, or running in Azure VM/App Service)
    2. Client credentials (client_id, client_secret, authority_id)
    3. DefaultAzureCredential (looks for AZURE_* env vars, CLI auth, etc.)
    
    Args:
        cluster: Kusto cluster URL (e.g., 'https://mycluster.westus.kusto.windows.net')
        database: Database name
        query: KQL query string
        client_id: Azure AD app client ID (optional)
        client_secret: Azure AD app client secret (optional)
        authority_id: Azure AD tenant ID (optional)
        use_managed_identity: Force managed identity auth (useful in Azure services)
    
    Returns:
        List of row dicts from Kusto
    """
    if not _KUSTO_AVAILABLE:
        raise ImportError("azure-kusto-data or azure.identity not available. Install via: pip install -r requirements.txt")

    # Determine credential strategy
    if use_managed_identity:
        credential = ManagedIdentityCredential()
    elif client_id and client_secret and authority_id:
        credential = ClientSecretCredential(
            tenant_id=authority_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    else:
        # Local-friendly fallback chain: existing default credentials first,
        # then interactive device code if none are available.
        credential = ChainedTokenCredential(
            DefaultAzureCredential(),
            DeviceCodeCredential(),
        )

    # Build connection string and client
    kcsb = KustoConnectionStringBuilder.with_azure_token_credential(cluster, credential)
    client = KustoClient(kcsb)

    # Execute query
    try:
        response = client.execute(database, query)
        rows = []
        for table in response.primary_results:
            column_names = [col.column_name for col in table.columns]
            for row in table:
                if hasattr(row, "to_dict"):
                    rows.append(row.to_dict())
                elif isinstance(row, dict):
                    rows.append(row)
                else:
                    rows.append({name: row[idx] for idx, name in enumerate(column_names)})
        return rows
    except Exception as e:
        message = str(e)
        if "DefaultAzureCredential failed" in message or "KustoAuthenticationError" in message:
            raise RuntimeError(
                "Kusto authentication failed. For local runs, use one of these options:\n"
                "1) PowerShell login: Connect-AzAccount\n"
                "2) Azure CLI login: az login\n"
                "3) Service principal: set KUSTO_CLIENT_ID, KUSTO_CLIENT_SECRET, KUSTO_TENANT_ID\n"
                "Then rerun the analyzer.\n\n"
                f"Original error: {e}"
            )
        if "E_LOW_MEMORY_CONDITION" in message or "lacks memory resources" in message:
            raise RuntimeError(
                "Kusto query hit low-memory limits. Retry with a smaller scan window and fewer rows, for example:\n"
                "--kusto-hours 1 --kusto-max-rows 500\n"
                "You can also filter by --version to reduce scanned data.\n\n"
                f"Original error: {e}"
            )
        raise RuntimeError(f"Kusto query failed: {e}")


def fetch_logs_from_file(path: str) -> List[Dict[str, Any]]:
    """Load logs from a JSONL file where each line is a JSON object (Kusto row)."""
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows
