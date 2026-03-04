import argparse
import json
import os
from .ingest import (
    fetch_logs_from_file,
    fetch_kusto_logs,
    fetch_kusto_logs_in_chunks,
    build_guest_proxy_agent_query,
)
from .parse import parse_rows
from .detectors import run_all_detectors, summarize_focused_triage


def main():
    p = argparse.ArgumentParser(
        description="GuestProxyAgent log analyzer - detect bugs from Kusto logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze local JSONL file
  python -m guestproxy_analyzer.cli tests/sample_logs.jsonl
  
  # Analyze Kusto cluster (using managed identity)
  python -m guestproxy_analyzer.cli \
    --kusto-cluster https://azcore.centralus.kusto.windows.net \
    --kusto-db Fa \
    --use-managed-identity
    
  # Analyze Kusto cluster (using service principal from env vars)
  export KUSTO_CLIENT_ID=<app-id>
  export KUSTO_CLIENT_SECRET=<secret>
  export KUSTO_TENANT_ID=<tenant-id>
  python -m guestproxy_analyzer.cli \
    --kusto-cluster https://azcore.centralus.kusto.windows.net \
    --kusto-db Fa
"""
    )
    p.add_argument("path", nargs="?", help="Path to JSONL log file (omit to use Kusto)")
    p.add_argument("--kusto-cluster", default="https://azcore.centralus.kusto.windows.net", help="Kusto cluster URL (e.g., https://azcore.centralus.kusto.windows.net)")
    p.add_argument("--kusto-db", default="Fa", help="Kusto database name")
    p.add_argument("--kusto-table", default="GuestAgentGenericLogs", help="Kusto table name (default: GuestAgentGenericLogs)")
    p.add_argument("--kusto-hours", type=int, default=24, help="Look back N hours (default: 24)")
    p.add_argument("--kusto-max-rows", type=int, default=2000, help="Max rows to fetch from Kusto (default: 2000)")
    p.add_argument("--kusto-start-time", help="Start time (ISO8601), e.g. 2026-02-24T00:00:00Z")
    p.add_argument("--kusto-end-time", help="End time (ISO8601), e.g. 2026-02-24T06:00:00Z")
    p.add_argument("--kusto-chunk-minutes", type=int, default=0, help="If >0, query Kusto in time chunks of this many minutes")
    p.add_argument("--use-managed-identity", action="store_true", help="Use managed identity for Kusto auth")
    p.add_argument("--client-id", help="Azure AD client ID (or set KUSTO_CLIENT_ID env var)")
    p.add_argument("--client-secret", help="Azure AD client secret (or set KUSTO_CLIENT_SECRET env var)")
    p.add_argument("--tenant-id", help="Azure AD tenant ID (or set KUSTO_TENANT_ID env var)")
    p.add_argument("--version", default="1.0.40", help="GuestProxyAgent Version")
    p.add_argument("--top", type=int, default=10, help="Top N items for triage output (default: 10)")
    p.add_argument("--triage-json", metavar="FILE", help="Write triage summary to a JSON file for CI consumption")
    
    args = p.parse_args()

    # Load logs
    if args.path:
        # Local file mode
        rows = fetch_logs_from_file(args.path)
    elif args.kusto_cluster and args.kusto_db:
        # Kusto mode
        client_id = args.client_id or os.environ.get("KUSTO_CLIENT_ID")
        client_secret = args.client_secret or os.environ.get("KUSTO_CLIENT_SECRET")
        tenant_id = args.tenant_id or os.environ.get("KUSTO_TENANT_ID")
        
        print(f"[*] Fetching logs from Kusto: {args.kusto_cluster}/{args.kusto_db}")
        if args.kusto_chunk_minutes > 0:
            rows = fetch_kusto_logs_in_chunks(
                cluster=args.kusto_cluster,
                database=args.kusto_db,
                table=args.kusto_table,
                chunk_minutes=args.kusto_chunk_minutes,
                client_id=client_id,
                client_secret=client_secret,
                authority_id=tenant_id,
                use_managed_identity=args.use_managed_identity,
                hours=args.kusto_hours,
                version=args.version,
                max_rows=args.kusto_max_rows,
                start_time=args.kusto_start_time,
                end_time=args.kusto_end_time,
            )
        else:
            query = build_guest_proxy_agent_query(
                hours=args.kusto_hours,
                table=args.kusto_table,
                version=args.version,
                max_rows=args.kusto_max_rows,
                start_time=args.kusto_start_time,
                end_time=args.kusto_end_time,
            )
            rows = fetch_kusto_logs(
                cluster=args.kusto_cluster,
                database=args.kusto_db,
                query=query,
                client_id=client_id,
                client_secret=client_secret,
                authority_id=tenant_id,
                use_managed_identity=args.use_managed_identity
            )
    else:
        p.print_help()
        return

    # Parse and analyze
    events = parse_rows(rows)
    # save events to file for debugging
    with open("debug_events.json", "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2, default=str)
        
    results = run_all_detectors(events)
    
    # Print results
    print(f"\n[+] Analyzed {len(events)} events")
    for k, v in results.items():
        print(f"\n[{k}] {len(v)} findings:")
        for f in v[:10]:  # Show first 10
            print(f"  - {f.message}")
        if len(v) > 10:
            print(f"  ... and {len(v) - 10} more")

    triage = summarize_focused_triage(events, results, top_n=max(1, args.top))

    print("\n[triage] Top status/url pairs:")
    for (status, url), count in triage["top_status_url"]:
        print(f"  - {count:>6}  {status:<18} {url}")

    print("\n[triage] Top forbidden URLs (403):")
    for url, count in triage["top_forbidden_urls"]:
        print(f"  - {count:>6}  {url}")

    print("\n[triage] Top client-error URLs (4xx):")
    for url, count in triage["top_client_error_urls"]:
        print(f"  - {count:>6}  {url}")

    print("\n[triage] Top server-error URLs (5xx):")
    for url, count in triage["top_server_error_urls"]:
        print(f"  - {count:>6}  {url}")

    print("\n[triage] Top slow URLs (latency findings):")
    for url, count in triage["top_slow_urls"]:
        print(f"  - {count:>6}  {url}")

    if args.triage_json:
        triage_report = {
            "total_events": len(events),
            "detector_counts": {k: len(v) for k, v in results.items()},
            "top_status_url": [
                {"status": status, "url": url, "count": count}
                for (status, url), count in triage["top_status_url"]
            ],
            "top_forbidden_urls": [
                {"url": url, "count": count}
                for url, count in triage["top_forbidden_urls"]
            ],
            "top_client_error_urls": [
                {"url": url, "count": count}
                for url, count in triage["top_client_error_urls"]
            ],
            "top_server_error_urls": [
                {"url": url, "count": count}
                for url, count in triage["top_server_error_urls"]
            ],
            "top_slow_urls": [
                {"url": url, "count": count}
                for url, count in triage["top_slow_urls"]
            ],
        }
        with open(args.triage_json, "w", encoding="utf-8") as tf:
            json.dump(triage_report, tf, indent=2)
        print(f"\n[+] Triage JSON written to {args.triage_json}")


if __name__ == "__main__":
    main()

