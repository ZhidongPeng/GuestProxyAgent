from typing import List, Dict, Any
from dataclasses import dataclass
from collections import Counter

@dataclass
class Finding:
    type: str
    message: str
    row: Dict[str, Any]


def _get_message(event: Dict[str, Any]) -> str:
    return str(event.get("Message") or event.get("message") or "")


def _get_level(event: Dict[str, Any]) -> str:
    return str(event.get("Level") or event.get("Severity") or "").lower()


def _get_status(event: Dict[str, Any]) -> str:
    return str(event.get("responseStatus") or event.get("status") or "")


def _get_url(event: Dict[str, Any]) -> str:
    return str(event.get("url") or event.get("Url") or "")


def detect_exceptions(events: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    for event in events:
        msg = _get_message(event)
        msg_lower = msg.lower()
        level = _get_level(event)
        status = _get_status(event)

        is_exception_like = (
            "exception" in msg_lower
            or "stacktrace" in msg_lower
            or "panic" in msg_lower
            or "traceback" in msg_lower
            or "connection failed" in msg_lower
            or "connectionreset" in msg_lower
            or "forcibly closed" in msg_lower
            or "timed out" in msg_lower
            or level in ("error", "err", "critical")
            or status.startswith("5")
        )
        if is_exception_like:
            findings.append(Finding("exception", msg, event))
    return findings


def detect_restarts(events: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    for event in events:
        msg = _get_message(event)
        msg_lower = msg.lower()
        if (
            "restart" in msg_lower
            or "restarted" in msg_lower
            or "killed" in msg_lower
            or "terminated" in msg_lower
            or "crash" in msg_lower
        ):
            findings.append(Finding("restart", msg, event))
    return findings


def detect_latency(events: List[Dict[str, Any]], threshold_ms: float = 1000.0) -> List[Finding]:
    findings: List[Finding] = []
    for event in events:
        # look for common duration fields
        for key in ("DurationMs", "durationMs", "duration", "latencyMs", "elapsedTime"):
            if key in event:
                try:
                    duration_ms = float(event[key])
                    if duration_ms <= threshold_ms:
                        continue

                    url = _get_url(event)
                    status = _get_status(event)
                    prefix = f"{url} [{status}] - " if url or status else ""
                    findings.append(
                        Finding(
                            "latency",
                            f"{prefix}{key}={duration_ms} > {threshold_ms}",
                            event,
                        )
                    )
                except Exception:
                    pass
    return findings


def summarize_focused_triage(
    events: List[Dict[str, Any]],
    results: Dict[str, List[Finding]],
    top_n: int = 10,
) -> Dict[str, List[Any]]:
    status_url_counter: Counter = Counter()
    forbidden_url_counter: Counter = Counter()
    client_error_url_counter: Counter = Counter()
    server_error_url_counter: Counter = Counter()
    slow_url_counter: Counter = Counter()

    for event in events:
        url = _get_url(event)
        status = _get_status(event)
        if not url or not status:
            continue

        status_url_counter[(status, url)] += 1
        if status == "403 Forbidden":
            forbidden_url_counter[url] += 1
        if status and status[0].isdigit() and status.startswith("4"):
            client_error_url_counter[url] += 1
        if status and status[0].isdigit() and status.startswith("5"):
            server_error_url_counter[url] += 1

    for finding in results.get("latency", []):
        url = _get_url(finding.row)
        if url:
            slow_url_counter[url] += 1

    return {
        "top_status_url": status_url_counter.most_common(top_n),
        "top_forbidden_urls": forbidden_url_counter.most_common(top_n),
        "top_client_error_urls": client_error_url_counter.most_common(top_n),
        "top_server_error_urls": server_error_url_counter.most_common(top_n),
        "top_slow_urls": slow_url_counter.most_common(top_n),
    }


def run_all_detectors(events: List[Dict[str, Any]]) -> Dict[str, List[Finding]]:
    return {
        "exceptions": detect_exceptions(events),
        "restarts": detect_restarts(events),
        "latency": detect_latency(events),
    }
