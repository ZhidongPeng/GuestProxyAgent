import json
from typing import List, Dict, Any, Optional
from dateutil import parser as date_parser


def _parse_timestamp(ev: Dict[str, Any]) -> Optional[Any]:
    for key in (
        "Timestamp",
        "Time",
        "timestamp",
        "time",
        "PreciseTimeStamp",
        "TimeGenerated",
    ):
        if key in ev and isinstance(ev[key], str):
            try:
                return date_parser.parse(ev[key])
            except Exception:
                pass
    return None


def _extract_message_payload(message: str) -> Optional[Dict[str, Any]]:
    start = message.find("{")
    if start < 0:
        return None

    payload_text = message[start:]
    try:
        parsed = json.loads(payload_text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    return None


def parse_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize Kusto-style rows into structured event dicts.

    Adds a `timestamp` field when a parsable timestamp is present.
    Also extracts embedded JSON payloads from `Message`/`message` and flattens
    common triage fields (e.g. `url`, `responseStatus`, `elapsedTime`).
    """
    events: List[Dict[str, Any]] = []
    for r in rows:
        ev = dict(r)

        message = ev.get("Message") or ev.get("message")
        if isinstance(message, str):
            payload = _extract_message_payload(message)
            if payload:
                ev["message_payload"] = payload

                for key in (
                    "id",
                    "method",
                    "url",
                    "responseStatus",
                    "elapsedTime",
                    "errorDetails",
                    "clientIp",
                    "clientPort",
                    "ip",
                    "port",
                ):
                    if key in payload and key not in ev:
                        ev[key] = payload[key]

        ts = _parse_timestamp(ev)
        if ts is not None:
            ev["timestamp"] = ts

        events.append(ev)
    return events
