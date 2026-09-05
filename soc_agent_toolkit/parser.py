"""
parser.py — Normalize raw alerts/logs into a common schema.

Supports:
  - JSON (single object or list of objects, e.g. from a SIEM export)
  - CEF (Common Event Format, e.g. "CEF:0|Vendor|Product|Version|SigID|Name|Sev|ext=..")
  - Generic syslog-ish lines ("<timestamp> <host> <process>: <message>")

Normalized alert schema:
{
    "id": str,
    "timestamp": str | None,
    "source": str,          # device/product that raised it
    "signature": str,       # rule/signature name or id
    "severity": int,        # 0-10 normalized scale
    "src_ip": str | None,
    "dest_ip": str | None,
    "user": str | None,
    "message": str,
    "raw": str,             # original raw line/object for audit trail
}
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from .logging_setup import get_logger

logger = get_logger(__name__)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Matches a CEF extension key immediately followed by '=', where the key is
# preceded by start-of-string or whitespace (so "=" inside a value, e.g.
# "msg=result = 5", is never mistaken for the start of a new field).
_CEF_KEY_RE = re.compile(r"(?:^|(?<=\s))([A-Za-z][\w.]*)=")

# CEF escape sequences per the CEF spec: values may contain a backslash-escaped
# '=', '\', or 'n' (newline). Anything else after a backslash is left as-is
# rather than silently dropped, since an unrecognized escape is more likely a
# stray backslash in the original data than a spec-compliant sequence.
_CEF_ESCAPE_MAP = {"n": "\n", "\\": "\\", "=": "="}


def _unescape_cef_value(value: str) -> str:
    return re.sub(r"\\(.)", lambda m: _CEF_ESCAPE_MAP.get(m.group(1), "\\" + m.group(1)), value)


def parse_cef_extension(extension: str) -> dict[str, str]:
    """
    Parse a CEF extension string ("key1=val1 key2=val with spaces key3=...")
    into a dict, correctly handling:
      - values containing spaces (e.g. msg=Multiple failed SSH logins)
      - escaped '=' and '\\' inside values (e.g. msg=path\\=C:\\\\temp)
      - a bare '=' inside a value that isn't a new key (e.g. msg=result = 5)

    A naive regex like r"(\\w+)=((?:[^\\s=]|\\s(?!\\w+=))*)" breaks on the
    last case above and on multi-word keys; this version locates key markers
    first, then treats everything between two markers as one (unescaped) value.
    """
    if not extension:
        return {}

    matches = list(_CEF_KEY_RE.finditer(extension))
    result: dict[str, str] = {}
    for i, m in enumerate(matches):
        key = m.group(1)
        val_start = m.end()
        val_end = matches[i + 1].start() if i + 1 < len(matches) else len(extension)
        raw_val = extension[val_start:val_end].rstrip()
        result[key] = _unescape_cef_value(raw_val)

    if not matches and extension.strip():
        logger.warning("CEF extension had no parseable key=value pairs: %r", extension[:120])
    return result


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _extract_ips(text: str) -> list[str]:
    return _IP_RE.findall(text or "")


def parse_json_alert(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a single JSON-shaped alert (keys vary by vendor, so we probe common ones)."""
    def pick(*keys, default=None):
        for k in keys:
            if k in raw and raw[k] not in (None, ""):
                return raw[k]
        return default

    message = pick("message", "msg", "description", "name", default="")
    src_ip = pick("src_ip", "source_ip", "srcip", "sourceAddress")
    dest_ip = pick("dest_ip", "destination_ip", "dstip", "destinationAddress")

    ips_in_msg = _extract_ips(str(message))
    if not src_ip and ips_in_msg:
        src_ip = ips_in_msg[0]
    if not dest_ip and len(ips_in_msg) > 1:
        dest_ip = ips_in_msg[1]

    return {
        "id": str(pick("id", "alert_id", "uuid", default=_new_id())),
        "timestamp": pick("timestamp", "time", "@timestamp", "eventTime"),
        "source": str(pick("source", "product", "vendor", "sensor", default="unknown")),
        "signature": str(pick("signature", "rule", "rule_name", "sig", "category", default="unspecified")),
        "severity": _normalize_severity(pick("severity", "sev", "priority", default=5)),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "user": pick("user", "username", "account"),
        "message": str(message),
        "raw": json.dumps(raw, ensure_ascii=False),
    }


def parse_cef(line: str) -> dict[str, Any]:
    """Parse a single CEF-formatted line."""
    # CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    parts = line.split("|", 7)
    if not parts[0].startswith("CEF:") or len(parts) < 7:
        raise ValueError("Not a valid CEF line")

    vendor, product, _pver, sig_id, name, severity = parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
    extension = parts[7] if len(parts) > 7 else ""

    ext = parse_cef_extension(extension)
    message = ext.get("msg", name)
    ips_in_msg = _extract_ips(message)

    return {
        "id": ext.get("externalId", _new_id()),
        "timestamp": ext.get("rt") or ext.get("end"),
        "source": f"{vendor}/{product}",
        "signature": f"{sig_id}:{name}",
        "severity": _normalize_severity(severity),
        "src_ip": ext.get("src") or (ips_in_msg[0] if ips_in_msg else None),
        "dest_ip": ext.get("dst") or (ips_in_msg[1] if len(ips_in_msg) > 1 else None),
        "user": ext.get("suser") or ext.get("duser"),
        "message": message,
        "raw": line,
    }


def parse_syslog(line: str) -> dict[str, Any]:
    """Best-effort parse of a generic syslog-style line."""
    m = re.match(
        r"^(?P<ts>\S+\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(\[\d+\])?:\s*(?P<msg>.*)$",
        line.strip(),
    )
    ips = _extract_ips(line)
    if m:
        gd = m.groupdict()
        return {
            "id": _new_id(),
            "timestamp": gd["ts"],
            "source": gd["host"],
            "signature": gd["proc"],
            "severity": 5,
            "src_ip": ips[0] if ips else None,
            "dest_ip": ips[1] if len(ips) > 1 else None,
            "user": None,
            "message": gd["msg"],
            "raw": line,
        }
    # Fallback: couldn't match the pattern, still return something usable
    return {
        "id": _new_id(),
        "timestamp": None,
        "source": "unknown",
        "signature": "unparsed_syslog",
        "severity": 5,
        "src_ip": ips[0] if ips else None,
        "dest_ip": ips[1] if len(ips) > 1 else None,
        "user": None,
        "message": line.strip(),
        "raw": line,
    }


def _normalize_severity(value: Any) -> int:
    """Map varied severity representations (strings, 1-10, 1-4, low/med/high) onto 0-10."""
    if isinstance(value, (int, float)):
        return max(0, min(10, int(value)))
    text = str(value).strip().lower()
    text_map = {
        "informational": 1, "info": 1, "low": 3, "medium": 5, "moderate": 5,
        "high": 8, "critical": 10, "severe": 10,
    }
    if text in text_map:
        return text_map[text]
    try:
        return max(0, min(10, int(float(text))))
    except ValueError:
        return 5


def parse_alerts(raw_input: str | list[dict] | dict, validate: bool = True) -> list[dict[str, Any]]:
    """
    Entry point: auto-detects format and returns a list of normalized alerts.

    Accepts:
      - a JSON string (object or array)
      - a Python list[dict] / dict already
      - raw text with one CEF or syslog line per row

    validate=True (default) runs every parsed alert through
    models.validate_alerts() so malformed alerts (bad severity, malformed
    IPs, missing required fields) are logged and dropped instead of
    silently propagating bad data into triage/enrichment.
    """
    if isinstance(raw_input, (list, dict)):
        items = raw_input if isinstance(raw_input, list) else [raw_input]
        parsed = [parse_json_alert(item) for item in items]
    else:
        text = raw_input.strip()
        if not text:
            return []

        # Try whole-blob JSON first
        try:
            data = json.loads(text)
            items = data if isinstance(data, list) else [data]
            parsed = [parse_json_alert(item) for item in items]
        except json.JSONDecodeError:
            # Otherwise treat as line-delimited CEF/syslog
            parsed = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    if line.startswith("CEF:"):
                        parsed.append(parse_cef(line))
                    else:
                        parsed.append(parse_syslog(line))
                except Exception:
                    logger.exception("Failed to parse line, skipping: %r", line[:200])

    logger.info("Parsed %d raw alert(s)", len(parsed))
    if not validate:
        return parsed

    from .models import validate_alerts  # local import avoids a circular import at module load time

    return validate_alerts(parsed, strict=False)
