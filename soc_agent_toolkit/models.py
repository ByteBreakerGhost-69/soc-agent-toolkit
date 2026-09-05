"""
models.py — Typed, validated representation of a normalized alert.

Using stdlib dataclasses (no extra dependency) rather than Pydantic to keep
the toolkit lightweight; the validation contract is the same idea (fail
fast on malformed data) without adding a hard dependency. If your project
already depends on Pydantic, `Alert.model_dump()`-style usage can be swapped
in later without changing callers, since everything downstream consumes
`.to_dict()`.

parser.py builds raw dicts (matching existing behavior/tests); call
`Alert.from_dict()` to validate before it enters triage/enrichment.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any

from .logging_setup import get_logger

logger = get_logger(__name__)


class AlertValidationError(ValueError):
    """Raised when a raw alert dict fails schema validation."""


def _validate_ip(value: str | None, field_name: str) -> str | None:
    if value in (None, ""):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise AlertValidationError(f"{field_name!r} is not a valid IP address: {value!r}")
    return value


@dataclass
class Alert:
    id: str
    signature: str
    severity: int
    message: str
    timestamp: str | None = None
    source: str = "unknown"
    src_ip: str | None = None
    dest_ip: str | None = None
    user: str | None = None
    raw: str = ""
    # Optional fields populated later in the pipeline (mitre.py / enrichment.py / triage.py)
    mitre: list[dict[str, str]] = field(default_factory=list)
    mitre_source: str | None = None
    enrichment: dict[str, Any] = field(default_factory=dict)
    occurrence_count: int = 1
    first_seen: str | None = None
    last_seen: str | None = None
    related_ids: list[str] = field(default_factory=list)
    priority_score: int | None = None
    priority_tier: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            raise AlertValidationError("Alert.id must be non-empty")
        if not self.signature:
            raise AlertValidationError("Alert.signature must be non-empty")
        if not isinstance(self.severity, int) or not (0 <= self.severity <= 10):
            raise AlertValidationError(f"Alert.severity must be an int 0-10, got {self.severity!r}")
        # message may legitimately be empty (some devices send blank descriptions),
        # but warn so it's visible in observability rather than silently dropped.
        if not self.message:
            logger.warning("Alert %s has an empty message field", self.id)
        self.src_ip = _validate_ip(self.src_ip, "src_ip")
        self.dest_ip = _validate_ip(self.dest_ip, "dest_ip")

    @classmethod
    def from_dict(cls, data: dict[str, Any], strict: bool = False) -> "Alert | None":
        """
        Build a validated Alert from a raw dict (as produced by parser.py).

        strict=True raises AlertValidationError on bad data (use in tests /
        CI). strict=False (default) logs a warning and returns None so a
        batch job can skip one bad alert instead of crashing the whole run.
        """
        known_fields = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        try:
            return cls(**filtered)
        except AlertValidationError as exc:
            logger.warning("Dropping invalid alert (id=%s): %s", data.get("id", "?"), exc)
            if strict:
                raise
            return None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_alerts(raw_alerts: list[dict[str, Any]], strict: bool = False) -> list[dict[str, Any]]:
    """Validate a batch of raw alert dicts, dropping (or raising on) invalid ones."""
    validated = []
    for raw in raw_alerts:
        alert = Alert.from_dict(raw, strict=strict)
        if alert is not None:
            validated.append(alert.to_dict())
    dropped = len(raw_alerts) - len(validated)
    if dropped:
        logger.info("validate_alerts: dropped %d/%d invalid alert(s)", dropped, len(raw_alerts))
    return validated
