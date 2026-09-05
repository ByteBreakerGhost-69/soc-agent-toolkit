"""Tests for models.py — covers item #8 from the review (input validation)."""

import pytest

from soc_agent_toolkit.models import Alert, AlertValidationError, validate_alerts


def _valid_raw():
    return {"id": "a1", "signature": "Brute Force", "severity": 8, "message": "test", "src_ip": "1.2.3.4"}


class TestAlert:
    def test_valid_alert_constructs(self):
        alert = Alert.from_dict(_valid_raw(), strict=True)
        assert alert.id == "a1"
        assert alert.severity == 8

    def test_missing_id_dropped_non_strict(self):
        raw = _valid_raw()
        raw["id"] = ""
        assert Alert.from_dict(raw, strict=False) is None

    def test_missing_id_raises_strict(self):
        raw = _valid_raw()
        raw["id"] = ""
        with pytest.raises(AlertValidationError):
            Alert.from_dict(raw, strict=True)

    def test_severity_out_of_range_dropped(self):
        raw = _valid_raw()
        raw["severity"] = 15
        assert Alert.from_dict(raw, strict=False) is None

    def test_invalid_ip_dropped(self):
        raw = _valid_raw()
        raw["src_ip"] = "999.999.999.999"
        assert Alert.from_dict(raw, strict=False) is None

    def test_none_ip_is_allowed(self):
        raw = _valid_raw()
        raw["src_ip"] = None
        alert = Alert.from_dict(raw, strict=True)
        assert alert.src_ip is None

    def test_unknown_fields_ignored(self):
        raw = _valid_raw()
        raw["some_vendor_specific_field"] = "whatever"
        alert = Alert.from_dict(raw, strict=True)
        assert alert.id == "a1"


class TestValidateAlerts:
    def test_drops_invalid_keeps_valid(self):
        raws = [_valid_raw(), {**_valid_raw(), "id": "", "severity": 5}]
        result = validate_alerts(raws, strict=False)
        assert len(result) == 1
        assert result[0]["id"] == "a1"
