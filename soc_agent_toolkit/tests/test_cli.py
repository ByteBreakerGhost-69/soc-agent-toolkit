"""Tests for CLI commands."""

from soc_agent_toolkit.cli import build_parser


def test_status_command_is_registered():
    parser = build_parser()
    args = parser.parse_args(["status"])
    assert args.command == "status"


def test_config_command_is_registered():
    parser = build_parser()
    args = parser.parse_args(["config"])
    assert args.command == "config"


def test_doctor_command_is_registered():
    parser = build_parser()
    args = parser.parse_args(["doctor"])
    assert args.command == "doctor"


def test_grouped_enrich_commands_are_registered():
    parser = build_parser()

    ip_args = parser.parse_args(["enrich", "ip", "8.8.8.8"])
    domain_args = parser.parse_args(["enrich", "domain", "example.com"])
    hash_args = parser.parse_args(
        ["enrich", "hash", "d41d8cd98f00b204e9800998ecf8427e"]
    )

    assert ip_args.enrich_type == "ip"
    assert domain_args.enrich_type == "domain"
    assert hash_args.enrich_type == "hash"


def test_legacy_enrich_command_remains_supported():
    parser = build_parser()

    args = parser.parse_args(["enrich-ip", "8.8.8.8"])

    assert args.command == "enrich-ip"
    assert args.ip == "8.8.8.8"


def test_doctor_command_is_registered_and_runs(monkeypatch, capsys):
    from soc_agent_toolkit import cli

    class FakeResponse:
        status_code = 200

    def fake_get(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(cli.requests, "get", fake_get)

    parser = cli.build_parser()
    args = parser.parse_args(["doctor"])

    assert args.func(args) == cli.EXIT_OK

    output = capsys.readouterr().out
    assert "SOC AGENT DOCTOR" in output
    assert "All diagnostic checks passed." in output
