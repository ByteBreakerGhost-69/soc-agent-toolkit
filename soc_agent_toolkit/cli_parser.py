"""
cli_parser.py - Argument parser construction for SOC Agent Toolkit.
"""

from __future__ import annotations

import argparse


def build_parser(
    *,
    cmd_analyze,
    cmd_triage,
    cmd_mitre,
    cmd_enrich_ip,
    cmd_enrich_domain,
    cmd_enrich_hash,
    cmd_status,
    cmd_doctor,
    cmd_config,
    cmd_version,
) -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="soc-agent",
        description=(
            "SOC Agent Toolkit — "
            "AI-assisted SOC alert triage and incident analysis"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="{analyze,triage,mitre,enrich,status,config,doctor,version}",
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze and triage security alerts",
    )

    analyze_parser.add_argument(
        "input",
        help="Path to alert/log file, or '-' to read from stdin",
    )

    analyze_parser.add_argument(
        "--assets",
        help=(
            "Optional JSON file mapping IP/hostname "
            "to criticality weight"
        ),
    )

    analyze_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the complete analysis result as JSON",
    )

    analyze_parser.add_argument(
        "--log-level",
        default=None,
        help=(
            "DEBUG, INFO, WARNING, ERROR "
            "(default: INFO or $SOC_TOOLKIT_LOG_LEVEL)"
        ),
    )

    analyze_parser.set_defaults(func=cmd_analyze)

    triage_parser = subparsers.add_parser(
        "triage",
        help="Deduplicate and prioritize security alerts",
    )

    triage_parser.add_argument(
        "input",
        help="Path to JSON alert file, or '-' to read from stdin",
    )

    triage_parser.add_argument(
        "--assets",
        help="Optional JSON file mapping IP/hostname to criticality weight",
    )

    triage_parser.add_argument(
        "--json",
        action="store_true",
        help="Print triaged alerts as JSON",
    )

    triage_parser.add_argument(
        "--async",
        dest="use_async",
        action="store_true",
        help="Enrich alerts concurrently before triage",
    )

    triage_parser.add_argument(
        "--log-level",
        default=None,
        help="DEBUG, INFO, WARNING, ERROR",
    )

    triage_parser.set_defaults(func=cmd_triage)

    mitre_parser = subparsers.add_parser(
        "mitre",
        help="Map text to MITRE ATT&CK techniques",
    )

    mitre_parser.add_argument(
        "text",
        help="Security alert text to map",
    )

    mitre_parser.set_defaults(func=cmd_mitre)

    # Grouped enrichment commands
    enrich_parser = subparsers.add_parser(
        "enrich",
        help="Enrich IPs, domains, and file hashes",
    )

    enrich_subparsers = enrich_parser.add_subparsers(
        dest="enrich_type",
        required=True,
    )

    enrich_ip_group_parser = enrich_subparsers.add_parser(
        "ip",
        help="Check IP reputation",
    )
    enrich_ip_group_parser.add_argument(
        "ip",
        help="IPv4 or IPv6 address to investigate",
    )
    enrich_ip_group_parser.set_defaults(func=cmd_enrich_ip)

    enrich_domain_group_parser = enrich_subparsers.add_parser(
        "domain",
        help="Check domain reputation",
    )
    enrich_domain_group_parser.add_argument(
        "domain",
        help="Domain to investigate",
    )
    enrich_domain_group_parser.set_defaults(func=cmd_enrich_domain)

    enrich_hash_group_parser = enrich_subparsers.add_parser(
        "hash",
        help="Check file hash reputation",
    )
    enrich_hash_group_parser.add_argument(
        "hash",
        help="MD5, SHA1, or SHA256 file hash to investigate",
    )
    enrich_hash_group_parser.set_defaults(func=cmd_enrich_hash)

    enrich_ip_parser = subparsers.add_parser(
        "enrich-ip",
        help=argparse.SUPPRESS,
    )

    enrich_ip_parser.add_argument(
        "ip",
        help="IPv4 or IPv6 address to investigate",
    )

    enrich_ip_parser.set_defaults(func=cmd_enrich_ip)

    enrich_domain_parser = subparsers.add_parser(
        "enrich-domain",
        help=argparse.SUPPRESS,
    )

    enrich_domain_parser.add_argument(
        "domain",
        help="Domain to investigate",
    )

    enrich_domain_parser.set_defaults(func=cmd_enrich_domain)

    enrich_hash_parser = subparsers.add_parser(
        "enrich-hash",
        help=argparse.SUPPRESS,
    )

    enrich_hash_parser.add_argument(
        "hash",
        help="MD5, SHA1, or SHA256 file hash to investigate",
    )

    enrich_hash_parser.set_defaults(func=cmd_enrich_hash)

    status_parser = subparsers.add_parser(
        "status",
        help="Show toolkit and integration status",
    )

    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Print status as JSON",
    )

    status_parser.set_defaults(func=cmd_status)

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Run toolkit health checks",
    )

    doctor_parser.add_argument(
        "--network",
        action="store_true",
        help="Also check outbound HTTPS connectivity",
    )

    doctor_parser.add_argument(
        "--json",
        action="store_true",
        help="Print diagnostic results as JSON",
    )

    doctor_parser.set_defaults(func=cmd_doctor)

    config_parser = subparsers.add_parser(
        "config",
        help="Show toolkit configuration status",
    )

    config_parser.add_argument(
        "--json",
        action="store_true",
        help="Print configuration as JSON",
    )

    config_parser.set_defaults(func=cmd_config)

    version_parser = subparsers.add_parser(
        "version",
        help="Show SOC Agent Toolkit version",
    )

    version_parser.set_defaults(func=cmd_version)

    hidden_commands = {"enrich-ip", "enrich-domain", "enrich-hash"}
    subparsers._choices_actions = [
        action
        for action in subparsers._choices_actions
        if action.dest not in hidden_commands
    ]

    return parser
