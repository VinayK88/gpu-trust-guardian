"""Command-line entry point for demos, scans, guard checks, and adapters."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .guardrails import evaluate_request
from .morpheus import to_jsonl
from .nvidia_runtime import collect_nvml_snapshot
from .pipeline import load_events, scan_files, write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Explainable GPU and AI-infrastructure security lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Analyze a CSV and an attestation fixture")
    scan.add_argument("--events", type=Path, required=True)
    scan.add_argument("--attestation", type=Path, required=True)
    scan.add_argument("--scenario", default="custom")
    scan.add_argument("--output", type=Path)

    guard = subparsers.add_parser("guard", help="Evaluate one analyst-agent request")
    guard.add_argument("message")
    guard.add_argument("--tool")
    guard.add_argument("--human-approved", action="store_true")

    export = subparsers.add_parser("morpheus-export", help="Export Morpheus-ready JSONL")
    export.add_argument("--events", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)

    subparsers.add_parser("nvml", help="Read one optional live NVML snapshot")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        report = scan_files(args.events, args.attestation, args.scenario)
        payload = json.dumps(report.to_dict(), indent=2, default=str)
        if args.output:
            write_report(report, args.output)
        print(payload)
        return 0
    if args.command == "guard":
        print(
            json.dumps(
                evaluate_request(args.message, args.tool, args.human_approved).to_dict(),
                indent=2,
            )
        )
        return 0
    if args.command == "morpheus-export":
        args.output.write_text(to_jsonl(load_events(args.events)), encoding="utf-8")
        print(f"Wrote {args.output}")
        return 0
    if args.command == "nvml":
        print(json.dumps(collect_nvml_snapshot(), indent=2))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
