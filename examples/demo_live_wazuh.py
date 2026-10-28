"""
SecAgents — Live Wazuh AI Demonstration.

Uses Alex's existing read-only Wazuh Indexer client
to retrieve recent alerts and analyze them with Qwen.

Run:
    python3 -m examples.demo_live_wazuh
    python3 -m examples.demo_live_wazuh --limit 5
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from app.gateway import AIGateway
from examples.demo_ai_gateway import display_analysis


DEFAULT_CLIENT = Path.home() / "wazuh-ai-client" / "wazuh_client.py"


def main():
    parser = argparse.ArgumentParser(
        description="SecAgents Live Wazuh AI Demonstration"
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=1,
        help="Maximum number of Wazuh alerts to analyze (1-10)"
    )

    parser.add_argument(
        "--minutes",
        type=int,
        default=1440,
        help="Look back this many minutes (default: 1440)"
    )

    parser.add_argument(
        "--min-level",
        type=int,
        default=7,
        help="Minimum Wazuh rule level (default: 7)"
    )

    parser.add_argument(
        "--client",
        type=Path,
        default=DEFAULT_CLIENT,
        help="Path to Alex's existing Wazuh client"
    )

    args = parser.parse_args()

    if not 1 <= args.limit <= 10:
        parser.error("--limit must be between 1 and 10")

    if args.minutes <= 0:
        parser.error("--minutes must be greater than zero")

    if not 0 <= args.min_level <= 16:
        parser.error("--min-level must be between 0 and 16")

    client_path = args.client.expanduser().resolve()

    if not client_path.is_file():
        print(f"ERROR: Wazuh client not found: {client_path}")
        return 1

    print("\n" + "=" * 65)
    print("             SECAGENTS LIVE WAZUH AI DEMO")
    print("=" * 65)
    print("Source: Live Wazuh Indexer")
    print("Model: Qwen3.5:9b")
    print("Mode: Read-only AI enrichment")
    print(f"Maximum alerts: {args.limit}")
    print(f"Lookback: {args.minutes} minutes")
    print(f"Minimum Wazuh level: {args.min_level}")

    # The export exists only inside a private temporary directory.
    # It is not added to the Git repository.
    with tempfile.TemporaryDirectory(
        prefix="secagents-wazuh-"
    ) as temporary_directory:

        export_path = (
            Path(temporary_directory) / "wazuh-alerts.json"
        )

        command = [
            sys.executable,
            str(client_path),
            "--min-level",
            str(args.min_level),
            "--minutes",
            str(args.minutes),
            "--limit",
            str(args.limit),
            "--output",
            str(export_path),
        ]

        print("\nRetrieving recent Wazuh alerts...")
        print("Alex's client will request authentication if needed.\n")

        # Preserve the existing interactive password prompt.
        # Do not capture or log credentials.
        try:
            completed = subprocess.run(
                command,
                cwd=client_path.parent,
                check=False,
            )
        except OSError as error:
            print(f"ERROR: Could not start Wazuh client: {error}")
            return 1

        if completed.returncode != 0:
            print("\nERROR: Wazuh alert retrieval failed.")
            return 1

        if not export_path.is_file():
            print("\nERROR: Wazuh client did not create an export.")
            return 1

        try:
            with export_path.open(
                "r",
                encoding="utf-8"
            ) as file:
                records = json.load(file)
        except (OSError, json.JSONDecodeError) as error:
            print(f"\nERROR: Invalid Wazuh export: {error}")
            return 1

        if not isinstance(records, list):
            print("\nERROR: Expected a JSON array of Wazuh alerts.")
            return 1

        if not records:
            print("\nNo matching Wazuh alerts found.")
            print("Try increasing --minutes or lowering --min-level.")
            return 0

        # Never process more alerts than requested.
        records = records[:args.limit]

        gateway = AIGateway()
        passed = 0
        failed = 0

        for number, record in enumerate(records, start=1):
            try:
                display_analysis(
                    number,
                    len(records),
                    record,
                    gateway,
                )
                passed += 1
            except Exception as error:
                failed += 1
                print(
                    f"\nAlert {number} failed: "
                    f"{type(error).__name__}: {error}"
                )

        print("\n" + "=" * 65)
        print("LIVE WAZUH AI DEMONSTRATION RESULTS")
        print("=" * 65)
        print("Alerts retrieved:", len(records))
        print("Passed:", passed)
        print("Failed:", failed)
        print("Temporary export removed when the script exits.")
        print("No automated security actions were performed.")

        return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())