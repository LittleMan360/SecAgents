"""
SecAgents — AI Gateway Demonstration

Processes previously exported Wazuh alerts using the
existing SecAgents AI gateway and local Qwen model.

Usage:
    python3 -m examples.demo_ai_gateway
    python3 -m examples.demo_ai_gateway --all
"""

import argparse
import json
import os
import time

from app.gateway import AIGateway
from app.normalizer import normalize_alert
from app.schemas import validate_event


DEFAULT_DATASET = (
    "/home/dalton/wazuh-ai-client/wazuh-local-test.json"
)


def display_analysis(number, total, raw_event, gateway):
    """Analyze and display one Wazuh alert."""

    print("\n" + "=" * 65)
    print(f"SECAGENTS — SECURITY ALERT {number}/{total}")
    print("=" * 65)

    # Normalize and validate the original alert.
    event = normalize_alert(raw_event)
    validate_event(event)

    print("\nORIGINAL WAZUH EVIDENCE")
    print("-" * 65)
    print("Event ID:    ", event["event_id"])
    print("Event Index: ", event.get("event_index"))
    print("Hostname:    ", event["hostname"])
    print("Timestamp:   ", event["timestamp"])
    print("Rule ID:     ", event["rule_id"])
    print("Severity:    ", event["severity"])
    print("Description: ", event["description"])

    print("\nSending alert to Qwen...")
    start = time.time()

    # The gateway performs its own normalization and validation.
    result = gateway.process_alert(raw_event)

    elapsed = time.time() - start

    # Confirm the AI result references the original Wazuh record.
    assert result["event_id"] == event["event_id"]
    assert result["event_index"] == (event.get("event_index") or "")

    print("\nAI SECURITY ANALYSIS")
    print("-" * 65)
    print("Classification:", result["classification"].upper())
    print("Confidence:    ", f"{result['confidence']:.0%}")

    print("\nSUMMARY")
    print(result["summary"])

    print("\nSOURCE CONTEXT")
    print(result["source_context"])

    print("\nUNCERTAINTY")
    print(result["uncertainty"])

    print("\nEVIDENCE")
    for item in result["evidence"]:
        print(f"  - {item}")

    print("\nRECOMMENDED INVESTIGATION ACTIONS")
    for item in result["recommended_actions"]:
        print(f"  - {item}")

    if result.get("mitre_explanation"):
        print("\nMITRE ATT&CK CONTEXT")
        print(result["mitre_explanation"])

    print("\nVALIDATION")
    print("-" * 65)
    print("AI output schema:          PASS")
    print("Original event references: PASS")
    print(f"Processing time:           {elapsed:.2f} seconds")

    return elapsed


def main():
    parser = argparse.ArgumentParser(
        description="SecAgents AI Gateway Demonstration"
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Analyze every alert in the dataset"
    )

    parser.add_argument(
        "--file",
        default=os.environ.get(
            "SECAGENTS_DEMO_DATASET",
            DEFAULT_DATASET
        ),
        help="Path to the exported Wazuh JSON dataset"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print("ERROR: Wazuh dataset not found.")
        print("Check the --file argument.")
        return 1

    with open(args.file, "r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list) or not events:
        print("ERROR: Dataset must contain a nonempty JSON list.")
        return 1

    selected_events = events if args.all else events[:1]

    print("\n" + "=" * 65)
    print("             SECAGENTS AI SECURITY ANALYSIS")
    print("=" * 65)
    print("Model: Qwen3.5:9b")
    print("Source: Previously exported Wazuh alerts")
    print("Mode: Read-only AI enrichment demonstration")

    gateway = AIGateway()

    passed = 0
    failed = 0

    for number, raw_event in enumerate(selected_events, start=1):
        try:
            display_analysis(
                number,
                len(selected_events),
                raw_event,
                gateway
            )
            passed += 1

        except Exception as error:
            failed += 1
            print(f"\nFAIL: {type(error).__name__}")
            print("The alert could not be analyzed.")

    print("\n" + "=" * 65)
    print("DEMONSTRATION RESULTS")
    print("=" * 65)
    print("Alerts processed:", len(selected_events))
    print("Passed:          ", passed)
    print("Failed:          ", failed)
    print("Original evidence was not modified by this script.")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())