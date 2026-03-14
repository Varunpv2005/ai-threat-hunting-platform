#!/usr/bin/env python3
"""
CLI entry point — run the log simulator from the command line.

Usage examples
--------------
# Stream to stdout at default rate
python -m backend.log_simulator.run

# Write to a JSONL file at 10 events/s
python -m backend.log_simulator.run --output file --rate 10

# Export a labeled training batch of 50,000 events
python -m backend.log_simulator.run --mode batch --batch-size 50000 --output file

# Stream to Kafka
python -m backend.log_simulator.run --output kafka --rate 20
"""

import argparse
import json
import sys

from .simulator import LogSimulator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI Threat Hunting — Cybersecurity Log Simulator"
    )
    parser.add_argument(
        "--mode",
        choices=["stream", "batch"],
        default="stream",
        help="stream: continuous; batch: fixed-size export for ML training",
    )
    parser.add_argument("--rate",       type=float, default=5.0,   help="Events per second (stream mode)")
    parser.add_argument("--attack-prob",type=float, default=0.02,  help="Per-second probability of an attack scenario")
    parser.add_argument("--output",     choices=["stdout","file","kafka"], default="stdout")
    parser.add_argument("--output-path",default="logs/simulated.jsonl")
    parser.add_argument("--kafka-topic",default="raw-logs")
    parser.add_argument("--batch-size", type=int,   default=10_000, help="Events to generate in batch mode")
    parser.add_argument("--no-attacks", action="store_true",        help="Batch mode only: omit attack events")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    simulator = LogSimulator(
        events_per_second=args.rate,
        attack_probability=args.attack_prob,
        output=args.output,
        output_path=args.output_path,
        kafka_topic=args.kafka_topic,
    )

    if args.mode == "batch":
        print(f"[simulator] Generating {args.batch_size:,} events...", file=sys.stderr)
        events = simulator.generate_batch(
            n=args.batch_size,
            include_attacks=not args.no_attacks,
        )
        if args.output == "stdout":
            for e in events:
                print(json.dumps(e))
        else:
            with open(args.output_path, "w") as f:
                for e in events:
                    f.write(json.dumps(e) + "\n")
            attack_count = sum(1 for e in events if e.get("label") == 1)
            print(
                f"[simulator] Wrote {len(events):,} events "
                f"({attack_count:,} attacks, "
                f"{len(events)-attack_count:,} normal) → {args.output_path}",
                file=sys.stderr,
            )
    else:
        simulator.run()


if __name__ == "__main__":
    main()
