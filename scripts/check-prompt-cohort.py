#!/usr/bin/env python3
"""Check a predeclared paired-prompt cohort offline, without invoking targets."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.evaluation.benchmark_cohort import CohortError, check_files


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Invalid cohort gate arguments\n")


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--reports-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = check_files(args.plan, args.reports_dir, args.output)
    except (CohortError, KeyboardInterrupt):
        print(
            "Cohort gate failed; no complete evidence set is implied", file=sys.stderr
        )
        return 1
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
