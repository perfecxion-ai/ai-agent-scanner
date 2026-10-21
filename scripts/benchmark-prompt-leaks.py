#!/usr/bin/env python3
"""Explicitly scoped, fixed-budget exploratory prompt comparison."""

import argparse
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.evaluation.prompt_benchmark import BenchmarkConfig, BenchmarkError, benchmark, exclusive_output


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'Invalid prompt benchmark arguments\n')


def main():
    parser = Parser(description=__doc__)
    for name in ('endpoint', 'provider', 'model', 'evidence-context-id', 'canary-env', 'revision', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--allow-network', action='append', required=True)
    parser.add_argument('--allow-loopback', action='store_true')
    parser.add_argument('--api-key-env')
    parser.add_argument('--pairs', type=int, default=10)
    parser.add_argument('--seed', type=int, default=0)
    args = vars(parser.parse_args())
    output = args.pop('output')
    args['allowed_networks'] = tuple(args.pop('allow_network'))
    try:
        config = BenchmarkConfig(**args)
        from src.evaluation.prompt_benchmark import _guard, _prepare
        *_, secrets = _prepare(config)
        _guard(output, secrets)
        with exclusive_output(output) as publish:
            result = asyncio.run(benchmark(config))
            publish(result)
        return 0 if result['status'] == 'completed' else 1
    except (BenchmarkError, KeyboardInterrupt):
        print('Prompt benchmark failed; no complete comparison is implied', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
