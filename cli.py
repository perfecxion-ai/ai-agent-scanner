#!/usr/bin/env python3
"""Compatibility entry point for the maintained scanner CLI."""

import sys

import click

from scanner_cli import cli


def main():
    """Forward legacy discovery flags without retaining a second scan engine."""
    arguments = sys.argv[1:]
    if arguments and arguments[0].startswith('-') and arguments[0] not in {'--help', '--version'}:
        arguments = ['discover', *arguments]
    click.echo('cli.py is deprecated; use ai-agent-scanner.', err=True)
    cli(args=arguments, prog_name='ai-agent-scanner')


if __name__ == '__main__':
    main()
