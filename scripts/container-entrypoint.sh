#!/bin/sh
set -eu

# New database, journal, and lock files must not inherit a permissive host mask.
umask 077

exec "$@"
