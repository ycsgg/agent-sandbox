#!/bin/sh
set -eu

if ! command -v asbx >/dev/null 2>&1; then
  echo "asbx is not installed or is not on PATH" >&2
  exit 127
fi

asbx doctor
