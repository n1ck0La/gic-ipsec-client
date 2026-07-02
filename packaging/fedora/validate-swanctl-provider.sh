#!/usr/bin/env bash
set -euo pipefail

dnf repoquery --whatprovides '*/swanctl'
