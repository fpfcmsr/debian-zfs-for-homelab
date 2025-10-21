#!/usr/bin/env bash
set -euo pipefail
sudo lb clean --purge || true
sudo lb config
sudo lb build
