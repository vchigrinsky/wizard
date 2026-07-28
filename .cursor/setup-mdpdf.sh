#!/usr/bin/env bash
# Ensure Node.js + mdpdf are available (for snapshots that predate Dockerfile changes).
set -euo pipefail

if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  sudo apt-get install -y --no-install-recommends nodejs \
    fonts-dejavu-core fonts-liberation fonts-noto-core \
    libasound2t64 libatk-bridge2.0-0 libatk1.0-0 libcairo2 libcups2 \
    libdbus-1-3 libdrm2 libgbm1 libglib2.0-0 libgtk-3-0 libnspr4 libnss3 \
    libpango-1.0-0 libx11-6 libxcb1 libxcomposite1 libxdamage1 libxext6 \
    libxfixes3 libxkbcommon0 libxrandr2 xdg-utils
fi

if ! command -v mdpdf >/dev/null 2>&1; then
  sudo npm install -g mdpdf
fi

export PUPPETEER_CACHE_DIR="${PUPPETEER_CACHE_DIR:-$HOME/.cache/puppeteer}"
mkdir -p "$PUPPETEER_CACHE_DIR"
if ! find "$PUPPETEER_CACHE_DIR" -type f -name chrome 2>/dev/null | grep -q .; then
  (cd "$(npm root -g)/mdpdf" && npx puppeteer browsers install chrome) || true
fi
