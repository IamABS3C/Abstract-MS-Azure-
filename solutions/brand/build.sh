#!/usr/bin/env bash
# Renders the PNGs in this folder from their SVG sources. The logo SVGs are the official
# Abstract Security lockups; do not edit or redraw them. Needs rsvg-convert and the Barlow,
# Barlow Semi Condensed and JetBrains Mono fonts installed (the banner text uses them).
set -euo pipefail
cd "$(dirname "$0")"
rsvg-convert -z 2 readme-banner.svg -o readme-banner.png
rsvg-convert -z 2 portal-badge.svg -o portal-badge.png
rsvg-convert -h 120 abstract-logo-white.svg -o abstract-logo-white.png
rsvg-convert -h 120 abstract-logo-black.svg -o abstract-logo-black.png
