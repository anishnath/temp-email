#!/bin/bash
# TikZ -> DVI -> SVG pipeline using latex + dvisvgm
# Requires: latex (texlive), dvisvgm
#
# Note: dvisvgm needs TeX paths to find PostScript pro files.
# Set TEXMFDIST to your TeX Live texmf-dist dir if dvisvgm fails.

set -e
cd "$(dirname "$0")"

# TeX Live 2025 basic default location (adjust if needed)
export TEXMFDIST="${TEXMFDIST:-/usr/local/texlive/2025basic/texmf-dist}"
export TEXMFCNF="${TEXMFCNF:-/usr/local/texlive/2025basic/texmf-dist/web2c}"

echo "1. Compiling sample.tex with latex (DVI)..."
echo "   Uses \\documentclass[dvisvgm]{minimal} for clean SVG output"
latex -interaction=nonstopmode sample.tex

echo ""
echo "2. Converting DVI to SVG with dvisvgm..."
dvisvgm --no-fonts -o sample.svg sample.dvi

echo ""
echo "Done. Output: sample.svg"
ls -la sample.svg
