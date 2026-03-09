#!/bin/bash
# Compile all TikZ samples and convert to SVG
# Uses: \documentclass[dvisvgm]{minimal} + latex + dvisvgm --no-fonts

set -e
cd "$(dirname "$0")"

export TEXMFDIST="${TEXMFDIST:-/usr/local/texlive/2025basic/texmf-dist}"
export TEXMFCNF="${TEXMFCNF:-/usr/local/texlive/2025basic/texmf-dist/web2c}"

for f in sample.tex sample2-graph.tex sample3-math.tex sample4-diagram.tex sample5-trees.tex; do
  [ -f "$f" ] || continue
  echo "=== $f ==="
  base="${f%.tex}"
  rm -f "${base}.dvi" "${base}.aux" "${base}.log" "${base}.svg"
  latex -interaction=nonstopmode "$f" > /dev/null 2>&1
  if [ -f "${base}.dvi" ]; then
    dvisvgm --no-fonts -o "${base}.svg" "${base}.dvi" 2>/dev/null
    echo "  OK: ${base}.svg ($(wc -c < "${base}.svg") bytes)"
  else
    echo "  FAIL: no DVI"
  fi
  echo ""
done

echo "Done. SVGs:"
ls -la *.svg 2>/dev/null || true
