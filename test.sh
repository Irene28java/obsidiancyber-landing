#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PYTHON=python3
if [[ -x ".venv/bin/python" ]]; then PYTHON=".venv/bin/python"; fi
"$PYTHON" -m py_compile server.py
if command -v node >/dev/null 2>&1; then node --check script.js; else echo "Node.js no instalado: se omite la comprobación de sintaxis JavaScript."; fi
"$PYTHON" -m unittest discover -s tests -v
