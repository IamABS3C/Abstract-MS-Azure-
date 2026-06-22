#!/usr/bin/env bash
# Abstract AI-SOC — one-command local launcher.
#   ./run.sh           create env if needed, register kernel, open JupyterLab
#   ./run.sh --check    validate env + imports and exit 0 (no launch; for CI)
#   ./run.sh --app      build the self-contained console.html dashboard + open it (no kernel)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # safe under trailing-space repo path
CONDA="${HOME}/miniforge3/bin/conda"
ENV="abstract-soc"

if [ ! -x "$CONDA" ]; then
  echo "Miniforge not found at $CONDA." >&2
  echo "Install it: https://github.com/conda-forge/miniforge (or: brew install miniforge)" >&2
  exit 1
fi

if ! "$CONDA" env list | grep -qE "(^|/)${ENV}([[:space:]]|\$)"; then
  echo "Creating '${ENV}' env from environment.yml ..."
  "$CONDA" env create -f "${HERE}/environment.yml"
fi

# Register the Jupyter kernel if missing.
if ! "$CONDA" run -n "$ENV" jupyter kernelspec list 2>/dev/null | grep -q "abstract-soc"; then
  "$CONDA" run -n "$ENV" python -m ipykernel install --user \
    --name abstract-soc --display-name "Abstract AI-SOC"
fi

if [ "${1:-}" = "--check" ]; then
  "$CONDA" run -n "$ENV" python -c \
    "import jupyterlab,ipywidgets,matplotlib,networkx,pandas,plotly,pyvis,mcp,requests; print('env OK')"
  exit 0
fi

if [ "${1:-}" = "--app" ]; then
  # build the self-contained interactive dashboard (no kernel) and open it in a browser
  ( cd "$HERE" && "$CONDA" run -n "$ENV" python console_app.py )
  open "${HERE}/console.html" 2>/dev/null || xdg-open "${HERE}/console.html" 2>/dev/null \
    || echo "open ${HERE}/console.html in any browser"
  exit 0
fi

echo "Launching JupyterLab — pick the 'Abstract AI-SOC' kernel."
exec "$CONDA" run -n "$ENV" jupyter lab "${HERE}/soc_notebook.ipynb"
