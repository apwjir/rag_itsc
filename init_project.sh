#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/venv/bin/python" ]]; then
  PYTHON="$ROOT_DIR/venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
else
  PYTHON="python"
fi

echo "Using Python: $PYTHON"

echo "[1/4] Initializing Elasticsearch index..."
"$PYTHON" init_es_index.py

echo "[2/4] Ingesting MITRE data into Qdrant..."
"$PYTHON" ingest_data.py

echo "[3/4] Creating PostgreSQL tables..."
"$PYTHON" app/create_db.py

echo "[4/4] Seeding admin user..."
"$PYTHON" app/seed_admin.py

echo "Done. Project initialization completed successfully."
