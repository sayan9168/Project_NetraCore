#!/data/data/com.termux/files/usr/bin/bash
set -e

cd ~/Project_NetraCore
PY=./venv/bin/python

echo "🔧 Recreating clean virtual environment..."
rm -rf venv
python -m venv venv

echo "🔧 Upgrading pip..."
$PY -m pip install --upgrade pip setuptools wheel

echo "📦 Installing CORE (fastapi + uvicorn + pydantic v1)..."
$PY -m pip install --no-cache-dir "fastapi<0.100" "pydantic<2" "uvicorn==0.22.0"

echo "📦 Installing ENTERPRISE layers (rate-limit, ws, cloud, pdf)..."
$PY -m pip install --no-cache-dir slowapi websockets boto3 fpdf2 \
    || echo "⚠️ WARNING: some optional packages failed"

echo "📦 Installing cryptography (optional: RSA PDF signing)..."
$PY -m pip install --no-cache-dir cryptography \
    || echo "⚠️ WARNING: cryptography failed - RSA signing disabled"

echo "✅ Verifying core imports..."
$PY -c "import fastapi, uvicorn, pydantic, slowapi, boto3, fpdf2; print('ALL CORE OK')"

echo "🚀 Starting Netra-Core Enterprise Server..."
PYTHONPATH=. $PY -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
