#!/data/data/com.termux/files/usr/bin/bash

cd ~/Project_NetraCore

echo "Removing old venv..."
rm -rf venv

echo "Creating new venv..."
python -m venv venv

echo "Upgrading pip, setuptools, wheel..."
./venv/bin/python -m pip install --upgrade pip setuptools wheel

echo "Installing Termux-safe legacy profile..."
./venv/bin/python -m pip install --no-cache-dir \
    "fastapi==0.99.1" \
    "pydantic==1.10.17" \
    "uvicorn==0.22.0"

echo "Verifying installation..."
./venv/bin/python -c "import fastapi, uvicorn, pydantic; print('LEGACY BASE OK')"

echo ""
echo "If you see LEGACY BASE OK, run:"
echo "PYTHONPATH=. ./venv/bin/python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000"
