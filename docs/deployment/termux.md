# Termux / Edge Node

For field devices (Android) with limited RAM — runs the full gateway in
graceful-degradation mode (FTS5 legal search, pure-Python image forensics).

```bash
pkg install python rust binutils -y   # one-time toolchain
python -m venv venv && source venv/bin/activate
pip install -r requirements-termux.txt
PYTHONPATH=. python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

* Heavy ML (`torch`, `sentence-transformers`) is optional — every module has
  a stdlib fallback, and the API boots without them.
* Vault + audit logs stay on-device (`data/`, `logs/`); sync the JSONL files
  back to HQ for centralized chain verification.
* Serve the SOC dashboard locally at `http://127.0.0.1:8000/dashboard`.
