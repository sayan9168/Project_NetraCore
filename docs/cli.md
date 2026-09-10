# Operator CLI

`netra_cli.py` is **stdlib-only** — it runs anywhere Python does, no `pip install`.

```bash
python netra_cli.py health
python netra_cli.py intake --agent soc-op --case CASE-1 --target network \
  --evidence "beacon to 203.0.113.45" --priority HIGH \
  --warrant W-1 --issued-by "Cyber Cell" --expires 2026-12-31T23:59:59Z
python netra_cli.py findings CASE-1 --severity CRITICAL
python netra_cli.py summary CASE-1
python netra_cli.py verify CASE-1
python netra_cli.py report CASE-1 --signed --out report.pdf
python netra_cli.py export CASE-1 --out bundle.json
python netra_cli.py audit --verify
python netra_cli.py listen        # live SOC stream (needs `websockets`)
```

Auth flags: `--agent`, `--api-key`, `--token`
(or env `NETRA_API_URL`, `NETRA_AGENT_ID`, `NETRA_API_KEY`, `NETRA_TOKEN`).
Background intake: add `--async`, then `python netra_cli.py job <job_id>`.
