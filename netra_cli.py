#!/usr/bin/env python3
"""
Netra-Core operator CLI (stdlib-only — no dependencies required).

Usage:
    python netra_cli.py health
    python netra_cli.py token --api-key <KEY>              # exchange key for token
    python netra_cli.py intake --case CASE-1 --target network \\
        --evidence evidence.txt --priority HIGH \\
        --warrant W-1 --issued-by "Cyber Cell" --expires 2026-12-31
    python netra_cli.py cases
    python netra_cli.py findings CASE-1 --severity CRITICAL
    python netra_cli.py summary CASE-1
    python netra_cli.py verify CASE-1
    python netra_cli.py report CASE-1 --signed --out report.pdf
    python netra_cli.py export CASE-1 --out bundle.json
    python netra_cli.py audit --verify
    python netra_cli.py listen                             # SOC stream (needs `websockets`)

Auth: --agent AGENT-ID (dev mode) | --api-key KEY | --token TOKEN
      or env NETRA_API_URL / NETRA_API_KEY / NETRA_TOKEN / NETRA_AGENT_ID
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API = os.getenv("NETRA_API_URL", "http://127.0.0.1:8000")


def _headers(args) -> dict:
    headers = {"Content-Type": "application/json"}
    token = getattr(args, "token", None) or os.getenv("NETRA_TOKEN", "")
    api_key = getattr(args, "api_key", None) or os.getenv("NETRA_API_KEY", "")
    agent = getattr(args, "agent", None) or os.getenv("NETRA_AGENT_ID", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if api_key:
        headers["X-API-Key"] = api_key
    if agent:
        headers["X-Agent-ID"] = agent
    return headers


def _req(method: str, path: str, args, payload=None, raw_out: str = ""):
    url = API.rstrip("/") + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=_headers(args), method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = resp.read()
            if raw_out:
                with open(raw_out, "wb") as f:
                    f.write(body)
                print(f"Saved → {raw_out} ({len(body)} bytes)")
                return None
            ctype = resp.headers.get("Content-Type", "")
            if "application/json" in ctype:
                return json.loads(body.decode())
            print(body.decode(errors="replace"))
            return None
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode()
        except Exception:
            detail = e.reason
        print(f"HTTP {e.code}: {detail}", file=sys.stderr)
        sys.exit(1)


def _show(obj):
    print(json.dumps(obj, indent=2, default=str))


def add_auth(p):
    p.add_argument("--agent", default="", help="Agent ID (dev mode header)")
    p.add_argument("--api-key", default="", help="API key")
    p.add_argument("--token", default="", help="Bearer token")
    return p


def main():
    global API
    ap = argparse.ArgumentParser(prog="netra", description="Netra-Core operator CLI")
    ap.add_argument("--api", default=API, help="API base URL")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health", help="Basic health check")

    p = sub.add_parser("status", help="Detailed health + runtime info")
    add_auth(p)

    p = sub.add_parser("token", help="Exchange API key for a bearer token")
    p.add_argument("--api-key", required=True)

    p = sub.add_parser("intake", help="Submit a case (sync)")
    add_auth(p)
    p.add_argument("--case", required=True)
    p.add_argument("--target", required=True, choices=["android", "cloud", "media", "network"])
    p.add_argument("--evidence", required=True)
    p.add_argument("--priority", default="MEDIUM", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p.add_argument("--warrant", required=True)
    p.add_argument("--issued-by", default="Cyber Cell")
    p.add_argument("--expires", default="2026-12-31T23:59:59Z")
    p.add_argument("--full-access", action="store_true", default=True)
    p.add_argument("--async", dest="bg", action="store_true", help="Background job")

    p = sub.add_parser("cases", help="List cases")
    add_auth(p)
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--priority", default=None)
    p.add_argument("--target", default=None)

    p = sub.add_parser("findings", help="List/search findings")
    add_auth(p)
    p.add_argument("case_id")
    p.add_argument("--severity", default=None)
    p.add_argument("--module", default=None)
    p.add_argument("-q", default=None)
    p.add_argument("--limit", type=int, default=50)

    p = sub.add_parser("summary", help="Case summary")
    add_auth(p)
    p.add_argument("case_id")

    p = sub.add_parser("verify", help="Verify evidence chain")
    add_auth(p)
    p.add_argument("case_id")

    p = sub.add_parser("report", help="Download PDF report")
    add_auth(p)
    p.add_argument("case_id")
    p.add_argument("--signed", action="store_true")
    p.add_argument("--out", required=True)

    p = sub.add_parser("export", help="Export evidence bundle (JSON)")
    add_auth(p)
    p.add_argument("case_id")
    p.add_argument("--out", default="")

    p = sub.add_parser("delete", help="Delete a case (admin only)")
    add_auth(p)
    p.add_argument("case_id")

    p = sub.add_parser("job", help="Check background job")
    add_auth(p)
    p.add_argument("job_id")

    p = sub.add_parser("audit", help="Audit log: recent entries or verify chain")
    add_auth(p)
    p.add_argument("--verify", action="store_true")
    p.add_argument("--limit", type=int, default=20)

    p = sub.add_parser("listen", help="Stream live SOC alerts")
    p.add_argument("--token", default=os.getenv("NETRA_TOKEN", ""))

    args = ap.parse_args()
    API = args.api

    if args.cmd == "health":
        _show(_req("GET", "/health", args))
    elif args.cmd == "status":
        _show(_req("GET", "/v2/health", args))
    elif args.cmd == "token":
        _show(_req("POST", "/v1/auth/token", args, {"api_key": args.api_key}))
    elif args.cmd == "intake":
        payload = {
            "case_id": args.case,
            "legal_authority": {
                "warrant_id": args.warrant,
                "issued_by": args.issued_by,
                "expires_at": args.expires,
                "scope": {"full_access": args.full_access},
            },
            "target_type": args.target,
            "evidence_uri": args.evidence,
            "priority": args.priority,
        }
        path = "/v1/cases/intake/async" if args.bg else "/v1/cases/intake"
        _show(_req("POST", path, args, payload))
    elif args.cmd == "cases":
        qs = f"?limit={args.limit}&offset={args.offset}"
        if args.priority:
            qs += f"&priority={args.priority}"
        if args.target:
            qs += f"&target_type={args.target}"
        _show(_req("GET", f"/v1/cases{qs}", args))
    elif args.cmd == "findings":
        qs = f"?limit={args.limit}"
        if args.severity:
            qs += f"&severity={args.severity}"
        if args.module:
            qs += f"&module={args.module}"
        if args.q:
            qs += f"&q={args.q}"
        _show(_req("GET", f"/v1/cases/{args.case_id}/findings{qs}", args))
    elif args.cmd == "summary":
        _show(_req("GET", f"/v1/cases/{args.case_id}/summary", args))
    elif args.cmd == "verify":
        _show(_req("GET", f"/v1/evidence/verify/{args.case_id}", args))
    elif args.cmd == "report":
        path = ("/v1/cases/{}/report/signed" if args.signed else "/v1/cases/{}/report/pdf").format(
            args.case_id
        )
        _req("GET", path, args, raw_out=args.out)
    elif args.cmd == "export":
        bundle = _req("GET", f"/v1/cases/{args.case_id}/export", args)
        if args.out:
            with open(args.out, "w") as f:
                json.dump(bundle, f, indent=2, default=str)
            print(f"Saved → {args.out}")
        else:
            _show(bundle)
    elif args.cmd == "delete":
        _show(_req("DELETE", f"/v1/cases/{args.case_id}", args))
    elif args.cmd == "job":
        _show(_req("GET", f"/v1/jobs/{args.job_id}", args))
    elif args.cmd == "audit":
        if args.verify:
            _show(_req("GET", "/v1/audit/verify", args))
        else:
            _show(_req("GET", f"/v1/audit/recent?limit={args.limit}", args))
    elif args.cmd == "listen":
        try:
            import asyncio

            import websockets
        except ImportError:
            print("Install the 'websockets' package for live streaming.", file=sys.stderr)
            sys.exit(2)

        async def _run():
            ws_url = API.replace("http", "ws") + "/ws/soc-dashboard"
            if args.token:
                ws_url += f"?token={args.token}"
            print(f"Connecting to {ws_url} ...")
            async with websockets.connect(ws_url) as ws:
                print("Connected. Waiting for alerts (Ctrl+C to stop)...")
                while True:
                    print(json.dumps(json.loads(await ws.recv()), indent=2))

        asyncio.run(_run())


if __name__ == "__main__":
    main()
