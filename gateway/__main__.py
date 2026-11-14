"""Run the gateway.

    python -m gateway --policy-dir policies --upstream http://127.0.0.1:8001/mcp

Agent keys come from the AGENT_KEYS env var (a JSON object of
key -> agent id) or from --keys-file. The admin key comes from
GATEWAY_ADMIN_KEY. The audit log defaults to data/audit.jsonl.
Only run this against tool servers you control — the gateway is the
enforcement point, and it must be the only path an agent has to the
tools.
"""
from __future__ import annotations

import argparse
import json
import os

import uvicorn

from .proxy import Gateway, create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent Gateway")
    parser.add_argument("--policy-dir", default="policies")
    parser.add_argument("--upstream", default="http://127.0.0.1:8001/mcp",
                        help="upstream MCP server URL (JSON-RPC over HTTP)")
    parser.add_argument("--audit", default="data/audit.jsonl")
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--keys-file", default=None,
                        help="JSON file of api-key -> agent id")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    keys: dict[str, str] = {}
    if args.keys_file and os.path.exists(args.keys_file):
        keys = json.loads(open(args.keys_file, encoding="utf-8").read())
    if os.environ.get("AGENT_KEYS"):
        keys.update(json.loads(os.environ["AGENT_KEYS"]))
    if not keys:
        keys = {"demo-key-support-bot": "support-bot"}
        print("No agent keys configured — using the demo key "
              "'demo-key-support-bot' for agent support-bot. "
              "Set AGENT_KEYS or --keys-file in production.")
    gateway = Gateway(policy_dir=args.policy_dir, keys=keys,
                      upstream_url=args.upstream, audit_path=args.audit,
                      data_dir=args.data_dir)
    print(f"Agent Gateway listening on http://{args.host}:{args.port}")
    print(f"upstream: {args.upstream}")
    print(f"agents: {sorted(gateway.policies)}")
    uvicorn.run(create_app(gateway), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
