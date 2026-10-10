"""Run the payments (:9101) and comms (:9102) MCP servers, streamable HTTP at /mcp.

    python -m cleargate.mcp.serve [--host 0.0.0.0] [--payments-port 9101] [--comms-port 9102]
"""
from __future__ import annotations

import argparse
import asyncio
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*authlib.jose.*")


async def _serve(host: str, payments_port: int, comms_port: int, rug_pull: bool = False) -> None:
    from cleargate.mcp import comms, payments

    db, db_label = payments.open_backend()
    slack, slack_label = comms.open_slack()
    comms_label = f"{slack_label}; email stub .cleargate/email_outbox.jsonl"
    if rug_pull:
        comms_label += "; RUG-PULL: post_incident_update description poisoned (catalog-drift demo)"
    servers = [
        ("payments", payments.build(db), payments_port, db_label),
        ("comms", comms.build(slack=slack, rug_pull=rug_pull), comms_port, comms_label),
    ]
    for name, _, port, label in servers:
        print(f"[{name}] http://localhost:{port}/mcp  (runtime: http://host.docker.internal:{port}/mcp)  backend: {label}",
              flush=True)
    await asyncio.gather(*(
        server.run_http_async(transport="http", host=host, port=port, path="/mcp", show_banner=False,
                              log_level="warning")
        for _, server, port, _ in servers
    ))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cleargate mcp-serve", description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--payments-port", type=int, default=9101)
    parser.add_argument("--comms-port", type=int, default=9102)
    parser.add_argument("--rug-pull", action="store_true",
                        help="poison post_incident_update's description (catalog-drift demo; env CLEARGATE_RUGPULL=1)")
    args = parser.parse_args(argv)
    import os
    rug_pull = args.rug_pull or os.environ.get("CLEARGATE_RUGPULL", "") not in ("", "0", "false", "False")
    try:
        asyncio.run(_serve(args.host, args.payments_port, args.comms_port, rug_pull=rug_pull))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
