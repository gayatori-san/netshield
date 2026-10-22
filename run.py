#!/usr/bin/env python3
"""NetShield entry point.

    python run.py                  # http://127.0.0.1:5000
    python run.py --port 8080
    python run.py --host 0.0.0.0   # only on a trusted lab network

Settings come from config/thresholds.toml plus NETSHIELD_* environment
variables (see .env.example). The reloader is always off: the pipeline owns
background threads, and a reloader restart would leave orphaned sniffers.
"""

from __future__ import annotations

import argparse
import sys

from netshield.api.app import create_app
from netshield.config.settings import ConfigError, load_settings

BANNER = """\
  NetShield — network attack detection (educational)
  ---------------------------------------------------
  URL       : http://{host}:{port}/
  Database  : {db}
  Capture   : replay a PCAP, run the demo, or sniff an interface
  Safety    : simulated response by default; real firewall changes stay off
  Warning   : observe only traffic you are authorised to capture.
"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="netshield",
        description="Run the NetShield detection dashboard.",
    )
    parser.add_argument("--host", help="bind address (default: settings host)")
    parser.add_argument("--port", type=int, help="TCP port (default: settings port)")
    parser.add_argument("--debug", action="store_true", help="enable Flask debug logging")
    parser.add_argument(
        "--no-demo-pace",
        action="store_true",
        help="run the demo scenario as fast as possible (for a quick check)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"netshield: configuration error: {exc}", file=sys.stderr)
        return 2

    host = args.host or settings.host
    port = settings.port if args.port is None else args.port
    if not 0 < port < 65536:
        print(f"netshield: invalid port {port}", file=sys.stderr)
        return 2

    app = create_app(settings, demo_pace=not args.no_demo_pace)
    pipeline = app.extensions["netshield"].pipeline

    print(BANNER.format(host="127.0.0.1" if host in ("0.0.0.0", "::") else host, port=port, db=settings.db_path))
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "  NOTE: the dashboard has no authentication. Binding beyond loopback\n"
            "        exposes capture controls to anyone who can reach this port.\n",
            file=sys.stderr,
        )

    try:
        app.run(
            host=host,
            port=port,
            debug=args.debug or settings.debug,
            use_reloader=False,
            threaded=True,
        )
    except KeyboardInterrupt:
        pass
    finally:
        pipeline.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
