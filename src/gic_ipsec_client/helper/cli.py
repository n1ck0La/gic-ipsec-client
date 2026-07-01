from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from gic_ipsec_client.helper import privileged


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gic-ipsec-helper")
    subcommands = parser.add_subparsers(dest="command", required=True)

    render = subcommands.add_parser(
        "render-profile",
        help="Render validated profile into /etc/swanctl.",
    )
    render.add_argument("--request", required=True, type=Path)

    delete = subcommands.add_parser("delete-profile", help="Delete GIC swanctl files for a UUID.")
    delete.add_argument("--profile-uuid", required=True)

    subcommands.add_parser("load-profile", help="Run swanctl --load-all.")

    connect = subcommands.add_parser("connect-profile", help="Initiate a rendered profile.")
    connect.add_argument("--profile-uuid", required=True)

    disconnect = subcommands.add_parser("disconnect-profile", help="Terminate a profile.")
    disconnect.add_argument("--profile-uuid", required=True)

    status = subcommands.add_parser("status-profile", help="Print profile status.")
    status.add_argument("--profile-uuid", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    uid = privileged.helper_uid()

    try:
        if args.command == "render-profile":
            result = privileged.render_profile_from_request(args.request, uid=uid)
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "delete-profile":
            deleted = privileged.delete_profile(args.profile_uuid)
            print(json.dumps({"deleted": deleted}, sort_keys=True))
            return 0
        if args.command == "load-profile":
            privileged.ensure_runtime_tools()
            return privileged.load_profile()
        if args.command == "connect-profile":
            privileged.ensure_runtime_tools()
            return privileged.connect_profile(args.profile_uuid)
        if args.command == "disconnect-profile":
            privileged.ensure_runtime_tools()
            return privileged.disconnect_profile(args.profile_uuid)
        if args.command == "status-profile":
            privileged.ensure_runtime_tools()
            print(privileged.status_profile(args.profile_uuid))
            return 0
    except Exception as exc:
        print(privileged.error_to_message(exc), file=sys.stderr)
        return 1

    parser.error(f"Unhandled command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
