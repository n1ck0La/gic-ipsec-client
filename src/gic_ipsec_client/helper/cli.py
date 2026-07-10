from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from gic_ipsec_client import __version__
from gic_ipsec_client.helper import privileged


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gic-ipsec-helper")
    subcommands = parser.add_subparsers(dest="command", required=True)

    render = subcommands.add_parser(
        "render-profile",
        help="Render validated profile into the active swanctl config root.",
    )
    render.add_argument("--request", required=True, type=Path)
    render.add_argument("--config-root", default="")

    delete = subcommands.add_parser("delete-profile", help="Delete GIC swanctl files for a UUID.")
    delete.add_argument("--profile-uuid", required=True)
    delete.add_argument("--config-root", default="")

    load = subcommands.add_parser("load-profile", help="Run swanctl --load-all.")
    load.add_argument("--config-root", default="")

    connect = subcommands.add_parser("connect-profile", help="Initiate a rendered profile.")
    connect.add_argument("--profile-uuid", required=True)
    connect.add_argument("--config-root", default="")

    disconnect = subcommands.add_parser("disconnect-profile", help="Terminate a profile.")
    disconnect.add_argument("--profile-uuid", required=True)
    disconnect.add_argument("--config-root", default="")

    reconnect = subcommands.add_parser(
        "reconnect-network-interface",
        help="Reconnect the saved NetworkManager interface after DNS rollback failure.",
    )
    reconnect.add_argument("--profile-uuid", required=True)

    status = subcommands.add_parser("status-profile", help="Print profile status.")
    status.add_argument("--profile-uuid", required=True)
    status.add_argument("--config-root", default="")

    list_sas = subcommands.add_parser("list-sas", help="Run swanctl --list-sas.")
    list_sas.add_argument("--config-root", default="")

    list_conns = subcommands.add_parser("list-conns", help="Run swanctl --list-conns.")
    list_conns.add_argument("--config-root", default="")

    diagnostics = subcommands.add_parser("diagnostics", help="Print swanctl diagnostics as JSON.")
    diagnostics.add_argument("--profile-uuid", default="")
    diagnostics.add_argument("--config-root", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if raw_args and Path(raw_args[0]).name == "gic-ipsec-helper":
        raw_args = raw_args[1:]
    if raw_args[:1] and raw_args[0] in {"--version", "-V"}:
        print(f"gic-ipsec-helper {__version__}")
        return 0
    parser = build_parser()
    args = parser.parse_args(raw_args)
    uid = privileged.helper_uid()

    try:
        if args.command == "render-profile":
            result = privileged.render_profile_from_request(
                args.request,
                uid=uid,
                config_root_override=args.config_root,
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "delete-profile":
            deleted = privileged.delete_profile(
                args.profile_uuid,
                config_root_override=args.config_root,
            )
            print(json.dumps({"deleted": deleted}, sort_keys=True))
            return 0
        if args.command == "load-profile":
            privileged.ensure_runtime_tools()
            return privileged.load_profile()
        if args.command == "connect-profile":
            privileged.ensure_runtime_tools()
            return privileged.connect_profile(
                args.profile_uuid,
                config_root_override=args.config_root,
            )
        if args.command == "disconnect-profile":
            privileged.ensure_runtime_tools()
            return privileged.disconnect_profile(args.profile_uuid)
        if args.command == "reconnect-network-interface":
            return privileged.reconnect_network_interface(args.profile_uuid)
        if args.command == "status-profile":
            privileged.ensure_runtime_tools()
            print(privileged.status_profile(args.profile_uuid))
            return 0
        if args.command == "list-sas":
            privileged.ensure_runtime_tools()
            print(privileged.list_sas())
            return 0
        if args.command == "list-conns":
            privileged.ensure_runtime_tools()
            print(privileged.list_conns())
            return 0
        if args.command == "diagnostics":
            result = privileged.swanctl_diagnostics(
                profile_id=args.profile_uuid or None,
                config_root_override=args.config_root,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
    except Exception as exc:
        print(privileged.error_to_message(exc), file=sys.stderr)
        return 1

    parser.error(f"Unhandled command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
