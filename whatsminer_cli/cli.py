from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional

from .core import (
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    _ENCRYPTED_COMMANDS,
    call_whatsminer,
    generate_token,
    load_miner_conf,
    now_ts_int,
    resolve_param_inputs,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Whatsminer CLI utility (API v3.0.1). Use miner-conf.json or CLI args for connection credentials."
    )
    parser.add_argument("--config", "-c", default="miner-conf.json", help="Path to miner-conf.json (default: miner-conf.json)")
    parser.add_argument("--host", help="Miner host (overrides config)")
    parser.add_argument("--port", type=int, help=f"Miner TCP port (default {DEFAULT_PORT})")
    parser.add_argument("--login", help="Account name (e.g., super)")
    parser.add_argument("--password", help="Account password (overrides config)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Socket timeout seconds")

    sub = parser.add_subparsers(dest="action", required=True)

    gs = sub.add_parser("get-salt", help="Call get.device.info and show salt (useful before set.* commands)")
    gs.add_argument("--param", default="salt", help="Parameter for get.device.info (default: salt)")

    callp = sub.add_parser("call", help="Call any API command")
    callp.add_argument("cmd", help="Command name, e.g., get.device.info or set.miner.pools")

    group = callp.add_mutually_exclusive_group()
    group.add_argument("--param", help="Scalar param value (int/float/bool/string). Example: --param 3200")
    group.add_argument("--param-json", help="Param as JSON string. Example: --param-json '{\"pools\":[...]}'.")
    group.add_argument("--param-file", help="Param from JSON file. Example: --param-file pools.json")

    callp.add_argument("--salt", help="Salt value (optional). For set.* commands you should provide or obtain from get.device.info")
    callp.add_argument("--ts", type=int, help="Timestamp integer to use for token generation (optional)")
    callp.add_argument("--show-request", action="store_true", help="Print JSON request that will be sent (for debugging)")
    callp.add_argument("--save-response", help="Save response JSON to file")

    return parser


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = build_parser()
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    conf = load_miner_conf(args.config)
    host = args.host or conf.get("host")
    port = args.port or conf.get("port") or DEFAULT_PORT
    account = args.login or conf.get("login") or "super"
    password = args.password or conf.get("password")

    if host is None or password is None:
        print("Error: host and password must be supplied either via CLI or miner-conf.json", file=sys.stderr)
        build_parser().print_help()
        return 2

    if args.action == "get-salt":
        try:
            resp = call_whatsminer(host, port, account, password, "get.device.info", args.param, salt=None, ts=None, timeout=args.timeout)
            print(json.dumps(resp, indent=2, ensure_ascii=False))
            try:
                if isinstance(resp.get("msg"), dict) and "salt" in resp["msg"]:
                    print("\nExtracted salt:", resp["msg"]["salt"])
            except Exception:
                pass
        except Exception as exc:
            print("Error:", exc, file=sys.stderr)
            return 1
        return 0

    if args.action == "call":
        cmd = args.cmd
        param_obj = resolve_param_inputs(args.param, args.param_json, args.param_file)
        provided_salt = args.salt

        try:
            if cmd.startswith("set.") and not provided_salt:
                print("Fetching salt from get.device.info ...")
                info = call_whatsminer(host, port, account, password, "get.device.info", "salt", salt=None, ts=None, timeout=args.timeout)
                if isinstance(info.get("msg"), dict) and info["msg"].get("salt"):
                    provided_salt = info["msg"]["salt"]
                    print("Obtained salt:", provided_salt)
                else:
                    print("Warning: Could not obtain salt automatically; please supply --salt", file=sys.stderr)

            if args.show_request:
                ts_to_use = args.ts if args.ts is not None else (now_ts_int() if cmd.startswith("set.") else None)
                preview_req: Dict[str, Any] = {"cmd": cmd}
                if cmd.startswith("set."):
                    if provided_salt:
                        token, _digest = generate_token(cmd, password, provided_salt, ts_to_use)
                        preview_req.update({"ts": ts_to_use, "token": token, "account": account})
                        if cmd in _ENCRYPTED_COMMANDS:
                            preview_req["param"] = "<ENCRYPTED_BASE64>"
                        elif param_obj is not None:
                            preview_req["param"] = param_obj
                    else:
                        preview_req["note"] = "salt missing; token not computed"
                else:
                    if param_obj is not None:
                        preview_req["param"] = param_obj
                print("=== Request preview ===")
                print(json.dumps(preview_req, indent=2, ensure_ascii=False))
                print("=======================")

            resp = call_whatsminer(host, port, account, password, cmd, param_obj, salt=provided_salt, ts=args.ts, timeout=args.timeout)
            print(json.dumps(resp, indent=2, ensure_ascii=False))
            if args.save_response:
                with open(args.save_response, "w", encoding="utf-8") as f:
                    json.dump(resp, f, indent=2, ensure_ascii=False)
                print("Saved response to", args.save_response)

        except Exception as exc:
            print("Error while calling API:", exc, file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
