#!/usr/bin/env python3
# Yet another Whatsminer tool
# API v3.0.1 utility
# - Send any API command (get.* / set.* / ...) to miner over TCP (default port 4433).
# - Config via CLI or miner-conf.json:
#   {
#     "host": "192.168.1.2",
#     "port": 4433,
#     "login": "super",
#     "password": "passw0rd"
#   }
# - English comments and help messages.
# - CLI parameters:
#   * --param VALUE       -> scalar param (int/float/bool/str)
#   * --param-json JSON   -> structured param (object/array)
#   * --param-file FILE   -> load structured param from JSON file.
#
# Important: AES import compatibility is handled for both pycryptodome and pycryptodomex.

from __future__ import annotations
import argparse
import json
import socket
import struct
import time
import base64
import hashlib
import os
import sys
from typing import Optional, Any, Dict

# AES import compatibility (as requested)
try:
    from Cryptodome.Cipher import AES  # pycryptodomex (Ubuntu/Debian)
except Exception:  # pragma: no cover
    try:
        from Crypto.Cipher import AES  # pycryptodome
    except Exception:  # pragma: no cover
        AES = None

if AES is None:
    raise ImportError(
        "AES cipher not available. Install pycryptodome or pycryptodomex:\n"
        "  pip install pycryptodome\n"
        "  # or\n"
        "  pip install pycryptodomex"
    )

DEFAULT_PORT = 4433
DEFAULT_TIMEOUT = 10  # seconds

def now_ts_int() -> int:
    """Return current unix timestamp as int (seconds)."""
    return int(time.time())

def sha256_digest_bytes(s: str) -> bytes:
    """Return sha256 digest bytes for input string s (utf-8)."""
    return hashlib.sha256(s.encode("utf-8")).digest()

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 pad bytes to block_size."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def generate_token(cmd: str, account_password: str, salt: str, ts: int) -> (str, bytes):
    """
    Token per API v3.0.1:
      digest = sha256(cmd + password + salt + ts)  -> 32 raw bytes
      token  = base64(digest) first 8 chars
    Returns: (token_str, digest_bytes)
    """
    concat = f"{cmd}{account_password}{salt}{ts}"
    digest = sha256_digest_bytes(concat)
    b64 = base64.b64encode(digest).decode("ascii")
    token = b64[:8]
    return token, digest

def encrypt_param_aes_ecb_base64(param_obj: Any, aes_key_bytes: bytes) -> str:
    """
    Encrypt 'param' JSON for selected commands:
      - serialize to compact JSON
      - AES-ECB (key = sha256 digest bytes), PKCS#7 pad
      - base64 encode
    Returns base64 string.
    """
    if aes_key_bytes is None:
        raise ValueError("AES key bytes required for encryption")
    json_str = json.dumps(param_obj, separators=(",", ":"), ensure_ascii=False)
    data = json_str.encode("utf-8")
    padded = pkcs7_pad(data, 16)
    cipher = AES.new(aes_key_bytes, AES.MODE_ECB)
    ct = cipher.encrypt(padded)
    return base64.b64encode(ct).decode("ascii")

def recvall(sock: socket.socket, n: int) -> Optional[bytes]:
    """Receive exactly n bytes or return None on failure/EOF."""
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)

def send_request_and_receive(host: str, port: int, request_obj: dict, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Send request_obj (JSON) to miner using TCP framing:
      - send 4-byte little-endian length + ASCII JSON
      - read 4-byte response length, then JSON
    Returns parsed JSON dict (or {"raw": "..."} if parse fails).
    """
    req_str = json.dumps(request_obj, separators=(",", ":"), ensure_ascii=False)
    req_bytes = req_str.encode("ascii", errors="ignore")  # API uses ASCII payload
    length = len(req_bytes)
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(struct.pack("<I", length))
        s.sendall(req_bytes)
        header = recvall(s, 4)
        if header is None or len(header) < 4:
            raise ConnectionError("Failed to read response length")
        resp_len = struct.unpack("<I", header)[0]
        if resp_len == 0:
            return {}
        resp_bytes = recvall(s, resp_len)
        if resp_bytes is None:
            raise ConnectionError("Failed to read full response")
        resp_text = resp_bytes.decode("utf-8", errors="ignore")
        try:
            return json.loads(resp_text)
        except Exception:
            return {"raw": resp_text}

_ENCRYPTED_COMMANDS = {"set.miner.pools", "set.user.change_passwd"}

def call_whatsminer(
    host: str,
    port: int,
    account: str,
    account_password: str,
    cmd: str,
    param: Optional[Any] = None,
    salt: Optional[str] = None,
    ts: Optional[int] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """
    Generic caller for Whatsminer API.
    For set.* commands:
      - ts and token are required and computed automatically
      - 'salt' must be known (typically from get.device.info 'salt')
      - Certain commands encrypt 'param' (see _ENCRYPTED_COMMANDS)
    """
    request: Dict[str, Any] = {"cmd": cmd}
    is_set_cmd = cmd.startswith("set.")
    ts_val = ts if ts is not None else (now_ts_int() if is_set_cmd else None)

    if is_set_cmd:
        if salt is None:
            raise ValueError("Salt is required for set.* commands. Obtain it via get.device.info (param: \"salt\").")
        token, sha256_digest = generate_token(cmd, account_password, salt, ts_val)
        request.update({"ts": ts_val, "token": token, "account": account})
        if cmd in _ENCRYPTED_COMMANDS:
            if param is None:
                raise ValueError(f"Command {cmd} requires 'param'.")
            enc_b64 = encrypt_param_aes_ecb_base64(param, sha256_digest)
            request["param"] = enc_b64
        else:
            if param is not None:
                request["param"] = param
    else:
        if param is not None:
            request["param"] = param

    return send_request_and_receive(host, port, request, timeout=timeout)

def load_miner_conf(path: str = "miner-conf.json") -> dict:
    """Load miner configuration file if exists, else return {}."""
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def parse_scalar(value: str) -> Any:
    """
    Best-effort scalar parsing:
      - int (e.g., '3200')
      - float (e.g., '12.5')
      - bool true/false (case-insensitive)
      - null -> None
      - otherwise: keep as string
    """
    if value is None:
        return None
    v = value.strip()
    low = v.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "none"):
        return None
    try:
        if v.startswith(("0x", "0X")):
            return int(v, 16)
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v

def resolve_param_inputs(param_scalar: Optional[str], param_json: Optional[str], param_file: Optional[str]) -> Optional[Any]:
    """
    Resolve mutually exclusive param sources:
      - --param: scalar (auto-cast)
      - --param-json: JSON string -> object/array/primitive
      - --param-file: read JSON from file
    """
    if param_scalar is not None:
        return parse_scalar(param_scalar)
    if param_json is not None:
        try:
            return json.loads(param_json)
        except Exception as e:
            raise ValueError(f"Failed to parse --param-json: {e}")
    if param_file is not None:
        if not os.path.exists(param_file):
            raise FileNotFoundError(f"Param file not found: {param_file}")
        with open(param_file, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except Exception as e:
                raise ValueError(f"Failed to parse param file JSON: {e}")
    return None

def main():
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

    g = callp.add_mutually_exclusive_group()
    g.add_argument("--param", help="Scalar param value (int/float/bool/string). Example: --param 3200")
    g.add_argument("--param-json", help="Param as JSON string. Example: --param-json '{\"pools\":[...]}'.")
    g.add_argument("--param-file", help="Param from JSON file. Example: --param-file pools.json")

    callp.add_argument("--salt", help="Salt value (optional). For set.* commands you should provide or obtain from get.device.info")
    callp.add_argument("--ts", type=int, help="Timestamp integer to use for token generation (optional)")
    callp.add_argument("--show-request", action="store_true", help="Print JSON request that will be sent (for debugging)")
    callp.add_argument("--save-response", help="Save response JSON to file")

    args = parser.parse_args()

    conf = load_miner_conf(args.config)
    host = args.host or conf.get("host")
    port = args.port or conf.get("port") or DEFAULT_PORT
    account = args.login or conf.get("login") or "super"
    password = args.password or conf.get("password")

    if host is None or password is None:
        print("Error: host and password must be supplied either via CLI or miner-conf.json", file=sys.stderr)
        parser.print_help()
        sys.exit(2)

    if args.action == "get-salt":
        try:
            resp = call_whatsminer(host, port, account, password, "get.device.info", args.param, salt=None, ts=None, timeout=args.timeout)
            print(json.dumps(resp, indent=2, ensure_ascii=False))
            try:
                if isinstance(resp.get("msg"), dict) and "salt" in resp["msg"]:
                    print("\nExtracted salt:", resp["msg"]["salt"])
            except Exception:
                pass
        except Exception as e:
            print("Error:", e, file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

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

        except Exception as e:
            print("Error while calling API:", e, file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
