from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import time
from importlib import import_module, util
from typing import Any, Dict, Optional

DEFAULT_PORT = 4433
DEFAULT_TIMEOUT = 10  # seconds


class MissingAESCipher(ImportError):
    """Raised when no AES cipher implementation is available."""


def _load_aes_cipher():
    for module_name in ("Cryptodome.Cipher.AES", "Crypto.Cipher.AES"):
        if util.find_spec(module_name) is not None:
            module = import_module(module_name)
            return module.AES
    raise MissingAESCipher(
        "AES cipher not available. Install pycryptodome or pycryptodomex:\n"
        "  pip install pycryptodome\n"
        "  # or\n"
        "  pip install pycryptodomex"
    )


AES = _load_aes_cipher()


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


def generate_token(cmd: str, account_password: str, salt: str, ts: int) -> tuple[str, bytes]:
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
        except Exception as exc:  # pragma: no cover - input validation
            raise ValueError(f"Failed to parse --param-json: {exc}")
    if param_file is not None:
        if not os.path.exists(param_file):
            raise FileNotFoundError(f"Param file not found: {param_file}")
        with open(param_file, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except Exception as exc:  # pragma: no cover - input validation
                raise ValueError(f"Failed to parse param file JSON: {exc}")
    return None


__all__ = [
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
    "call_whatsminer",
    "encrypt_param_aes_ecb_base64",
    "generate_token",
    "load_miner_conf",
    "parse_scalar",
    "resolve_param_inputs",
    "send_request_and_receive",
]
