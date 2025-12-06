import base64
import json

import pytest

from whatsminer_cli import core
from whatsminer_cli.core import (
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    call_whatsminer,
    encrypt_param_aes_ecb_base64,
    generate_token,
    parse_scalar,
    resolve_param_inputs,
)


def _unpad_pkcs7(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def test_parse_scalar_conversions():
    assert parse_scalar("3200") == 3200
    assert parse_scalar("12.5") == 12.5
    assert parse_scalar("true") is True
    assert parse_scalar("False") is False
    assert parse_scalar("null") is None
    assert parse_scalar("0x10") == 16
    assert parse_scalar("text") == "text"


def test_resolve_param_inputs_priority(tmp_path):
    json_value = {"item": 1}
    json_file = tmp_path / "param.json"
    json_file.write_text(json.dumps(json_value), encoding="utf-8")

    assert resolve_param_inputs("5", None, None) == 5
    assert resolve_param_inputs(None, json.dumps(json_value), None) == json_value
    assert resolve_param_inputs(None, None, str(json_file)) == json_value

    with pytest.raises(FileNotFoundError):
        resolve_param_inputs(None, None, tmp_path / "missing.json")


# Token generation should be deterministic for the same inputs

def test_generate_token_deterministic():
    token, digest = generate_token("set.miner.power", "passw0rd", "salt123", 1700000000)
    expected_digest = core.sha256_digest_bytes("set.miner.powerpassw0rdsalt1231700000000")
    expected_token = base64.b64encode(expected_digest).decode("ascii")[:8]

    assert digest == expected_digest
    assert token == expected_token


def test_encrypt_param_aes_ecb_base64_roundtrip():
    param = {"foo": "bar", "num": 42}
    aes_key = core.sha256_digest_bytes("encryption-key")

    encoded = encrypt_param_aes_ecb_base64(param, aes_key)
    cipher = core.AES.new(aes_key, core.AES.MODE_ECB)
    padded = cipher.decrypt(base64.b64decode(encoded))
    decoded = json.loads(_unpad_pkcs7(padded).decode("utf-8"))

    assert decoded == param


def test_call_whatsminer_builds_set_request(monkeypatch):
    captured = {}

    def fake_send(host: str, port: int, request_obj: dict, timeout: int = DEFAULT_TIMEOUT):
        captured["host"] = host
        captured["port"] = port
        captured["timeout"] = timeout
        captured["request"] = request_obj
        return {"STATUS": "S"}

    monkeypatch.setattr(core, "send_request_and_receive", fake_send)

    param = {"pools": [{"url": "pool", "user": "u", "pass": "x"}]}
    salt = "salty"
    ts = 1111

    response = call_whatsminer("1.2.3.4", DEFAULT_PORT, "super", "password", "set.miner.pools", param, salt=salt, ts=ts, timeout=5)

    assert response == {"STATUS": "S"}
    assert captured["host"] == "1.2.3.4"
    assert captured["port"] == DEFAULT_PORT
    assert captured["timeout"] == 5

    request = captured["request"]
    assert request["cmd"] == "set.miner.pools"
    assert request["account"] == "super"
    assert request["ts"] == ts

    expected_token, sha_digest = generate_token("set.miner.pools", "password", salt, ts)
    assert request["token"] == expected_token

    cipher = core.AES.new(sha_digest, core.AES.MODE_ECB)
    decoded_json = json.loads(_unpad_pkcs7(cipher.decrypt(base64.b64decode(request["param"]))).decode("utf-8"))
    assert decoded_json == param


def test_call_whatsminer_requires_salt():
    with pytest.raises(ValueError):
        call_whatsminer("host", 1, "acc", "pwd", "set.miner.power")
