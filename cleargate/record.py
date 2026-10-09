from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cleargate.canonical import canonical_json, digest

GENESIS = "0" * 64


def load_or_create_key(state_dir: Path, records_dir: Path) -> Ed25519PrivateKey:
    key_path = state_dir / "signing_key.pem"
    pub_path = records_dir / "signing_pub.pem"
    if key_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        assert isinstance(key, Ed25519PrivateKey)
    else:
        state_dir.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        key_path.chmod(0o600)
    records_dir.mkdir(parents=True, exist_ok=True)
    pub_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))
    return key


def public_key_fingerprint(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


class SignedRecord:
    def __init__(self, path: Path, key: Ed25519PrivateKey, header: dict[str, Any]):
        self.path = path
        self._key = key
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = GENESIS
        path.parent.mkdir(parents=True, exist_ok=True)
        path.unlink(missing_ok=True)
        self.append({"kind": "header", "pubkey_sha256": public_key_fingerprint(key), "created": time.time(), **header})

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            body: dict[str, Any] = {"seq": self._seq, "prev_hash": self._prev, "payload": payload}
            if "args" in payload:
                body["args_digest"] = digest(payload["args"])
            line_hash = digest(body)
            signature = base64.b64encode(self._key.sign(line_hash.encode("ascii"))).decode("ascii")
            entry = body | {"hash": line_hash, "sig": signature}
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(canonical_json(entry) + "\n")
            self._seq += 1
            self._prev = line_hash
            return entry


def read_record(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
