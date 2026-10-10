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


SEAL_VERSION = 1


class SignedRecord:
    """Append-only, hash-chained, Ed25519-signed JSONL.

    The file always ends in a signed seal line naming the record count and the final chain hash.
    Each append replaces the previous seal, so the record is sealed whenever the run stops
    writing, and dropping lines from the end leaves an unsealed (or wrongly sealed) file that
    verify.py rejects. The header announces the seal so a truncated record cannot pass as legacy."""

    def __init__(self, path: Path, key: Ed25519PrivateKey, header: dict[str, Any]):
        self.path = path
        self._key = key
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = GENESIS
        self._seal_at: int | None = None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.unlink(missing_ok=True)
        path.touch()
        self.append({"kind": "header", "pubkey_sha256": public_key_fingerprint(key), "created": time.time(),
                     "seal": SEAL_VERSION, **header})

    def _line(self, payload: dict[str, Any], seq: int, prev: str) -> dict[str, Any]:
        body: dict[str, Any] = {"seq": seq, "prev_hash": prev, "payload": payload}
        if "args" in payload:
            body["args_digest"] = digest(payload["args"])
        line_hash = digest(body)
        signature = base64.b64encode(self._key.sign(line_hash.encode("ascii"))).decode("ascii")
        return body | {"hash": line_hash, "sig": signature}

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry = self._line(payload, self._seq, self._prev)
            seal = self._line({"kind": "seal", "count": self._seq + 1, "final_hash": entry["hash"],
                               "sealed_at": time.time()}, self._seq + 1, entry["hash"])
            with self.path.open("r+b") as fh:
                fh.seek(0, 2)
                start = self._seal_at if self._seal_at is not None else fh.tell()
                fh.seek(start)
                fh.truncate()
                fh.write((canonical_json(entry) + "\n").encode("utf-8"))
                self._seal_at = fh.tell()
                fh.write((canonical_json(seal) + "\n").encode("utf-8"))
            self._seq += 1
            self._prev = entry["hash"]
            return entry


def read_record(path: Path) -> list[dict[str, Any]]:
    """Every record line except the trailing seal (verify.py checks the seal)."""
    entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [e for e in entries if (e.get("payload") or {}).get("kind") != "seal"]
