#!/usr/bin/env python3
"""Verify a ClearGate signed record. Needs no API keys, only `cryptography`.

    python verify.py records/<run>-gated.jsonl [--pubkey records/signing_pub.pem]

Recomputes every arguments digest and line hash, checks the hash chain and every
Ed25519 signature, checks the signed seal on the last line (record count + final chain
hash, so a truncated record fails), and prints MATCH or the first mismatch. Records
written before seals existed verify as "UNSEALED (legacy)".
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

GENESIS = "0" * 64


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def verify(path: Path, pubkey_path: Path) -> tuple[bool, str]:
    key = serialization.load_pem_public_key(pubkey_path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        return False, f"MISMATCH: {pubkey_path} is not an Ed25519 public key"
    fingerprint = hashlib.sha256(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
    prev = GENESIS
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not lines:
        return False, "MISMATCH: the record is empty"
    sealed_format = False
    seal: dict | None = None
    for number, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            return False, f"MISMATCH at line {number}: not JSON ({exc})"
        if not isinstance(entry, dict):
            return False, f"MISMATCH at line {number}: not a record object"
        where = f"line {number} (seq {entry.get('seq')})"
        if entry.get("seq") != number - 1:
            return False, f"MISMATCH at {where}: expected seq {number - 1}"
        if entry.get("prev_hash") != prev:
            return False, f"MISMATCH at {where}: prev_hash does not chain to line {number - 1}"
        payload = entry.get("payload", {})
        if number == 1 and payload.get("pubkey_sha256") != fingerprint:
            return False, "MISMATCH at line 1: the header names a different signing key"
        if number == 1:
            sealed_format = bool(payload.get("seal"))
        if "args" in payload and entry.get("args_digest") != sha256(dict(payload["args"] or {})):
            return False, f"MISMATCH at {where}: args_digest does not match the canonical arguments"
        body = {k: entry[k] for k in ("seq", "prev_hash", "payload", "args_digest") if k in entry}
        if entry.get("hash") != sha256(body):
            return False, f"MISMATCH at {where}: line hash does not match its contents"
        try:
            key.verify(base64.b64decode(entry.get("sig", "")), entry["hash"].encode("ascii"))
        except (InvalidSignature, ValueError):
            return False, f"MISMATCH at {where}: bad Ed25519 signature"
        if payload.get("kind") == "seal":
            if number != len(lines):
                return False, f"MISMATCH at {where}: a seal line is followed by more records"
            if payload.get("count") != number - 1 or payload.get("final_hash") != prev:
                return False, f"MISMATCH: truncated/unsealed (seal names {payload.get('count')} records, file has {number - 1})"
            seal = payload
        prev = entry["hash"]
    if seal is not None:
        return True, (f"MATCH: {len(lines) - 1} records, sealed; chain intact, all signatures valid "
                      f"(key {fingerprint[:16]}…)")
    if sealed_format:
        return False, f"MISMATCH: truncated/unsealed ({len(lines)} records, no seal line at the end)"
    return True, (f"UNSEALED (legacy): {len(lines)} records, chain intact, all signatures valid, but truncation "
                  f"cannot be ruled out (key {fingerprint[:16]}…)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("record", type=Path)
    parser.add_argument("--pubkey", type=Path, default=None)
    args = parser.parse_args()
    pubkey = args.pubkey or args.record.parent / "signing_pub.pem"
    for need, what in ((args.record, "record"), (pubkey, "public key (pass --pubkey)")):
        if not need.is_file():
            print(f"ERROR: {what} not found: {need}", file=sys.stderr)
            return 2
    try:
        ok, message = verify(args.record, pubkey)
    except ValueError as exc:  # unreadable PEM or non-UTF-8 record
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
