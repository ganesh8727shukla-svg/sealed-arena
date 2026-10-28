"""Canonical hash-chain helpers for the local Bayora prototype audit log."""

import hashlib
import json


GENESIS_HASH = "0" * 64


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_entry(previous_hash, body):
    if not isinstance(previous_hash, str) or len(previous_hash) != 64:
        raise ValueError("previous_hash must be a SHA-256 hex digest")
    return hashlib.sha256((previous_hash + canonical_json(body)).encode("utf-8")).hexdigest()


def verify_chain(entries):
    expected_previous = GENESIS_HASH
    for expected_sequence, entry in enumerate(entries, start=1):
        if entry.get("sequence") != expected_sequence:
            return {"verified": False, "checked": expected_sequence - 1,
                    "error": "sequence_mismatch", "failed_sequence": expected_sequence}
        if entry.get("previous_hash") != expected_previous:
            return {"verified": False, "checked": expected_sequence - 1,
                    "error": "previous_hash_mismatch", "failed_sequence": expected_sequence}
        expected_hash = hash_entry(expected_previous, entry.get("body"))
        if entry.get("entry_hash") != expected_hash:
            return {"verified": False, "checked": expected_sequence - 1,
                    "error": "entry_hash_mismatch", "failed_sequence": expected_sequence}
        expected_previous = expected_hash
    return {"verified": True, "checked": len(entries), "root_hash": expected_previous}
