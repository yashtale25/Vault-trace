#!/usr/bin/env python3
"""
password_checker.py
--------------------
Command-line companion to the Password Strength Checker & Vault website.

Implements the same six regex-based test points as the web app, plus:
  - a Shannon-style entropy estimate and offline crack-time projection
  - a tiny local encrypted vault (XOR cipher + SHA-256 passphrase check)
    stored in a JSON file next to this script

This is written for a cybersecurity coursework project to demonstrate
regex-based validation and basic applied cryptography concepts in Python.
It is NOT intended as production-grade credential storage.

Usage:
    python password_checker.py check "MyP@ssw0rd123"
    python password_checker.py check            # interactive prompt (hidden input)
    python password_checker.py vault             # open the interactive vault menu
"""

import re
import sys
import json
import math
import base64
import hashlib
import getpass
import os
from datetime import datetime

VAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.json")

# ---------------------------------------------------------------------------
# Regex-based test points (mirrors the web app's TP-01 .. TP-06)
# ---------------------------------------------------------------------------

WEAK_LIST_RE = re.compile(
    r"^(123456|password|qwerty|letmein|111111|abc123|iloveyou|admin|welcome|"
    r"monkey|dragon|football|baseball|123123|000000|12345678|1234567890)",
    re.IGNORECASE,
)
REPEATED_RE = re.compile(r"(.)\1{2,}")           # same char 3+ times in a row
UPPER_RE = re.compile(r"[A-Z]")
LOWER_RE = re.compile(r"[a-z]")
DIGIT_RE = re.compile(r"\d")
SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")

SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop"]


def is_sequential(password: str) -> bool:
    """Detect 3+ character runs from common keyboard/alphabet/number sequences."""
    lowered = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - 2):
            chunk = seq[i:i + 3]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def has_weak_pattern(password: str) -> bool:
    return bool(WEAK_LIST_RE.match(password)) or bool(REPEATED_RE.search(password)) or is_sequential(password)


def run_checks(password: str) -> dict:
    """Run all six test points and return a dict of {id: (passed, description)}."""
    return {
        "TP-01": (len(password) >= 8, "At least 8 characters long"),
        "TP-02": (bool(UPPER_RE.search(password)), "Contains an uppercase letter"),
        "TP-03": (bool(LOWER_RE.search(password)), "Contains a lowercase letter"),
        "TP-04": (bool(DIGIT_RE.search(password)), "Contains a numeric digit"),
        "TP-05": (bool(SPECIAL_RE.search(password)), "Contains a special character"),
        "TP-06": (not has_weak_pattern(password) if password else False,
                  "No common word, repeated run, or sequence"),
    }


def estimate_crack_time(password: str) -> tuple:
    """Return (entropy_bits, seconds_to_crack) assuming a 10^10 guesses/sec offline attack."""
    pool = 0
    if LOWER_RE.search(password):
        pool += 26
    if UPPER_RE.search(password):
        pool += 26
    if DIGIT_RE.search(password):
        pool += 10
    if SPECIAL_RE.search(password):
        pool += 32
    if pool == 0 or len(password) == 0:
        return 0.0, 0.0

    entropy = len(password) * math.log2(pool)
    guesses = (2 ** entropy) / 2
    guesses_per_second = 1e10
    return entropy, guesses / guesses_per_second


def format_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("centuries", 3153600000),
        ("years", 31536000),
        ("days", 86400),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, secs in units:
        if seconds >= secs:
            val = seconds / secs
            return f"{val:,.1f} {name}" if val < 1000 else f"{val:.2e} {name}"
    return "instantly"


def score_band(checks: dict, password: str) -> str:
    passed = sum(1 for ok, _ in checks.values() if ok)
    if not password:
        return "N/A"
    if passed <= 2:
        return "VERY WEAK"
    if passed == 3:
        return "WEAK"
    if passed == 4:
        return "FAIR"
    if passed == 5:
        return "STRONG"
    return "VERY STRONG" if len(password) >= 12 else "STRONG"


def print_report(password: str) -> None:
    checks = run_checks(password)
    entropy, seconds = estimate_crack_time(password)
    band = score_band(checks, password)

    print("\n" + "=" * 52)
    print(" PASSWORD STRENGTH REPORT")
    print("=" * 52)
    for tp_id, (passed, desc) in checks.items():
        mark = "[PASS]" if passed else "[FAIL]"
        print(f"  {tp_id}  {mark:8} {desc}")
    print("-" * 52)
    print(f"  Overall rating   : {band}")
    print(f"  Entropy estimate : {entropy:.1f} bits")
    print(f"  Est. crack time  : {format_seconds(seconds)}  (offline, 10^10 guesses/sec)")
    print("=" * 52 + "\n")


# ---------------------------------------------------------------------------
# Tiny local vault (educational XOR cipher + SHA-256 passphrase verification)
# ---------------------------------------------------------------------------

def _hash_passphrase(passphrase: str) -> str:
    return hashlib.sha256(passphrase.encode("utf-8")).hexdigest()


def _xor_cipher(text: str, key: str) -> str:
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))


def _encrypt(plaintext: str, key: str) -> str:
    return base64.b64encode(_xor_cipher(plaintext, key).encode("utf-8", "surrogatepass")).decode("ascii")


def _decrypt(ciphertext: str, key: str) -> str:
    raw = base64.b64decode(ciphertext.encode("ascii")).decode("utf-8", "surrogatepass")
    return _xor_cipher(raw, key)


def _load_vault() -> dict:
    if not os.path.exists(VAULT_PATH):
        return {"passphrase_hash": None, "entries": []}
    with open(VAULT_PATH, "r") as f:
        return json.load(f)


def _save_vault(data: dict) -> None:
    with open(VAULT_PATH, "w") as f:
        json.dump(data, f, indent=2)


def vault_menu() -> None:
    data = _load_vault()
    passphrase = getpass.getpass("Master passphrase: ")

    if data["passphrase_hash"] is None:
        data["passphrase_hash"] = _hash_passphrase(passphrase)
        _save_vault(data)
        print("New vault created and unlocked.")
    elif data["passphrase_hash"] != _hash_passphrase(passphrase):
        print("Incorrect passphrase.")
        return
    else:
        print("Vault unlocked.")

    while True:
        print("\n1) List entries  2) Add entry  3) Reveal entry  4) Delete entry  5) Exit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            if not data["entries"]:
                print("  (vault is empty)")
            for i, e in enumerate(data["entries"]):
                print(f"  [{i}] {e['label']}  —  {e['username']}")

        elif choice == "2":
            label = input("  Site / label: ").strip()
            username = input("  Username: ").strip()
            pw = getpass.getpass("  Password to store: ")
            print_report(pw)
            data["entries"].append({
                "label": label,
                "username": username,
                "cipher": _encrypt(pw, passphrase),
                "created": datetime.now().isoformat(timespec="seconds"),
            })
            _save_vault(data)
            print("  Entry saved.")

        elif choice == "3":
            idx = input("  Entry index to reveal: ").strip()
            if idx.isdigit() and int(idx) < len(data["entries"]):
                entry = data["entries"][int(idx)]
                try:
                    print(f"  Password: {_decrypt(entry['cipher'], passphrase)}")
                except Exception:
                    print("  Could not decrypt (wrong passphrase for this entry).")
            else:
                print("  Invalid index.")

        elif choice == "4":
            idx = input("  Entry index to delete: ").strip()
            if idx.isdigit() and int(idx) < len(data["entries"]):
                removed = data["entries"].pop(int(idx))
                _save_vault(data)
                print(f"  Deleted '{removed['label']}'.")
            else:
                print("  Invalid index.")

        elif choice == "5":
            print("Goodbye.")
            break
        else:
            print("  Unrecognized option.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("check", "vault"):
        print(__doc__)
        sys.exit(0)

    command = sys.argv[1]

    if command == "check":
        if len(sys.argv) >= 3:
            password = sys.argv[2]
        else:
            password = getpass.getpass("Enter password to analyze: ")
        print_report(password)

    elif command == "vault":
        vault_menu()


if __name__ == "__main__":
    main()
