#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Dec 25 20:34:59 2025

@author: shane
"""

import json
import sqlite3
from pathlib import Path

# Constants for Firefox Crypto
MAGIC1 = b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"


def create_mixed_profile():
    base_dir = Path("tests/firefox-mixed-keys")
    if base_dir.exists():
        print(f"Directory {base_dir} already exists. Skipping generation.")
        return
    base_dir.mkdir(parents=True)

    print(f"Generating mixed key profile in {base_dir}...")

    # 1. Create key4.db with TWO keys
    conn = sqlite3.connect(base_dir / "key4.db")
    c = conn.cursor()
    c.execute("CREATE TABLE metadata (id TEXT PRIMARY KEY, item1, item2)")
    c.execute("CREATE TABLE nssPrivate (a11, a102)")

    # Metadata: Simple password check (Salt + Check Blob)
    # This is a dummy check that our mock/test logic accepts
    c.execute(
        "INSERT INTO metadata VALUES ('password', ?, ?)",
        (b"global_salt", b"pw_check_blob"),
    )

    # nssPrivate: Insert the MIXED keys
    # Key 0: Legacy 24-byte key blob (We simulate this decrypting to 24 bytes)
    # In a real DB, this is ASN.1 wrapped. For our integration test,
    # we rely on the mocked decryptor in the test to interpret this specific blob.
    c.execute("INSERT INTO nssPrivate VALUES (?, ?)", (b"blob_legacy_24", MAGIC1))

    # Key 1: Modern 32-byte key blob
    c.execute("INSERT INTO nssPrivate VALUES (?, ?)", (b"blob_modern_32", MAGIC1))

    conn.commit()
    conn.close()

    # 2. Create logins.json encrypted with the MODERN key
    # Our test infrastructure mocks the decryption, so we can use dummy base64 strings
    # The crucial part is that the test asserts it extracts data using the modern key logic
    logins_data = {
        "nextId": 2,
        "logins": [
            {
                "id": 1,
                "hostname": "http://www.mixedkeys.com",
                "encryptedUsername": "QUFBQUFBQUE=",  # Base64 for 'AAAAAAAA'
                "encryptedPassword": "QUFBQUFBQUE=",
                "deleted": False,
            }
        ],
    }

    with open(base_dir / "logins.json", "w") as f:
        json.dump(logins_data, f)

    print("Done.")


if __name__ == "__main__":
    create_mixed_profile()
