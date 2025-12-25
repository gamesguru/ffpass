#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Dec 26 00:10:05 2025

@author: shane
"""

import hmac
import json
import secrets
import sqlite3
from hashlib import sha1
from pathlib import Path

from Crypto.Cipher import AES, DES3
# Dependencies: pyasn1, pycryptodome
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.univ import Integer, ObjectIdentifier, OctetString, Sequence

# Constants
MASTER_PASSWORD = "password123"
GLOBAL_SALT = secrets.token_bytes(20)
# We will generate a 24-byte (3DES) master key to encrypt the database
REAL_MASTER_KEY = secrets.token_bytes(24)

# OIDs
OID_PKCS12_3DES = (1, 2, 840, 113_549, 1, 12, 5, 1, 3)
MAGIC1 = b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
MAGIC_AES = (2, 16, 840, 1, 101, 3, 4, 1, 42)


def PKCS7pad(b, block_size=8):
    pad_len = (-len(b) - 1) % block_size + 1
    return b + bytes([pad_len] * pad_len)


def derive_3des_key(global_salt, master_password, entry_salt):
    """
    Derives Key and IV using the specific Firefox/NSS PKCS#12-like KDF.
    Matches decrypt3DES in ffpass/__init__.py
    """
    hp = sha1(global_salt + master_password.encode()).digest()
    pes = entry_salt + b"\x00" * (20 - len(entry_salt))
    chp = sha1(hp + entry_salt).digest()
    k1 = hmac.new(chp, pes + entry_salt, sha1).digest()
    tk = hmac.new(chp, pes, sha1).digest()
    k2 = hmac.new(chp, tk + entry_salt, sha1).digest()
    k = k1 + k2
    iv = k[-8:]
    key = k[:24]
    return key, iv


def asn1_wrap_3des(entry_salt, ciphertext):
    """
    Wraps the salt and ciphertext in the ASN.1 structure expected by Firefox.
    Structure: Sequence[ Sequence[ OID, Sequence[Salt, Iters] ], Ciphertext ]
    """
    # 1. Algorithm Identifier
    params = Sequence()
    params[0] = OctetString(entry_salt)
    params[1] = Integer(1)  # Iterations

    algo_id = Sequence()
    algo_id[0] = ObjectIdentifier(OID_PKCS12_3DES)
    algo_id[1] = params

    # 2. Outer Sequence
    outer = Sequence()
    outer[0] = algo_id
    outer[1] = OctetString(ciphertext)

    return der_encode(outer)


def encrypt_pbe(data, global_salt, master_password):
    """
    Encrypts data (e.g. password-check or master key) using 3DES PBE.
    Returns the DER-encoded ASN.1 blob.
    """
    entry_salt = secrets.token_bytes(20)
    key, iv = derive_3des_key(global_salt, master_password, entry_salt)

    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_data = PKCS7pad(data)
    ciphertext = cipher.encrypt(padded_data)

    return asn1_wrap_3des(entry_salt, ciphertext)


def encode_login_data(key, data):
    """
    Encrypts a username or password using the Master Key (AES-256 logic).
    Matches encodeLoginData in ffpass/__init__.py
    """
    # Use AES-256 if key is 32 bytes, else 3DES. Our REAL_MASTER_KEY is 24 bytes (3DES).
    # To match modern Firefox better, let's pretend we use 3DES for the DB entry
    # but the logic handles whatever key we give it.
    # Let's stick to the AES path here if we want; but wait, REAL_MASTER_KEY is 24 bytes.
    # We must use 3DES logic for the login entry if key is 24 bytes.

    asn1data = Sequence()
    asn1data[0] = OctetString(MAGIC1)
    asn1data[1] = Sequence()

    if len(key) == 32:
        # AES Logic
        iv = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(PKCS7pad(data.encode(), block_size=16))
        asn1data[1][0] = ObjectIdentifier(MAGIC_AES)
        asn1data[1][1] = OctetString(iv)
        asn1data[2] = OctetString(ciphertext)
    else:
        # 3DES Logic (matches our 24-byte master key)
        # OID: 1.2.840.113549.3.7 (des-ede3-cbc)
        OID_3DES_CBC = (1, 2, 840, 113_549, 3, 7)
        iv = secrets.token_bytes(8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        ciphertext = cipher.encrypt(PKCS7pad(data.encode(), block_size=8))
        asn1data[1][0] = ObjectIdentifier(OID_3DES_CBC)
        asn1data[1][1] = OctetString(iv)
        asn1data[2] = OctetString(ciphertext)

    from base64 import b64encode

    return b64encode(der_encode(asn1data)).decode()


def create_mp_profile():
    base_dir = Path("tests/firefox-mp-test")
    if base_dir.exists():
        import shutil

        shutil.rmtree(base_dir)
    base_dir.mkdir(parents=True)

    print(f"Generating Real Encrypted MP profile in {base_dir}...")

    # 1. Create key4.db
    conn = sqlite3.connect(base_dir / "key4.db")
    c = conn.cursor()
    c.execute("CREATE TABLE metadata (id TEXT PRIMARY KEY, item1, item2)")
    c.execute("CREATE TABLE nssPrivate (a11, a102)")

    # A. Metadata: Password Check
    # The tool verifies password by decrypting this and checking for "password-check\x02\x02"
    # The encrypt_pbe function handles padding.
    password_check_blob = encrypt_pbe(b"password-check", GLOBAL_SALT, MASTER_PASSWORD)
    c.execute(
        "INSERT INTO metadata VALUES ('password', ?, ?)",
        (GLOBAL_SALT, password_check_blob),
    )

    # B. nssPrivate: Encrypted Master Key
    # The tool decrypts this to get the key used for logins.json
    master_key_blob = encrypt_pbe(REAL_MASTER_KEY, GLOBAL_SALT, MASTER_PASSWORD)
    c.execute("INSERT INTO nssPrivate VALUES (?, ?)", (master_key_blob, MAGIC1))

    conn.commit()
    conn.close()

    # 2. Create logins.json
    # These strings are actually encrypted with REAL_MASTER_KEY now
    logins_data = {
        "nextId": 2,
        "logins": [
            {
                "id": 1,
                "hostname": "https://locked.com",
                "encryptedUsername": encode_login_data(REAL_MASTER_KEY, "secret_user"),
                "encryptedPassword": encode_login_data(REAL_MASTER_KEY, "secret_pass"),
                "deleted": False,
            }
        ],
    }

    with open(base_dir / "logins.json", "w") as f:
        json.dump(logins_data, f)

    print("Done.")


if __name__ == "__main__":
    create_mp_profile()
