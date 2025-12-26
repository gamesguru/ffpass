#!/usr/bin/env python3
import sys
from base64 import b64decode
from hashlib import sha1, sha256, pbkdf2_hmac
import argparse
import json
from pathlib import Path
from getpass import getpass
import sqlite3
import string
from pyasn1.codec.der.decoder import decode as der_decode
from Crypto.Cipher import AES, DES3

# --- CONSTANTS ---
MAGIC1 = b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
OID_PBES2 = (1, 2, 840, 113_549, 1, 5, 13)
OID_PKCS12_3DES = (1, 2, 840, 113_549, 1, 12, 5, 1, 3)

class NoDatabase(Exception): pass
class WrongPassword(Exception): pass

def unpad(b):
    if not b: return b
    return b[:-b[-1]] if b[-1] <= len(b) else b

def clean_iv(iv_bytes):
    if len(iv_bytes) == 14: return b'\x04\x0e' + iv_bytes
    elif len(iv_bytes) == 18 and iv_bytes.startswith(b'\x04\x10'): return iv_bytes[2:]
    return iv_bytes

def decrypt_key_entry(a11, global_salt, master_password):
    """Decrypts a single key entry from nssPrivate"""
    try:
        decoded, _ = der_decode(a11)
        key_oid = decoded[0][0].asTuple()

        # Derive the unwrap key based on OID
        if key_oid == OID_PBES2:
            # AES based wrap
            algo = decoded[0][1][0]
            pbkdf2_params = algo[1]
            entry_salt = pbkdf2_params[0].asOctets()
            iters = int(pbkdf2_params[1])
            key_len = int(pbkdf2_params[2])

            enc_pwd = sha1(global_salt + master_password.encode('utf-8')).digest()
            k = pbkdf2_hmac('sha256', enc_pwd, entry_salt, iters, dklen=key_len)

            iv = clean_iv(decoded[0][1][1][1].asOctets())
            cipher = AES.new(k, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(decoded[1].asOctets()))

        elif key_oid == OID_PKCS12_3DES:
            # 3DES based wrap
            entry_salt = decoded[0][1][0].asOctets()
            ciphertext = decoded[1].asOctets()

            # 3DES Key Derivation
            hp = sha1(global_salt + master_password.encode()).digest()
            pes = entry_salt + b"\x00" * (20 - len(entry_salt))
            chp = sha1(hp + entry_salt).digest()
            k1 = sha1(pes + entry_salt).digest() # Simplified HMAC logic replacement for brevity/compatibility
            # Note: Using standard PBKDF logic for 3DES usually involves the full HMAC-SHA1 sequence
            # Reverting to the known working 3DES helper from previous scripts

            return decrypt3DES(global_salt, master_password, entry_salt, ciphertext)

    except Exception as e:
        # print(f"DEBUG: Failed to decrypt a key entry: {e}", file=sys.stderr)
        return None

def decrypt3DES(globalSalt, masterPassword, entrySalt, encryptedData):
    # Standard Mozilla 3DES Logic
    import hmac
    hp = sha1(globalSalt + masterPassword.encode()).digest()
    pes = entrySalt + b"\x00" * (20 - len(entrySalt))
    chp = sha1(hp + entrySalt).digest()
    k1 = hmac.new(chp, pes + entrySalt, sha1).digest()
    tk = hmac.new(chp, pes, sha1).digest()
    k2 = hmac.new(chp, tk + entrySalt, sha1).digest()
    k = k1 + k2
    iv = k[-8:]
    key = k[:24]
    return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData)

def get_all_keys(directory, pwd=""):
    db = Path(directory) / "key4.db"
    conn = sqlite3.connect(str(db))
    c = conn.cursor()

    # 1. Get Global Salt
    c.execute("SELECT item1, item2 FROM metadata WHERE id = 'password'")
    try:
        global_salt, item2 = next(c)
    except StopIteration:
        raise NoDatabase()

    # 2. Check Password (using item2)
    # We skip strict validation here to focus on key extraction,
    # but we assume the pwd is correct if it works for any key.

    print(f"[*] Global Salt: {global_salt.hex()}", file=sys.stderr)

    # 3. Find ALL Keys
    # Note: We select ALL entries, not just where a102=MAGIC1,
    # just in case the ID format varies.
    c.execute("SELECT a11, a102 FROM nssPrivate")

    found_keys = []

    rows = c.fetchall()
    print(f"[*] Found {len(rows)} entries in nssPrivate", file=sys.stderr)

    for idx, (a11, a102) in enumerate(rows):
        key = decrypt_key_entry(a11, global_salt, pwd)
        if key:
            print(f"[*] Decrypted Key #{idx}: {len(key)} bytes | ID: {a102.hex() if a102 else 'None'}", file=sys.stderr)
            found_keys.append(key)
        else:
            print(f"[*] Key #{idx}: Failed to decrypt", file=sys.stderr)

    return found_keys, global_salt

def try_decrypt_login(key, ciphertext, iv):
    # Try AES (if key 16/24/32)
    if len(key) in [16, 24, 32]:
        try:
            # Standard AES
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(ciphertext)
            res = unpad(pt)
            text = res.decode('utf-8')
            if is_valid_text(text): return text, "AES-Standard"
        except: pass

    # Try 3DES (if key 24)
    if len(key) == 24:
        try:
            cipher = DES3.new(key, DES3.MODE_CBC, iv[:8])
            pt = cipher.decrypt(ciphertext)
            res = unpad(pt)
            text = res.decode('utf-8')
            if is_valid_text(text): return text, "3DES-Standard"
        except: pass

    return None, None

def is_valid_text(text):
    if not text: return False
    printable = set(string.printable)
    return sum(1 for c in text if c in printable) / len(text) > 0.9

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", required=True)
    args = parser.parse_args()

    pwd = ""
    # Simple password prompt handling
    try:
        keys, salt = get_all_keys(args.directory, pwd)
    except:
        pwd = getpass("Master Password: ")
        keys, salt = get_all_keys(args.directory, pwd)

    if not keys:
        print("[!] No keys could be decrypted. Wrong password?", file=sys.stderr)
        return

    with open(Path(args.directory) / "logins.json", "r") as f:
        js = json.load(f)

    print("\n--- ATTEMPTING DECRYPTION WITH FOUND KEYS ---")

    # Try to find the "Golden Key" using the first row
    golden_key = None

    first_row = next((r for r in js["logins"] if not r.get("deleted")), None)
    if not first_row:
        print("No logins found.")
        return

    data = b64decode(first_row["encryptedUsername"])
    asn1, _ = der_decode(data)
    iv = clean_iv(asn1[1][1].asOctets())
    ciphertext = asn1[2].asOctets()

    print(f"[*] Testing {len(keys)} keys on first login...", file=sys.stderr)

    for k in keys:
        text, method = try_decrypt_login(k, ciphertext, iv)
        if text:
            print(f"[!!!] GOLDEN KEY FOUND: {len(k)} bytes ({method})", file=sys.stderr)
            golden_key = k
            break

    if not golden_key:
        print("[X] None of the decrypted keys worked on the login data.", file=sys.stderr)
        print("[*] Trying Key Expansion on 24-byte keys...", file=sys.stderr)

        # Last ditch: Try expanding any 24-byte keys found
        for k in keys:
            if len(k) == 24:
                expanded = sha256(k).digest()
                text, method = try_decrypt_login(expanded, ciphertext, iv)
                if text:
                    print(f"[!!!] EXPANDED KEY FOUND: SHA256(Key) worked!", file=sys.stderr)
                    golden_key = expanded
                    break

    if golden_key:
        print("url,username,password")
        for row in js["logins"]:
            if row.get("deleted"): continue
            try:
                # Decrypt User
                u_data = b64decode(row["encryptedUsername"])
                u_asn1, _ = der_decode(u_data)
                u_iv = clean_iv(u_asn1[1][1].asOctets())
                u_ct = u_asn1[2].asOctets()
                user, _ = try_decrypt_login(golden_key, u_ct, u_iv)

                # Decrypt Pass
                p_data = b64decode(row["encryptedPassword"])
                p_asn1, _ = der_decode(p_data)
                p_iv = clean_iv(p_asn1[1][1].asOctets())
                p_ct = p_asn1[2].asOctets()
                pw, _ = try_decrypt_login(golden_key, p_ct, p_iv)

                print(f"{row['hostname']},{user or ''},{pw or ''}")
            except:
                print(f"{row['hostname']},ERROR,ERROR")
    else:
        print("Failed to find a working key.")

if __name__ == "__main__":
    main()
