#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

"""
The MIT License (MIT)
Copyright (c) 2018 Louis Abraham <louis.abraham@yahoo.fr>
Laurent Clevy (@lorenzo2472)

ffpass can import and export passwords from Firefox Quantum.
"""

import sys
from base64 import b64decode, b64encode
from hashlib import sha1, pbkdf2_hmac
import argparse
import json
from pathlib import Path
import csv
import secrets
from getpass import getpass
from uuid import uuid4
from datetime import datetime
from urllib.parse import urlparse
import sqlite3
import os.path
import logging
import string

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.univ import Sequence, OctetString, ObjectIdentifier
from Crypto.Cipher import AES, DES3


MAGIC1 = b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

# des-ede3-cbc
MAGIC2 = (1, 2, 840, 113_549, 3, 7)

# aes-256-cbc
MAGIC_AES = (2, 16, 840, 1, 101, 3, 4, 1, 42)

# pkcs-12-PBEWithSha1AndTripleDESCBC
OID_PKCS12_3DES = (1, 2, 840, 113_549, 1, 12, 5, 1, 3)

# pkcs5PBES2
OID_PBES2 = (1, 2, 840, 113_549, 1, 5, 13)


class NoDatabase(Exception):
    pass


class WrongPassword(Exception):
    pass


class NoProfile(Exception):
    pass


def censor(data):
    """
    Censors the middle third of a hex string or bytes object.
    """
    if not data: return "None"
    s = data.hex() if isinstance(data, (bytes, bytearray)) else str(data)

    length = len(s)
    if length <= 12: return s

    third = length // 3
    return f"{s[:third]}.....{s[2*third:]}"


def clean_iv(iv_bytes):
    if len(iv_bytes) == 14:
        return b'\x04\x0e' + iv_bytes
    elif len(iv_bytes) == 18 and iv_bytes.startswith(b'\x04\x10'):
        return iv_bytes[2:]
    return iv_bytes


def PKCS7pad(b, block_size=8):
    pad_len = (-len(b) - 1) % block_size + 1
    return b + bytes([pad_len] * pad_len)


def PKCS7unpad(b):
    if not b:
        return b
    return b[: -b[-1]]


def decrypt3DES(globalSalt, masterPassword, entrySalt, encryptedData):
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


def decrypt_key_entry(a11, global_salt, master_password):
    try:
        decoded, _ = der_decode(a11)
        key_oid = decoded[0][0].asTuple()

        if key_oid == OID_PBES2:
            # AES Logic
            algo = decoded[0][1][0]
            pbkdf2_params = algo[1]
            entry_salt = pbkdf2_params[0].asOctets()
            iters = int(pbkdf2_params[1])
            key_len = int(pbkdf2_params[2])

            logging.debug(f"  > Method: PBKDF2-HMAC-SHA256 | Iterations: {iters}")
            logging.debug(f"  > Salt: {censor(entry_salt)} (Local) + {censor(global_salt)} (Global)")

            enc_pwd = sha1(global_salt + master_password.encode('utf-8')).digest()
            k = pbkdf2_hmac('sha256', enc_pwd, entry_salt, iters, dklen=key_len)

            iv = clean_iv(decoded[0][1][1][1].asOctets())
            logging.debug(f"  > Cipher: AES-256-CBC | IV: {censor(iv)}")

            cipher = AES.new(k, AES.MODE_CBC, iv)
            return PKCS7unpad(cipher.decrypt(decoded[1].asOctets()))

        elif key_oid == OID_PKCS12_3DES:
            # 3DES Logic
            entry_salt = decoded[0][1][0].asOctets()
            ciphertext = decoded[1].asOctets()

            logging.debug(f"  > Method: PKCS12-3DES-Derivation")
            logging.debug(f"  > Salt: {censor(entry_salt)} (Local) + {censor(global_salt)} (Global)")

            import hmac
            hp = sha1(global_salt + master_password.encode()).digest()
            pes = entry_salt + b"\x00" * (20 - len(entry_salt))
            chp = sha1(hp + entry_salt).digest()
            k1 = hmac.new(chp, pes + entry_salt, sha1).digest()
            tk = hmac.new(chp, pes, sha1).digest()
            k2 = hmac.new(chp, tk + entry_salt, sha1).digest()
            k = k1 + k2
            iv = k[-8:]
            key = k[:24]

            logging.debug(f"  > Cipher: 3DES-CBC | IV: {censor(iv)}")
            return PKCS7unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext))

    except Exception as e:
        logging.debug(f"  > Failed: {e}")
        return None


def get_all_keys(directory, pwd=""):
    db = Path(directory) / "key4.db"
    if not db.exists(): raise NoDatabase()

    conn = sqlite3.connect(str(db))
    c = conn.cursor()

    # 1. Get Global Salt
    c.execute("SELECT item1, item2 FROM metadata WHERE id = 'password'")
    try:
        global_salt, item2 = next(c)
    except StopIteration: raise NoDatabase()

    logging.info(f"[*] Global Salt: {censor(global_salt)}")

    # 2. Check Password (simplified via key decryption attempt)
    # 3. Find ALL Keys
    c.execute("SELECT a11, a102 FROM nssPrivate")
    rows = c.fetchall()
    logging.info(f"[*] Found {len(rows)} entries in nssPrivate")

    found_keys = []
    for idx, (a11, a102) in enumerate(rows):
        logging.debug(f"[*] Attempting to decrypt Key #{idx} (ID: {censor(a102)})...")

        key = decrypt_key_entry(a11, global_salt, pwd)

        if key:
            logging.info(f"[*] Decrypted Key #{idx}: {len(key)} bytes | ID: {a102.hex()}")
            found_keys.append(key)
        else:
            logging.debug(f"[*] Key #{idx}: Failed to decrypt (Wrong Password or Corrupt)")

    if not found_keys:
        # If no keys decrypted, the password is definitely wrong
        raise WrongPassword()

    return found_keys, global_salt


def try_decrypt_login(key, ciphertext, iv):
    # Try AES
    if len(key) in [16, 24, 32]:
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(ciphertext)
            res = PKCS7unpad(pt)
            text = res.decode('utf-8')
            if is_valid_text(text): return text, "AES-Standard"
        except: pass

    # Try 3DES
    if len(key) == 24:
        try:
            cipher = DES3.new(key, DES3.MODE_CBC, iv[:8])
            pt = cipher.decrypt(ciphertext)
            res = PKCS7unpad(pt)
            text = res.decode('utf-8')
            if is_valid_text(text): return text, "3DES-Standard"
        except: pass

    return None, None


def is_valid_text(text):
    if not text or len(text) < 2: return False
    printable = set(string.printable)
    if sum(1 for c in text if c in printable) / len(text) < 0.9: return False
    return True


def decodeLoginData(key, data):
    try:
        asn1data, _ = der_decode(b64decode(data))
        iv = clean_iv(asn1data[1][1].asOctets())
        ciphertext = asn1data[2].asOctets()

        text, method = try_decrypt_login(key, ciphertext, iv)
        if text: return text
        raise ValueError("Decryption failed")
    except Exception:
        raise ValueError("Decryption failed")


def encodeLoginData(key, data):
    asn1data = Sequence()
    asn1data[0] = OctetString(MAGIC1)
    asn1data[1] = Sequence()

    if len(key) == 32:  # AES-256
        iv = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(PKCS7pad(data.encode(), block_size=16))

        asn1data[1][0] = ObjectIdentifier(MAGIC_AES)
        asn1data[1][1] = OctetString(iv)
        asn1data[2] = OctetString(ciphertext)

    elif len(key) == 24:  # 3DES
        iv = secrets.token_bytes(8)
        des = DES3.new(key, DES3.MODE_CBC, iv)
        ciphertext = des.encrypt(PKCS7pad(data.encode(), block_size=8))

        asn1data[1][0] = ObjectIdentifier(MAGIC2)
        asn1data[1][1] = OctetString(iv)
        asn1data[2] = OctetString(ciphertext)
    else:
        raise ValueError(f"Unknown key type/size: {len(key)}")

    return b64encode(der_encode(asn1data)).decode()


def getJsonLogins(directory):
    with open(directory / "logins.json", "r") as loginf:
        jsonLogins = json.load(loginf)
    return jsonLogins


def dumpJsonLogins(directory, jsonLogins):
    with open(directory / "logins.json", "w") as loginf:
        json.dump(jsonLogins, loginf, separators=",:")


def exportLogins(key, jsonLogins):
    if "logins" not in jsonLogins:
        logging.error("no 'logins' key in logins.json")
        return []
    logins = []
    for row in jsonLogins["logins"]:
        if row.get("deleted"): continue
        try:
            user = decodeLoginData(key, row["encryptedUsername"])
            pw = decodeLoginData(key, row["encryptedPassword"])
            logins.append((row["hostname"], user, pw))
        except Exception as e:
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.debug(f"Failed to decrypt {row.get('hostname')}: {e}")
            continue
    return logins


def lower_header(csv_file):
    it = iter(csv_file)
    yield next(it).lower()
    yield from it


def readCSV(csv_file):
    logins = []
    reader = csv.DictReader(lower_header(csv_file))
    for row in reader:
        logins.append((rawURL(row["url"]), row["username"], row["password"]))
    return logins


def rawURL(url):
    p = urlparse(url)
    return type(p)(*p[:2], *[""] * 4).geturl()


def addNewLogins(key, jsonLogins, logins):
    nextId = jsonLogins["nextId"]
    timestamp = int(datetime.now().timestamp() * 1000)
    logging.info('adding logins')
    for i, (url, username, password) in enumerate(logins, nextId):
        logging.debug(f'adding {url} {username}')
        entry = {
            "id": i,
            "hostname": url,
            "httpRealm": None,
            "formSubmitURL": "",
            "usernameField": "",
            "passwordField": "",
            "encryptedUsername": encodeLoginData(key, username),
            "encryptedPassword": encodeLoginData(key, password),
            "guid": "{%s}" % uuid4(),
            "encType": 1,
            "timeCreated": timestamp,
            "timeLastUsed": timestamp,
            "timePasswordChanged": timestamp,
            "timesUsed": 0,
        }
        jsonLogins["logins"].append(entry)
    jsonLogins["nextId"] += len(logins)


def guessDir():
    dirs = {
        "darwin": "~/Library/Application Support/Firefox/Profiles",
        "linux": "~/.mozilla/firefox",
        "win32": os.path.expandvars(r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles"),
        "cygwin": os.path.expandvars(r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles"),
    }

    if sys.platform not in dirs:
        logging.error(f"Automatic profile selection is not supported for {sys.platform}")
        logging.error("Please specify a profile to parse (-d path/to/profile)")
        raise NoProfile

    paths = Path(dirs[sys.platform]).expanduser()
    profiles = [path.parent for path in paths.glob(os.path.join("*", "logins.json"))]
    logging.debug(f"Paths: {paths}")
    logging.debug(f"Profiles: {profiles}")

    if len(profiles) == 0:
        logging.error("Cannot find any Firefox profiles")
        raise NoProfile

    if len(profiles) > 1:
        logging.error("More than one profile detected. Please specify a profile to parse (-d path/to/profile)")
        logging.error("valid profiles:\n\t\t" + '\n\t\t'.join(map(str, profiles)))
        raise NoProfile

    profile_path = profiles[0]

    logging.info(f"Using profile: {profile_path}")
    return profile_path


def askpass(directory):
    password = ""
    while True:
        try:
            # FIX: Use get_all_keys and select best key manually
            keys, _ = get_all_keys(directory, password)
            # Prefer 32-byte key, fallback to first
            best_key = next((k for k in keys if len(k) == 32), keys[0])
            logging.info(f"Selected Master Key: {len(best_key)} bytes (from {len(keys)} candidates)")
            return best_key
        except WrongPassword:
            password = getpass("Master Password: ")
        else:
            break
    return None


def main_export(args):
    try:
        key = askpass(args.directory)
    except NoDatabase:
        return

    if not key:
        logging.error("Failed to derive master key.")
        return

    jsonLogins = getJsonLogins(args.directory)
    logins = exportLogins(key, jsonLogins)
    writer = csv.writer(args.file)
    writer.writerow(["url", "username", "password"])
    writer.writerows(logins)


def main_import(args):
    if args.file == sys.stdin:
        try:
            key = askpass(args.directory)
        except WrongPassword:
            logging.error("Password is not empty. You have to specify FROM_FILE.")
            sys.exit(1)
    else:
        key = askpass(args.directory)

    if not key:
        logging.error("Failed to derive master key.")
        return

    jsonLogins = getJsonLogins(args.directory)
    logins = readCSV(args.file)
    addNewLogins(key, jsonLogins, logins)
    dumpJsonLogins(args.directory, jsonLogins)


def makeParser():
    parser = argparse.ArgumentParser(
        prog="ffpass",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="mode")
    subparsers.required = True

    parser_export = subparsers.add_parser(
        "export", description="outputs a CSV with header `url,username,password`"
    )
    parser_import = subparsers.add_parser(
        "import",
        description="imports a CSV with columns `url,username,password` (order insensitive)",
    )

    parser_import.add_argument(
        "-f", "--file", dest="file", type=argparse.FileType("r", encoding="utf-8"), default=sys.stdin
    )
    parser_export.add_argument(
        "-f", "--file", dest="file", type=argparse.FileType("w", encoding="utf-8"), default=sys.stdout
    )

    for sub in subparsers.choices.values():
        sub.add_argument("-d", "--directory", "--dir", type=Path, default=None, help="Firefox profile directory")
        sub.add_argument("-v", "--verbose", action="store_true")
        sub.add_argument("--debug", action="store_true")

    parser_import.set_defaults(func=main_import)
    parser_export.set_defaults(func=main_export)

    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ModuleNotFoundError:
        pass

    return parser


def main():
    # Default level ERROR (Silent), INFO for verbose, DEBUG for debug
    parser = makeParser()
    args = parser.parse_args()

    log_level = logging.ERROR
    if args.verbose:
        log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG

    logging.basicConfig(level=log_level, format="%(message)s")

    if args.directory is None:
        try:
            args.directory = guessDir()
        except NoProfile:
            print("No Firefox profile found.")
            parser.print_help()
            parser.exit()
    args.directory = args.directory.expanduser()

    try:
        # Wrap in try/except for BrokenPipeError to allow piping to head
        try:
            args.func(args)
        except BrokenPipeError:
            # Python flushes standard streams on exit; redirect remaining output to devnull to avoid error dump
            sys.stdout = os.fdopen(1, 'w')
            pass
    except NoDatabase:
        logging.error("Firefox password database is empty.")


if __name__ == "__main__":
    main()
