#!/usr/bin/env python3

import os
import subprocess
import shutil
import pytest
import sys
from unittest.mock import patch
from pathlib import Path

# Add project root to path so we can import ffpass internals for mocking
sys.path.insert(0, str(Path(__file__).parent.parent))

from ffpass import get_all_keys

OS_NEWLINE = os.linesep
HEADER = 'url,username,password'
EXPECTED_MIXED_OUTPUT = [HEADER, 'http://www.mixedkeys.com,modern_user,modern_pass']


@pytest.fixture
def clean_profile(tmp_path):
    """
    Copies the requested profile to a temporary directory.
    """
    def _setup(profile_name):
        src = Path('tests') / profile_name
        dst = tmp_path / profile_name
        shutil.copytree(src, dst)
        return dst
    return _setup


def run_ffpass_internal(mode, path):
    """
    Runs ffpass as a library call instead of subprocess.
    This allows us to MOCK the decryption crypto while testing the CLI glue code.
    """
    from ffpass import main

    # Mock sys.argv
    test_args = ["ffpass", mode, "-d", str(path)]

    # We need to patch the low-level crypto functions because our
    # tests/firefox-mixed-keys/key4.db contains dummy blobs ('blob_modern_32'),
    # not real encrypted ASN.1 structures.
    with patch('sys.argv', test_args), \
         patch('ffpass.decrypt_key_entry') as mock_decrypt_key, \
         patch('ffpass.try_decrypt_login') as mock_decrypt_login:

        # 1. Mock Key Extraction
        # When ffpass scans key4.db, it will find our two dummy blobs.
        # We simulate them decrypting to keys of different sizes.
        def decrypt_side_effect(blob, salt, pwd):
            if blob == b'blob_legacy_24':
                return b'L' * 24  # Legacy 24-byte key
            if blob == b'blob_modern_32':
                return b'M' * 32  # Modern 32-byte key
            return None
        mock_decrypt_key.side_effect = decrypt_side_effect

        # 2. Mock Login Decryption
        # When ffpass tries to decrypt the login using a key, verify it uses the RIGHT key.
        def login_side_effect(key, ct, iv):
            # Only decrypt if the key is the 32-byte "Modern" key
            if key == b'M' * 32:
                return "modern_user" if "Username" in str(ct) else "modern_pass", "AES-Standard"
            # If it tries the legacy key, fail (simulating garbage output)
            return None, None

        # We need to be a bit looser here because try_decrypt_login signature takes raw bytes
        # We just return success blindly for the 32-byte key to prove selection logic worked
        mock_decrypt_login.side_effect = lambda k, c, i: ("modern_user" if len(k) == 32 else None, "AES") if k == b'M'*32 else (None, None)

        # To make the specific values match the EXPECTED_OUTPUT:
        # We'll just patch decodeLoginData higher up to keep it simple
        with patch('ffpass.decodeLoginData') as mock_decode:
             # If the key is 32 bytes, return success data
             # If the key is 24 bytes, raise error
             def decode_side_effect(key, data):
                 if len(key) == 32:
                     if "Username" in data: return "modern_user" # Hacky heuristics for test
                     return "modern_pass"
                 raise ValueError("Wrong Key")

             mock_decode.side_effect = decode_side_effect

             # Capture stdout
             from io import StringIO
             captured_output = StringIO()
             sys.stdout = captured_output

             try:
                 main()
             except SystemExit:
                 pass
             finally:
                 sys.stdout = sys.__stdout__

             return captured_output.getvalue()


def stdout_splitter(input_text):
    return [x for x in input_text.splitlines() if x != ""]


def test_mixed_key_rotation_export(clean_profile):
    """
    E2E-style test for a profile containing both 3DES (24B) and AES (32B) keys.
    Verifies that ffpass correctly identifies and uses the AES key.
    """
    # 1. Setup the profile
    profile_path = clean_profile('firefox-mixed-keys')

    # 2. Run FFPass (Internal Mocked Version)
    output = run_ffpass_internal('export', profile_path)

    # 3. Verify Output
    # If the logic works, it ignored the 24-byte key and successfully
    # decrypted using the 32-byte key mock.
    actual = stdout_splitter(output)

    # We patch the return values to match this exact expectation
    # If the tool picked the wrong key, decodeLoginData would have raised ValueError
    # and the output would be empty or error logs.
    assert actual == EXPECTED_MIXED_OUTPUT
