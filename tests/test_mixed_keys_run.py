#!/usr/bin/env python3

import os
import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Add project root to path so we can import ffpass internals for mocking
sys.path.insert(0, str(Path(__file__).parent.parent))

from ffpass import get_all_keys

OS_NEWLINE = os.linesep
HEADER = "url,username,password"
EXPECTED_MIXED_OUTPUT = [HEADER, "http://www.mixedkeys.com,modern_user,modern_pass"]


@pytest.fixture
def clean_profile(tmp_path):
    """
    Copies the requested profile to a temporary directory.
    """

    def _setup(profile_name):
        src = Path("tests") / profile_name
        dst = tmp_path / profile_name
        if not src.exists():
            pytest.fail(
                f"Test profile '{profile_name}' not found. Did you run scripts/generate_mixed_profile.py?"
            )
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
    with patch("sys.argv", test_args), patch(
        "ffpass.decrypt_key_entry"
    ) as mock_decrypt_key, patch("ffpass.try_decrypt_login") as mock_decrypt_login:

        # 1. Mock Key Extraction
        # When ffpass scans key4.db, it will find our two dummy blobs.
        # We simulate them decrypting to keys of different sizes.
        def decrypt_side_effect(blob, salt, pwd):
            if blob == b"blob_legacy_24":
                return b"L" * 24  # Legacy 24-byte key
            if blob == b"blob_modern_32":
                return b"M" * 32  # Modern 32-byte key
            return None

        mock_decrypt_key.side_effect = decrypt_side_effect

        # 2. Mock Golden Key Check (try_decrypt_login)
        # This function is called to verify if a key works on the first row.
        # We return success only for the 32-byte key.
        def try_login_side_effect(key, ct, iv):
            if key == b"M" * 32:
                # Return a valid string so the check passes
                return "valid_utf8_string", "AES-Standard"
            return None, None

        mock_decrypt_login.side_effect = try_login_side_effect

        # 3. Mock Final Decryption (decodeLoginData)
        # This is used during the actual CSV export loop.
        with patch("ffpass.decodeLoginData") as mock_decode:
            # Since the test data has identical strings for user/pass,
            # we use an iterator to return 'user' first, then 'pass'.
            return_values = iter(["modern_user", "modern_pass"])

            def decode_side_effect(key, data):
                if len(key) == 32:
                    try:
                        return next(return_values)
                    except StopIteration:
                        return "extra_field"
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
    profile_path = clean_profile("firefox-mixed-keys")

    # 2. Run FFPass (Internal Mocked Version)
    output = run_ffpass_internal("export", profile_path)

    # 3. Verify Output
    actual = stdout_splitter(output)

    assert actual == EXPECTED_MIXED_OUTPUT
