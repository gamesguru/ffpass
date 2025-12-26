#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Dec 25 19:30:48 2025

@author: shane
"""

import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

HEADER = "url,username,password"
EXPECTED_MIXED_OUTPUT = [HEADER, "http://www.mixedkeys.com,modern_user,modern_pass"]


@pytest.fixture
def clean_profile(tmp_path):
    def _setup(profile_name):
        src = Path("tests") / profile_name
        dst = tmp_path / profile_name
        if not src.exists():
            pytest.fail(
                f"Test profile '{profile_name}' not found. Run generate_mixed_profile.py first."
            )
        shutil.copytree(src, dst)
        return dst

    return _setup


def run_ffpass_internal(mode, path):
    from ffpass import main

    test_args = ["ffpass", mode, "-d", str(path)]

    # We patch get_all_keys directly to avoid the infinite loop issue
    # and avoid needing complex ASN.1 mocking for the password check.
    with (
        patch("sys.argv", test_args),
        patch("ffpass.get_all_keys") as mock_get_keys,
        patch("ffpass.try_decrypt_login") as mock_decrypt_login,
    ):

        # 1. Mock Key Return
        # Simulate finding two keys: Legacy (24 bytes) and Modern (32 bytes)
        mock_get_keys.return_value = ([b"L" * 24, b"M" * 32], b"salt")

        # 2. Mock Golden Key Check
        # Verify the tool checks if the key works on the first row
        def try_login_side_effect(key, ct, iv):
            if key == b"M" * 32:
                return "valid_utf8", "AES-Standard"
            return None, None

        mock_decrypt_login.side_effect = try_login_side_effect

        # 3. Mock Final Decryption
        with patch("ffpass.decodeLoginData") as mock_decode:
            # Use iterator to return user then pass
            return_values = iter(["modern_user", "modern_pass"])

            def decode_side_effect(key, data):
                if len(key) == 32:
                    try:
                        return next(return_values)
                    except StopIteration:
                        return "extra"
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
    profile_path = clean_profile("firefox-mixed-keys")
    output = run_ffpass_internal("export", profile_path)
    actual = stdout_splitter(output)
    assert actual == EXPECTED_MIXED_OUTPUT
