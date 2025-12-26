#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Dec 26 00:13:51 2025

@author: shane
"""

import shutil
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

# Allow importing ffpass from source
sys.path.insert(0, str(Path(__file__).parent.parent))

import ffpass  # noqa: E402
from ffpass import main  # noqa: E402

MASTER_PASSWORD = "password123"


@pytest.fixture
def mp_profile(tmp_path):
    """
    Setup the MP profile with REAL encrypted data.
    Requires running scripts/generate_mp_profile.py first.
    """
    src = Path("tests/firefox-mp-test")
    if not src.exists():
        pytest.fail(
            "Run scripts/generate_mp_profile.py first to generate real crypto assets"
        )
    dst = tmp_path / "firefox-mp-test"
    shutil.copytree(src, dst)
    return dst


def test_export_with_correct_password(mp_profile):
    """
    Verifies that providing the correct password via stdin allows
    successful decryption of the database.
    """
    # Mock user input to return correct password immediately
    ffpass.getpass = lambda x: MASTER_PASSWORD

    # Capture stdout to verify CSV output
    capture = StringIO()

    with patch("sys.argv", ["ffpass", "export", "-d", str(mp_profile)]), patch(
        "sys.stdout", capture
    ):

        # Run real main() - no internal crypto mocks!
        # This proves verify_password -> decrypt_key -> decodeLoginData all work
        try:
            main()
        except SystemExit:
            pass

    output = capture.getvalue()
    print(output)  # For debugging failures

    # Verify we successfully decrypted the specific credentials in logins.json
    assert "url,username,password" in output
    assert "https://locked.com,secret_user,secret_pass" in output


def test_export_with_wrong_password_retry(mp_profile):
    """
    Verifies the retry logic:
    1. Enter wrong password -> fail
    2. Enter correct password -> succeed
    """
    # Create an iterator that yields Wrong, then Right
    # This simulates the user typing correctly on the second attempt
    inputs = iter(["wrong_pass", MASTER_PASSWORD])

    ffpass.getpass = lambda x: next(inputs)

    capture = StringIO()

    with patch("sys.argv", ["ffpass", "export", "-d", str(mp_profile)]), patch(
        "sys.stdout", capture
    ):

        try:
            main()
        except SystemExit:
            pass

    output = capture.getvalue()

    # It should eventually succeed and print the data
    assert "secret_user" in output


def test_import_with_stdin_password(mp_profile):
    """
    Verifies that import also respects the password prompt mechanism.
    """
    ffpass.getpass = lambda x: MASTER_PASSWORD

    # Prepare input CSV for import
    input_csv = "url,username,password\nhttps://newsite.com,new_user,new_pass"

    # We need to mock stdin for the CSV data itself
    # AND mock ffpass.getpass for the master password

    # ffpass.main_import reads from args.file.
    # If args.file is sys.stdin, we must patch sys.stdin.

    with patch("sys.argv", ["ffpass", "import", "-d", str(mp_profile)]), patch(
        "sys.stdin", StringIO(input_csv)
    ):

        try:
            main()
        except SystemExit:
            pass

    # Verify the new login was actually added to the file
    # We can check by running export again or inspecting the JSON
    import json

    with open(mp_profile / "logins.json", "r") as f:
        data = json.load(f)

    # The file is encrypted, so we can't grep "new_user" directly.
    # We just check that the login count increased (was 1, now 2)
    assert len(data["logins"]) == 2
    assert data["nextId"] == 3
