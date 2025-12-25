#!/usr/bin/env python3

import ffpass
from pathlib import Path
import pytest
import sqlite3
import shutil

# This key corresponds to the static 'tests/firefox-84' profile in your repo
TEST_KEY = b'\xbfh\x13\x1a\xda\xb5\x9d\xe3X\x10\xe0\xa8\x8a\xc2\xe5\xbcE\xf2I\r\xa2pm\xf4'
MASTER_PASSWORD = 'test'
MAGIC1 = b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"


def _get_key(directory, password=""):
    """
    Helper to adapt the new get_all_keys API to legacy test expectations.
    """
    keys, _ = ffpass.get_all_keys(directory, password)
    # Simulate askpass logic: prefer 32-byte key, else first found
    best = next((k for k in keys if len(k) == 32), keys[0])
    return best


@pytest.fixture
def mixed_key_profile(tmp_path):
    """
    Creates a temporary profile based on firefox-84, but duplicates
    the key entry in key4.db to simulate a "Key Rotation" scenario
    (multiple keys present).
    """
    # 1. Base the profile on an existing valid one
    src = Path('tests/firefox-84')
    dst = tmp_path / "firefox-mixed"
    shutil.copytree(src, dst)

    # 2. Open the DB
    db_path = dst / "key4.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()

    # 3. Fetch the existing key row
    c.execute("SELECT * FROM nssPrivate WHERE a102 = ?", (MAGIC1,))
    row = c.fetchone()

    # Get column names to find the 'id' column index
    col_names = [d[0] for d in c.description]

    if row:
        row_list = list(row)

        # 4. Modify the UNIQUE 'id' column to avoid IntegrityError
        if 'id' in col_names:
            id_idx = col_names.index('id')
            original_id = row_list[id_idx]

            # Increment ID if integer, or change if bytes
            if isinstance(original_id, int):
                row_list[id_idx] = original_id + 100  # Ensure uniqueness
            else:
                # Fallback for blobs/bytes
                row_list[id_idx] = b'\xff' * len(original_id)

        # 5. Insert the duplicate row
        placeholders = ",".join(["?"] * len(row_list))
        c.execute(f"INSERT INTO nssPrivate VALUES ({placeholders})", row_list)
        conn.commit()

    conn.close()
    return dst


def test_firefox_key():
    key = _get_key(Path('tests/firefox-84'))
    assert key == TEST_KEY


def test_firefox_mp_key():
    key = _get_key(Path('tests/firefox-mp-84'), MASTER_PASSWORD)
    assert key == TEST_KEY


def test_firefox_wrong_masterpassword_key():
    with pytest.raises(ffpass.WrongPassword):
        _get_key(Path('tests/firefox-mp-84'), 'wrongpassword')


def test_legacy_firefox_key():
    key = _get_key(Path('tests/firefox-70'))
    assert key == TEST_KEY


def test_legacy_firefox_mp_key():
    key = _get_key(Path('tests/firefox-mp-70'), MASTER_PASSWORD)
    assert key == TEST_KEY


def test_legacy_firefox_wrong_masterpassword_key():
    with pytest.raises(ffpass.WrongPassword):
        _get_key(Path('tests/firefox-mp-70'), 'wrongpassword')


def test_mixed_key_retrieval(mixed_key_profile):
    """
    Verifies that get_all_keys() finds multiple keys in the DB.
    """
    keys, _ = ffpass.get_all_keys(mixed_key_profile)

    # Since we manually duplicated the key row in the fixture,
    # we expect exactly 2 keys to be decrypted.
    assert len(keys) == 2

    # Both keys should be valid (and identical in this specific test case)
    assert keys[0] == TEST_KEY
    assert keys[1] == TEST_KEY
