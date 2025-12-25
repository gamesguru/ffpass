#!/usr/bin/env python3

import subprocess
import shutil
import pytest
from pathlib import Path

MASTER_PASSWORD = 'test'
HEADER = 'url,username,password\n'
IMPORT_CREDENTIAL = 'http://www.example.com,foo,bar\n'
EXPECTED_EXPORT_OUTPUT = f'{HEADER}http://www.stealmylogin.com,test,test\n'
EXPECTED_IMPORT_OUTPUT = EXPECTED_EXPORT_OUTPUT + IMPORT_CREDENTIAL


@pytest.fixture
def clean_profile(tmp_path):
    """
    Copies the requested profile to a temporary directory and returns
    the path to the new copy.
    """
    def _setup(profile_name):
        src = Path('tests') / profile_name
        dst = tmp_path / profile_name
        shutil.copytree(src, dst)
        return dst
    return _setup


def run_ffpass(mode, path):
    command = ["ffpass", mode, "-d", str(path)]

    if mode == 'import':
        ffpass_input = HEADER + IMPORT_CREDENTIAL
    else:
        ffpass_input = None

    return subprocess.run(command, stdout=subprocess.PIPE, input=ffpass_input, encoding='utf-8')


def test_legacy_firefox_export(clean_profile):
    r = run_ffpass('export', clean_profile('firefox-70'))
    r.check_returncode()
    assert r.stdout == EXPECTED_EXPORT_OUTPUT


def test_firefox_export(clean_profile):
    r = run_ffpass('export', clean_profile('firefox-84'))
    r.check_returncode()
    assert r.stdout == EXPECTED_EXPORT_OUTPUT


def test_firefox_aes_export(clean_profile):
    # This uses your new AES-encrypted profile
    profile_path = clean_profile('firefox-146-aes')
    r = run_ffpass('export', profile_path)
    r.check_returncode()
    assert r.stdout == EXPECTED_EXPORT_OUTPUT


def test_legacy_firefox(clean_profile):
    profile_path = clean_profile('firefox-70')

    # modifies the temp file, not the original
    r = run_ffpass('import', profile_path)
    r.check_returncode()

    r = run_ffpass('export', profile_path)
    r.check_returncode()
    assert r.stdout == EXPECTED_IMPORT_OUTPUT


def test_firefox(clean_profile):
    profile_path = clean_profile('firefox-84')

    r = run_ffpass('import', profile_path)
    r.check_returncode()

    r = run_ffpass('export', profile_path)
    r.check_returncode()
    assert r.stdout == EXPECTED_IMPORT_OUTPUT

