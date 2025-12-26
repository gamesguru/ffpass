#!/usr/bin/env python3

import os
import subprocess
import shutil
import pytest
from pathlib import Path

OS_NEWLINE = os.linesep

MASTER_PASSWORD = 'test'
HEADER = 'url,username,password'
IMPORT_CREDENTIAL = 'http://www.example.com,foo,bar'
EXPECTED_EXPORT_OUTPUT = [HEADER, 'http://www.stealmylogin.com,test,test']
EXPECTED_IMPORT_OUTPUT = EXPECTED_EXPORT_OUTPUT + [IMPORT_CREDENTIAL]


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
    command = ["python", "./ffpass/__init__.py", mode, "-d", str(path)]

    if mode == 'import':
        ffpass_input = OS_NEWLINE.join([HEADER, IMPORT_CREDENTIAL])
    else:
        ffpass_input = None

    return subprocess.run(command, stdout=subprocess.PIPE, input=ffpass_input, encoding='utf-8')


def stdout_splitter(input_text):
    return [x for x in input_text.splitlines()]


def test_legacy_firefox_export(clean_profile):
    r = run_ffpass('export', clean_profile('firefox-70'))
    r.check_returncode()
    actual_export_output = stdout_splitter(r.stdout)
    assert actual_export_output == EXPECTED_EXPORT_OUTPUT


def test_firefox_export(clean_profile):
    r = run_ffpass('export', clean_profile('firefox-84'))
    r.check_returncode()
    assert stdout_splitter(r.stdout) == EXPECTED_EXPORT_OUTPUT


def test_firefox_aes_export(clean_profile):
    # This uses your new AES-encrypted profile
    profile_path = clean_profile('firefox-146-aes')
    r = run_ffpass('export', profile_path)
    r.check_returncode()
    assert stdout_splitter(r.stdout) == EXPECTED_EXPORT_OUTPUT


def test_legacy_firefox(clean_profile):
    profile_path = clean_profile('firefox-70')

    # modifies the temp file, not the original
    r = run_ffpass('import', profile_path)
    r.check_returncode()

    r = run_ffpass('export', profile_path)
    r.check_returncode()
    assert stdout_splitter(r.stdout) == EXPECTED_IMPORT_OUTPUT


def test_firefox(clean_profile):
    profile_path = clean_profile('firefox-84')

    r = run_ffpass('import', profile_path)
    r.check_returncode()

    r = run_ffpass('export', profile_path)
    r.check_returncode()
    assert stdout_splitter(r.stdout) == EXPECTED_IMPORT_OUTPUT
