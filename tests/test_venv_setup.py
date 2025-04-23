"""
test_venv_setup.py: Tests for venv_setup.py
User Story: US-XXX (see docs/user_stories.md)
"""
import shutil
import os
from pathlib import Path
import sys
import pytest

# Ensure src/ is on sys.path for import
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

import venv_setup

TEST_VENV = ".test-venv"

def teardown_module(module):
    # Remove test venv after tests
    if Path(TEST_VENV).exists():
        shutil.rmtree(TEST_VENV)

def test_ensure_venv_creates_new():
    if Path(TEST_VENV).exists():
        shutil.rmtree(TEST_VENV)
    created = venv_setup.ensure_venv(TEST_VENV)
    assert created
    assert Path(TEST_VENV).exists()
    assert (Path(TEST_VENV) / "bin" / "activate").exists()

def test_ensure_venv_idempotent():
    Path(TEST_VENV).mkdir(exist_ok=True)
    (Path(TEST_VENV) / "bin").mkdir(exist_ok=True)
    (Path(TEST_VENV) / "bin" / "activate").touch()
    created = venv_setup.ensure_venv(TEST_VENV)
    assert not created
