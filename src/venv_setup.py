"""
venv_setup.py: Helper for ensuring Python venv setup
User Story: US-XXX (see docs/user_stories.md)
"""
import os
import sys
import subprocess
from pathlib import Path

def ensure_venv(venv_dir=".venv"):
    """
    Ensures a Python virtual environment exists at venv_dir.
    Returns True if venv was created, False if already present.
    """
    venv_path = Path(venv_dir)
    if venv_path.exists() and (venv_path / "bin" / "activate").exists():
        return False
    subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
    return True

if __name__ == "__main__":
    created = ensure_venv()
    print(f"venv created: {created}")
