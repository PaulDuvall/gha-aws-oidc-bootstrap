"""
test_cfn_stack.py: Test CloudFormation stack Python logic
User Story: US-XXX (see docs/user_stories.md)
"""
import sys
from pathlib import Path
import subprocess
import pytest

SRC_DIR = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

import cfn_stack

def test_template_file_exists():
    assert cfn_stack.CLOUDFORMATION_TEMPLATE.exists(), "CloudFormation template does not exist"

def test_validate_template_invokes_aws(monkeypatch):
    calls = {}
    def fake_run(cmd, capture_output, text):
        calls['called'] = True
        assert "aws" in cmd[0]
        assert "cloudformation" in cmd
        assert "validate-template" in cmd
        assert any(str(cfn_stack.CLOUDFORMATION_TEMPLATE) in arg for arg in cmd)
        class Result:
            returncode = 0
            stdout = "Validation successful"
            stderr = ""
        return Result()
    monkeypatch.setattr(subprocess, "run", fake_run)
    result = cfn_stack.validate_template()
    assert calls.get('called'), "subprocess.run was not called"
    assert result.returncode == 0
    assert "Validation successful" in result.stdout
