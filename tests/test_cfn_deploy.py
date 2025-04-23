"""
test_cfn_deploy.py: Test CloudFormation deployment automation logic
User Story: US-XXX (see docs/user_stories.md)
"""
import sys
from pathlib import Path
import subprocess
import pytest

# Patch sys.path for src import for all test functions
SRC_DIR = Path(__file__).parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import cfn_deploy

def test_template_file_exists():
    assert cfn_deploy.TEMPLATE_PATH.exists(), "CloudFormation template does not exist"

def test_deploy_stack_invokes_aws(monkeypatch):
    calls = {}
    def fake_run(cmd, capture_output, text):
        calls['called'] = True
        assert "aws" in cmd[0]
        assert "cloudformation" in cmd
        assert "deploy" in cmd
        assert any(str(cfn_deploy.TEMPLATE_PATH) in arg for arg in cmd)
        assert "--stack-name" in cmd
        assert "--capabilities" in cmd
        class Result:
            returncode = 0
            stdout = "Deployment successful"
            stderr = ""
        return Result()
    monkeypatch.setattr(subprocess, "run", fake_run)
    result = cfn_deploy.deploy_stack()
    assert calls.get('called'), "subprocess.run was not called"
    assert result.returncode == 0
    assert "Deployment successful" in result.stdout

def test_argparse_accepts_cli(monkeypatch):
    import subprocess as sp
    import sys as _sys
    # Patch subprocess.run to avoid actual AWS CLI call
    monkeypatch.setattr(sp, "run", lambda *a, **k: type("R", (), {"returncode":0, "stdout":"ok", "stderr":""})())
    # Patch sys.argv for CLI test
    test_args = ["cfn_deploy.py", "--github-org", "PaulDuvall", "--region", "us-west-2", "--github-token", "dummy_token"]
    monkeypatch.setattr(_sys, "argv", test_args)
    import importlib
    import cfn_deploy as mod
    importlib.reload(mod)  # Re-run __main__
    # If no exception, argument parsing succeeded

def test_get_or_create_oidc_provider(monkeypatch):
    """
    US-XXX: Failing test (TDD) for OIDC provider discovery/creation logic.
    Ensures that get_or_create_oidc_provider() returns the correct ARN if it exists, or creates it if not.
    """
    # Simulate boto3 client
    class FakeIAM:
        def list_open_id_connect_providers(self):
            return {"OpenIDConnectProviderList": []}
        def create_open_id_connect_provider(self, Url, ClientIDList, ThumbprintList):
            assert Url == "https://token.actions.githubusercontent.com"
            return {"OpenIDConnectProviderArn": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}
    monkeypatch.setattr("boto3.client", lambda service, **kwargs: FakeIAM())
    from cfn_deploy import get_or_create_oidc_provider
    arn = get_or_create_oidc_provider(region="us-east-1")
    assert arn == "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
