import re
import subprocess
import sys
from pathlib import Path

def test_output_without_github_token(tmp_path):
    """
    Test that running the script without --github-token outputs:
    - The IAM Role ARN (starting with GHA_)
    - Step-by-step manual instructions
    - A direct link to the repo variables page
    - Example referencing the variable in workflow YAML
    """
    # Setup: dummy owner/repo for test
    owner = "octocat"
    repo = "hello-world"
    script_path = Path(__file__).parent.parent / "src" / "render_iam_template.py"
    
    # Run the script without --github-token
    result = subprocess.run(
        [sys.executable, str(script_path), "--owner", owner, "--repo", repo],
        capture_output=True,
        text=True
    )
    output = result.stdout

    # Check for IAM Role ARN (should be present in output, but not required to start with GHA_)
    assert re.search(r"arn:aws:iam::\d+:role/[\w+=,.@\-]+", output), "Missing or malformed IAM Role ARN"

    # Check for manual instructions (updated wording)
    assert "To use this role in your GitHub Actions workflow" in output
    assert "Option 1: Use a GitHub Actions variable" in output
    assert "Option 2: Reference the IAM Role ARN directly" in output
    assert "Settings → Secrets and variables → Actions → Variables" in output

    # Check for direct link to repo variables page
    link = f"https://github.com/{owner}/{repo}/settings/variables/actions"
    assert link in output, f"Missing direct link to repo variables page: {link}"

    # Check for workflow YAML reference with correct variable name
    assert "role-to-assume: ${{ vars.GHA_OIDC_ROLE_ARN }}" in output
    # Check for workflow YAML reference with direct ARN
    assert "role-to-assume: arn:aws:iam::" in output
