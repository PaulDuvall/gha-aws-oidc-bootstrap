"""
cfn_stack.py: Minimal CloudFormation template linter/validator
User Story: US-XXX (see docs/user_stories.md)
"""
import subprocess
from pathlib import Path

CLOUDFORMATION_TEMPLATE = Path(__file__).parent.parent / "cloudformation" / "iam_role.yaml"

def validate_template():
    """
    Validate the CloudFormation template using 'aws cloudformation validate-template'.
    Returns the subprocess.CompletedProcess result.
    """
    if not CLOUDFORMATION_TEMPLATE.exists():
        raise FileNotFoundError(f"Template not found: {CLOUDFORMATION_TEMPLATE}")
    result = subprocess.run([
        "aws", "cloudformation", "validate-template",
        "--template-body", f"file://{CLOUDFORMATION_TEMPLATE}"
    ], capture_output=True, text=True)
    return result

if __name__ == "__main__":
    res = validate_template()
    print(res.stdout)
    if res.returncode != 0:
        print(res.stderr)
        exit(res.returncode)
