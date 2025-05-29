"""
test_iam_role_template.py: Test CloudFormation IAM role template validity
User Story: US-XXX (see docs/user_stories.md)
"""
import yaml
from pathlib import Path

def ignore_unknown(loader, tag_suffix, node):
    # Return node as a string for unknown tags (like !Sub)
    return loader.construct_scalar(node)

yaml.SafeLoader.add_multi_constructor('!', ignore_unknown)

TEMPLATE_PATH = Path(__file__).parent.parent / "cloudformation" / "generated" / "iam_role.yaml"

def test_template_exists():
    assert TEMPLATE_PATH.exists(), f"{TEMPLATE_PATH} does not exist"

def test_yaml_valid():
    with TEMPLATE_PATH.open() as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict)
    assert "Resources" in data
    assert "GitHubActionsOIDCRole" in data["Resources"]
    role = data["Resources"]["GitHubActionsOIDCRole"]
    assert role["Type"] == "AWS::IAM::Role"
    assert "AssumeRolePolicyDocument" in role["Properties"]

def test_attaches_all_project_policies():
    """
    US-XXX: Test that all .json policy files in the project policies/ directory are attached to the IAM role in the template.
    """
    from pathlib import Path
    import yaml
    policies_dir = Path(__file__).parent.parent / "policies"
    project_policy_files = {p.name for p in policies_dir.iterdir() if p.suffix == ".json"}
    template_path = Path(__file__).parent.parent / "cloudformation" / "generated" / "iam_role.yaml"
    with template_path.open() as f:
        data = yaml.safe_load(f)
    role = data["Resources"]["GitHubActionsOIDCRole"]
    attached_policies = role["Properties"].get("Policies", [])
    attached_names = {p.get("PolicyName", "") for p in attached_policies}
    assert project_policy_files.issubset(attached_names), f"Not all project policies attached: {project_policy_files - attached_names}"

def test_policy_documents_are_inlined():
    """
    US-XXX: Failing test (TDD) for inlining policy documents.
    Checks that the PolicyDocument for each attached policy in the template matches the content of the corresponding .json file in policies/.
    """
    from pathlib import Path
    import yaml
    import json
    policies_dir = Path(__file__).parent.parent / "policies"
    template_path = Path(__file__).parent.parent / "cloudformation" / "generated" / "iam_role.yaml"
    with template_path.open() as f:
        data = yaml.safe_load(f)
    role = data["Resources"]["GitHubActionsOIDCRole"]
    attached_policies = role["Properties"].get("Policies", [])
    attached_by_name = {p["PolicyName"]: p for p in attached_policies}
    for policy_file in policies_dir.glob("*.json"):
        name = policy_file.name
        file_content = json.loads(policy_file.read_text())
        template_doc = attached_by_name.get(name, {}).get("PolicyDocument", None)
        assert template_doc == file_content, f"PolicyDocument for {name} is not inlined or does not match file content."

def test_custom_policy_file_attached(tmp_path):
    """
    US-XXX: Failing test (TDD) for custom policy file injection via --policy-file argument.
    Simulates rendering the template with a custom policy file and asserts it is present in the output.
    """
    import json
    import subprocess
    import yaml
    from pathlib import Path
    # 1. Create a custom policy file
    custom_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ssm:PutParameter", "ssm:GetParameter", "ssm:DeleteParameter"],
                "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/helloworld/*"
            }
        ]
    }
    custom_policy_path = tmp_path / "my-policy.json"
    custom_policy_path.write_text(json.dumps(custom_policy))

    # 2. Run the IAM template renderer with --policy-file (simulate CLI call)
    #    NOTE: This will fail until implementation supports --policy-file
    render_script = Path(__file__).parent.parent / "src" / "render_iam_template.py"
    output_template = tmp_path / "iam_role.yaml"
    # Simulate CLI: python render_iam_template.py --policy-file <path> --output <output_template>
    result = subprocess.run([
        "python3", str(render_script),
        "--policy-file", str(custom_policy_path),
        "--output", str(output_template)
    ], capture_output=True, text=True)
    # The script should exit 0 after implementation
    assert result.returncode == 0, f"Renderer failed: {result.stderr}"
    # 3. Check that the custom policy is present in the rendered template
    with output_template.open() as f:
        data = yaml.safe_load(f)
    role = data["Resources"]["GitHubActionsOIDCRole"]
    attached_policies = role["Properties"].get("Policies", [])
    found = False
    for policy in attached_policies:
        if policy.get("PolicyName") == "CustomPolicy" and policy.get("PolicyDocument") == custom_policy:
            found = True
    assert found, "Custom policy from --policy-file was not attached to the IAM role."
