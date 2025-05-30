"""
cfn_deploy.py: Minimal CloudFormation stack deployment automation
User Story: US-XXX (see docs/user_stories.md)
"""
import subprocess
from pathlib import Path
import argparse
import sys
import boto3

TEMPLATE_PATH = Path(__file__).parent.parent / "cloudformation" / "generated" / "iam_role.yaml"
STACK_NAME = None  # Will be set dynamically
DEFAULT_REGION = "us-east-1"

def deploy_stack(region=DEFAULT_REGION, oidc_provider_arn=None):
    """
    Deploys the CloudFormation stack using AWS CLI.
    Returns subprocess.CompletedProcess.
    """
    if not TEMPLATE_PATH.exists():
        raise FileNotFoundError(f"Template not found: {TEMPLATE_PATH}")
    result = subprocess.run([
        "aws", "cloudformation", "deploy",
        "--stack-name", STACK_NAME,
        "--template-file", str(TEMPLATE_PATH),
        "--region", region,
        "--parameter-overrides", f"OIDCProviderArn={oidc_provider_arn}",
        "--capabilities", "CAPABILITY_NAMED_IAM"
    ], capture_output=True, text=True)
    return result

def get_or_create_oidc_provider(region):
    """
    Returns the ARN for the GitHub Actions OIDC provider in this AWS account.
    If it does not exist, creates it and returns the ARN.
    """
    iam = boto3.client("iam", region_name=region)
    provider_url = "https://token.actions.githubusercontent.com"
    # 1. Check if provider exists
    resp = iam.list_open_id_connect_providers()
    for prov in resp.get("OpenIDConnectProviderList", []):
        arn = prov["Arn"] if isinstance(prov, dict) else prov
        if arn.endswith("oidc-provider/token.actions.githubusercontent.com"):
            return arn
    # 2. Create provider if not found
    # (Thumbprint for GitHub OIDC is always this value)
    thumbprints = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
    client_ids = ["sts.amazonaws.com"]
    create_resp = iam.create_open_id_connect_provider(
        Url=provider_url,
        ClientIDList=client_ids,
        ThumbprintList=thumbprints
    )
    return create_resp["OpenIDConnectProviderArn"]

def print_manual_github_oidc_instructions(role_arn, github_org, repo):
    print("\nTo use this IAM Role in your GitHub Actions workflow:\n")
    print("Option 1: Use a GitHub Actions variable (recommended for teams)")
    print("-------------------------------------------------------------")
    print("1. Go to your repository on GitHub.")
    print("2. Navigate to Settings → Secrets and variables → Actions → Variables.")
    print("3. Add a new variable:")
    print("   Name: GHA_OIDC_ROLE_ARN")
    print(f"   Value: {role_arn}\n")
    if github_org and repo:
        print(f"4. Or use this direct link: https://github.com/{github_org}/{repo}/settings/variables/actions\n")
    print("5. In your workflow YAML, reference the variable:\n")
    print("   - uses: aws-actions/configure-aws-credentials@v4")
    print("     with:")
    print("       role-to-assume: ${{ vars.GHA_OIDC_ROLE_ARN }}")
    print("       aws-region: us-east-1\n")
    print("Option 2: Reference the IAM Role ARN directly (simple for solo use)")
    print("-------------------------------------------------------------")
    print("In your workflow YAML, you can also hardcode the ARN directly:")
    print("   - uses: aws-actions/configure-aws-credentials@v4")
    print("     with:")
    print(f"       role-to-assume: {role_arn}")
    print("       aws-region: us-east-1\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy IAM role CloudFormation stack for GitHub Actions OIDC")
    parser.add_argument("--github-org", required=False, help="GitHub organization name")
    parser.add_argument("--github-repo", required=False, help="GitHub repository name")
    parser.add_argument("--region", default=DEFAULT_REGION, help="AWS region")
    parser.add_argument("--github-token", required=False, help="GitHub fine-grained PAT token")
    parser.add_argument("--oidc-provider-arn", required=False, help="OIDC provider ARN for GitHub Actions")
    args = parser.parse_args()

    # Compose unique stack name
    if args.github_org and args.github_repo:
        STACK_NAME = f"gha-aws-oidc-{args.github_org.lower()}-{args.github_repo.lower()}"
    elif args.github_org:
        STACK_NAME = f"gha-aws-oidc-{args.github_org.lower()}"
    else:
        STACK_NAME = "gha-aws-oidc-bootstrap"

    print(f"GitHub Org: {args.github_org}")
    print(f"GitHub Repo: {args.github_repo}")
    print(f"Region: {args.region}")
    print(f"GitHub Token Provided: {'yes' if args.github_token else 'no'}")
    if args.oidc_provider_arn:
        print(f"OIDC Provider ARN: {args.oidc_provider_arn}")
        oidc_provider_arn = args.oidc_provider_arn
    else:
        oidc_provider_arn = get_or_create_oidc_provider(args.region)
        print(f"OIDC Provider ARN: {oidc_provider_arn}")
    res = subprocess.run([
        "aws", "cloudformation", "deploy",
        "--stack-name", STACK_NAME,
        "--template-file", str(TEMPLATE_PATH),
        "--region", args.region,
        "--parameter-overrides", f"OIDCProviderArn={oidc_provider_arn}",
        "--capabilities", "CAPABILITY_NAMED_IAM"
    ], capture_output=True, text=True)
    print(res.stdout)
    if res.returncode != 0:
        print(res.stderr)
        exit(res.returncode)
    # Print IAM Role name from stack outputs
    import json
    import boto3
    cf = boto3.client("cloudformation", region_name=args.region)
    stack = cf.describe_stacks(StackName=STACK_NAME)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    role_arn = outputs.get("RoleArn")
    if role_arn:
        role_name = role_arn.split("/")[-1]
        print(f"Created/updated IAM Role name: {role_name}")
        # Set GitHub Actions variable GHA_OIDC_ROLE_ARN for all repos in allowed_repos.txt
        import subprocess
        import os
        github_token = args.github_token or os.environ.get("GITHUB_TOKEN")
        if github_token:
            print("Setting GHA_OIDC_ROLE_ARN GitHub Actions variable for all repos in allowed_repos.txt...")
            subprocess.run([
                sys.executable, "src/set_github_variable.py",
                "--github-org", args.github_org,
                "--github-token", github_token,
                "--var-name", "GHA_OIDC_ROLE_ARN",
                "--var-value", role_arn,
                "--repos-file", "allowed_repos.txt"
            ], check=False)
        else:
            repo = args.github_repo
            print_manual_github_oidc_instructions(role_arn, args.github_org, repo)
    else:
        print("IAM Role ARN not found in stack outputs.")
