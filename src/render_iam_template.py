import os
import yaml
import json
from jinja2 import Environment, FileSystemLoader
import argparse

def load_policies(policies_dir):
    policies = []
    for filename in os.listdir(policies_dir):
        if filename.endswith('.json'):
            with open(os.path.join(policies_dir, filename)) as f:
                policies.append({
                    'name': filename,
                    'document': json.load(f)
                })
    return policies

def to_nice_yaml_block(value, indent=12):
    # Dump YAML, remove document separator, and indent every line
    yaml_str = yaml.dump(value, default_flow_style=False, sort_keys=False)
    yaml_str = yaml_str.replace('---\n', '')
    pad = ' ' * indent
    return ''.join(pad + line if line.strip() else line for line in yaml_str.splitlines(keepends=True))

def print_github_oidc_instructions(role_arn, owner, repo):
    print("\nTo use this role in your GitHub Actions workflow:\n")
    print("Option 1: Use a GitHub Actions variable (recommended for teams)")
    print("-------------------------------------------------------------")
    print("1. Go to your repository on GitHub.")
    print("2. Navigate to Settings → Secrets and variables → Actions → Variables.")
    print("3. Add a new variable:")
    print("   Name: GHA_OIDC_ROLE_ARN")
    print(f"   Value: {role_arn}\n")
    if owner and repo:
        print(f"4. Or use this direct link: https://github.com/{owner}/{repo}/settings/variables/actions\n")
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

def main():
    parser = argparse.ArgumentParser(description="Render IAM Role CloudFormation template and/or print IAM Role info.")
    parser.add_argument('--owner', type=str, help='GitHub repository owner/org')
    parser.add_argument('--repo', type=str, help='GitHub repository name')
    parser.add_argument('--account-id', type=str, default='123456789012', help='AWS Account ID (for output example)')
    parser.add_argument('--role-name', type=str, default=None, help='IAM Role name (default: GHA_OIDC_ROLE_<OWNER>_<REPO>_ROLE)')
    parser.add_argument('--github-token', type=str, help='GitHub PAT for automation (optional)')
    args = parser.parse_args()

    # If no --github-token, print instructions and exit (TDD: manual mode)
    if not args.github_token and args.owner and args.repo:
        role_name = args.role_name or f"GHA_OIDC_ROLE_{args.owner.upper()}_{args.repo.upper()}_ROLE"
        role_arn = f"arn:aws:iam::{args.account_id}:role/{role_name}"
        print(f"\nIAM Role ARN: {role_arn}")
        print_github_oidc_instructions(role_arn, args.owner, args.repo)
        return

    env = Environment(
        loader=FileSystemLoader('cloudformation'),
        trim_blocks=True,
        lstrip_blocks=True
    )
    env.filters['to_nice_yaml_block'] = to_nice_yaml_block
    template = env.get_template('iam_role.template.j2')

    with open('cloudformation/generated/trust_policy.json') as f:
        trust_policy = json.load(f)

    policies = load_policies('policies')

    rendered = template.render(
        trust_policy=trust_policy,
        policies=policies
    )

    # Write to generated folder instead of cloudformation root
    os.makedirs('cloudformation/generated', exist_ok=True)
    with open('cloudformation/generated/iam_role.yaml', 'w') as f:
        f.write(rendered)

if __name__ == '__main__':
    main()
