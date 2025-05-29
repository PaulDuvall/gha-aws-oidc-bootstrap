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
    try:
        parser = argparse.ArgumentParser(description="Render IAM Role CloudFormation template and/or print IAM Role info.")
        parser.add_argument('--owner', type=str, help='GitHub repository owner/org')
        parser.add_argument('--repo', type=str, help='GitHub repository name')
        parser.add_argument('--account-id', type=str, default='123456789012', help='AWS Account ID (for output example)')
        parser.add_argument('--oidc-provider-arn', type=str, default='', help='OIDC Provider ARN')
        parser.add_argument('--policy-file', type=str, help='Path to custom policy JSON file')
        parser.add_argument('--output', type=str, default='cloudformation/generated/iam_role.yaml', help='Output path for rendered template')
        parser.add_argument('--github-token', type=str, help='GitHub PAT for automation (optional)')
        parser.add_argument('--role-name', type=str, default=None, help='IAM Role name (optional override)')
        args = parser.parse_args()

        print(f"DEBUG: owner={args.owner}, repo={args.repo}, output={args.output}", flush=True)

        # Load trust policy
        trust_policy_path = 'cloudformation/generated/trust_policy.json'
        print(f"DEBUG: Loading trust policy from {trust_policy_path}", flush=True)
        with open(trust_policy_path) as f:
            trust_policy = json.load(f)

        # Load policies
        policies = []
        policies_dir = os.path.join(os.path.dirname(__file__), '../policies')
        print(f"DEBUG: Loading policies from {policies_dir}", flush=True)
        for policy_file in os.listdir(policies_dir):
            if policy_file.endswith('.json'):
                with open(os.path.join(policies_dir, policy_file)) as pf:
                    policy_doc = json.load(pf)
                policies.append({
                    'name': policy_file,
                    'document': policy_doc
                })

        # Optionally add a custom policy
        if args.policy_file:
            print(f"DEBUG: Adding custom policy from {args.policy_file}", flush=True)
            with open(args.policy_file) as pf:
                custom_policy_doc = json.load(pf)
            policies.append({
                'name': 'CustomPolicy',
                'document': custom_policy_doc
            })

        template_path = os.path.join(os.path.dirname(__file__), '../cloudformation/iam_role.template.j2')
        print(f"DEBUG: Loading template from {template_path}", flush=True)
        env = Environment(
            loader=FileSystemLoader('cloudformation'),
            trim_blocks=True,
            lstrip_blocks=True
        )
        env.filters['to_nice_yaml_block'] = to_nice_yaml_block
        template = env.get_template('iam_role.template.j2')

        print("DEBUG: Rendering template and writing to output...", flush=True)
        rendered = template.render(
            trust_policy=trust_policy,
            policies=policies,
            owner=args.owner,
            repo=args.repo
        )

        # Write to specified output file
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, 'w') as f:
            f.write(rendered)
        print("DEBUG: Successfully wrote IAM template.", flush=True)

        # If no --github-token, print instructions and exit (TDD: manual mode)
        if not args.github_token and args.owner and args.repo:
            role_name = args.role_name or f"GHA_OIDC_ROLE_{args.owner.upper()}_{args.repo.upper()}_ROLE"
            role_arn = f"arn:aws:iam::{args.account_id}:role/{role_name}"
            print(f"\nIAM Role ARN: {role_arn}")
            print_github_oidc_instructions(role_arn, args.owner, args.repo)
            return
    except Exception as e:
        print(f"ERROR: {e}", flush=True)
        raise

if __name__ == '__main__':
    main()
