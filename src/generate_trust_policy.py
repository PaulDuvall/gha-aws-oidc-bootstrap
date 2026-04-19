"""
generate_trust_policy.py: Generate a trust policy for the OIDC IAM role from allowed_repos.txt
User Story: US-XXX (see docs/user_stories.md)
"""
import sys
from pathlib import Path
import argparse
import json
import boto3

def get_aws_account_id():
    """Resolve the current AWS account ID via STS caller identity."""
    return boto3.client("sts").get_caller_identity()["Account"]

def get_subs_from_repos(repos_file):
    subs = []
    if not Path(repos_file).exists():
        example = repos_file + ".example"
        msg = (
            f"\n[ERROR] The repository list file '{repos_file}' was not found.\n"
            f"Please create this file in your project root and list each allowed repository (in 'org/repo' format) on a separate line.\n"
            f"You can use '{example}' as a template.\n"
            f"\nExample entries:\n  PaulDuvall/gha-aws-oidc-bootstrap\n  PaulDuvall/llm-guardian\n  PaulDuvall/owasp_llm_top10\n"
        )
        print(msg, file=sys.stderr)
        sys.exit(2)
    with open(repos_file) as f:
        for line in f:
            repo = line.strip()
            if repo and not repo.startswith("#"):
                subs.append(f"repo:{repo}:ref:refs/heads/*")
    return subs

def parse_args():
    parser = argparse.ArgumentParser(description="Generate a GitHub OIDC trust policy JSON from allowed_repos.txt or individual repo")
    parser.add_argument("--repos-file", help="File listing repos (one per line)")
    parser.add_argument("--github-org", help="GitHub organization name")
    parser.add_argument("--github-repo", help="GitHub repository name")
    parser.add_argument("--aws-account-id", help="AWS account ID (defaults to STS caller identity)")
    parser.add_argument("--output", default="cloudformation/generated/trust_policy.json", help="Output JSON file")
    return parser.parse_args()

def resolve_subs(args):
    if args.github_org and args.github_repo:
        return [f"repo:{args.github_org}/{args.github_repo}:ref:refs/heads/*"]
    if args.repos_file:
        return get_subs_from_repos(args.repos_file)
    return get_subs_from_repos("allowed_repos.txt")

def build_trust_policy(account_id, subs):
    federated = f"arn:aws:iam::{account_id}:oidc-provider/token.actions.githubusercontent.com"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": federated},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringLike": {
                        "token.actions.githubusercontent.com:sub": subs
                    }
                }
            }
        ]
    }

def main():
    args = parse_args()
    subs = resolve_subs(args)
    account_id = args.aws_account_id or get_aws_account_id()
    trust_policy = build_trust_policy(account_id, subs)
    with open(args.output, "w") as f:
        json.dump(trust_policy, f, indent=2)
    print(f"Generated trust policy for {len(subs)} repos in {args.output}")

if __name__ == "__main__":
    main()
