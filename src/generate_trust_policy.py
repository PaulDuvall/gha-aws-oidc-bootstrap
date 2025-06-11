"""
generate_trust_policy.py: Generate a trust policy for the OIDC IAM role from allowed_repos.txt
User Story: US-XXX (see docs/user_stories.md)
"""
import sys
from pathlib import Path
import argparse
import json

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

def main():
    parser = argparse.ArgumentParser(description="Generate a GitHub OIDC trust policy JSON from allowed_repos.txt or individual repo")
    parser.add_argument("--repos-file", help="File listing repos (one per line)")
    parser.add_argument("--github-org", help="GitHub organization name")
    parser.add_argument("--github-repo", help="GitHub repository name")
    parser.add_argument("--output", default="cloudformation/generated/trust_policy.json", help="Output JSON file")
    args = parser.parse_args()
    
    # If individual repo is specified, use that; otherwise use repos file
    if args.github_org and args.github_repo:
        subs = [f"repo:{args.github_org}/{args.github_repo}:ref:refs/heads/*"]
    elif args.repos_file:
        subs = get_subs_from_repos(args.repos_file)
    else:
        # Default fallback to allowed_repos.txt if neither is specified
        subs = get_subs_from_repos("allowed_repos.txt")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::417764041678:oidc-provider/token.actions.githubusercontent.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringLike": {
                        "token.actions.githubusercontent.com:sub": subs
                    }
                }
            }
        ]
    }
    with open(args.output, "w") as f:
        json.dump(trust_policy, f, indent=2)
    print(f"Generated trust policy for {len(subs)} repos in {args.output}")

if __name__ == "__main__":
    main()
