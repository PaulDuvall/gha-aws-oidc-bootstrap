"""
set_github_variable.py: Set a GitHub Actions repository variable across multiple repos
User Story: US-130 (see docs/user_stories.md)
"""
import requests
import sys
from pathlib import Path
import argparse

GITHUB_API = "https://api.github.com"


def set_repo_variable(org, repo, var_name, var_value, github_token):
    url = f"{GITHUB_API}/repos/{org}/{repo}/actions/variables/{var_name}"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json"
    }
    # Try PATCH (update) first, fall back to POST (create)
    resp = requests.patch(url, headers=headers, json={"value": var_value})
    if resp.ok:
        print(f"✅ Updated variable '{var_name}' for {org}/{repo}.")
        return True
    if resp.status_code == 404:
        # Variable does not exist, create it
        create_url = f"{GITHUB_API}/repos/{org}/{repo}/actions/variables"
        resp = requests.post(create_url, headers=headers, json={"name": var_name, "value": var_value})
        if resp.ok:
            print(f"✅ Created variable '{var_name}' for {org}/{repo}.")
            return True
        else:
            print(f"❌ Failed to create variable '{var_name}' for {org}/{repo}: {resp.status_code} {resp.text}", file=sys.stderr)
            return False
    else:
        print(f"❌ Failed to update variable '{var_name}' for {org}/{repo}: {resp.status_code} {resp.text}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Set a GitHub Actions repo variable for all repos in allowed_repos.txt")
    parser.add_argument("--github-org", required=True, help="GitHub organization name")
    parser.add_argument("--github-token", required=True, help="GitHub Personal Access Token (PAT)")
    parser.add_argument("--var-name", required=True, help="Variable name to set")
    parser.add_argument("--var-value", required=True, help="Variable value to set")
    parser.add_argument("--repos-file", default="allowed_repos.txt", help="File listing repos (one per line, default: allowed_repos.txt)")
    args = parser.parse_args()

    repos_path = Path(args.repos_file)
    if not repos_path.exists():
        print(f"Repos file not found: {repos_path}", file=sys.stderr)
        sys.exit(1)
    repos = [line.strip() for line in repos_path.read_text().splitlines() if line.strip() and not line.startswith("#")]
    for repo in repos:
        if "/" in repo:
            org, repo_name = repo.split("/", 1)
        else:
            org, repo_name = args.github_org, repo
        set_repo_variable(org, repo_name, args.var_name, args.var_value, args.github_token)

if __name__ == "__main__":
    main()
