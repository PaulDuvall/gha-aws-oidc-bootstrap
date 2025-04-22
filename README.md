# GHA AWS OIDC Bootstrap
[![GitHub Actions Workflow Status](https://github.com/PaulDuvall/gha-aws-oidc-bootstrap/actions/workflows/verify_oidc.yml/badge.svg)](https://github.com/PaulDuvall/gha-aws-oidc-bootstrap/actions/workflows/verify_oidc.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/PaulDuvall/gha-aws-oidc-bootstrap)

This project provides a secure, automated setup for AWS OIDC authentication with GitHub Actions.

- Modular Bash script ([setup_oidc.sh](setup_oidc.sh)) for provisioning AWS IAM roles and trust policies
- GitHub Actions workflows for OIDC verification and code linting
- Documentation and CI/CD best practices

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/PaulDuvall/gha-aws-oidc-bootstrap.git
cd gha-aws-oidc-bootstrap
```

### 2. Run the OIDC Setup Script

```bash
bash setup_oidc.sh --github-org <ORG> --allowed-repos <repo1,repo2,...> --region <aws-region> --github-token <GITHUB_TOKEN>
```

- The script will always grant access to the current repository by default (auto-detected).
- To allow additional repositories, add each one (in `org/repo` format) to `allowed_repos.txt` (one per line) before running the script.
- You do NOT need to edit `allowed_repos.txt` if you only want to enable OIDC for the current repository.

### 3. Commit and Push Changes

```bash
git add .
git commit -m "chore: initial OIDC setup"
git push
```

---

## Secure OIDC Integration: What Happens Under the Hood

This automation sets up secure OIDC authentication between GitHub Actions and AWS, eliminating static AWS credentials and enabling short-lived, tightly-scoped credentials for every workflow run. Here’s what happens automatically (and what you’d otherwise do manually):

1. **Create the OIDC Identity Provider in AWS IAM**
   - Adds `token.actions.githubusercontent.com` as a provider and sets audience to `sts.amazonaws.com`.
2. **Create the IAM Role with Trust and Permissions**
   - Generates a trust policy allowing GitHub Actions from your current repo (and any in `allowed_repos.txt`) to assume the role via OIDC.
   - Attaches a permissions policy granting only the required AWS actions.
3. **Set the GitHub Repository Variable**
   - Sets the `GHA_OIDC_ROLE_ARN` variable in your GitHub repository, referencing the IAM Role ARN.
4. **(Optional) Manage Parameter Store/Secrets**
   - If needed, configures AWS SSM Parameter Store entries using SecureString and grants the IAM Role permission to read them.
5. **Update Trust Policy for Cross-Repo Access**
   - To allow another repo, add it to `allowed_repos.txt` and rerun the script.

You can view and manage the OIDC provider in the AWS Console (IAM > Identity providers) or with:
```bash
aws iam list-open-id-connect-providers
```

---

## Using the Tool: GitHub Token Requirements

When running `setup_oidc.sh`, you’ll be prompted for a GitHub Personal Access Token (PAT). This token is required to set repository variables and manage GitHub Actions configuration programmatically.

**How to create your GitHub token:**
1. Go to [GitHub > Settings > Developer settings > Personal access tokens](https://github.com/settings/tokens)
2. Click "Generate new token" (classic) or "Fine-grained token"
3. Name your token and set an expiration
4. **Required scopes:**
   - Classic: `repo` (for private repos), `workflow`, `admin:repo_hook`
   - Fine-grained: "Actions" (Read/Write), "Variables" (Read/Write), "Secrets" (if needed) for the target repo
5. Copy the token (you won’t be able to see it again)

**How it works:**
- The script uses your token to set up repository variables (like `GHA_OIDC_ROLE_ARN`) and configure GitHub Actions securely.
- The stack is designed for any target GitHub repository—not just the one running the automation.

---

## Example: GitHub Actions OIDC Workflow

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: actions/checkout@v4
  - name: Configure AWS credentials
    uses: aws-actions/configure-aws-credentials@v2
    with:
      role-to-assume: ${{ vars.GHA_OIDC_ROLE_ARN }}
      aws-region: us-east-1
      audience: sts.amazonaws.com
```

---

## Single-Stack, Multi-Repo OIDC Setup (Recommended)

This approach lets you manage OIDC access for multiple GitHub repositories using a single CloudFormation stack and IAM role.

### 1. Prepare Your Repository List
- **Create an `allowed_repos.txt` file in the project root listing each allowed repository in `org/repo` format, one per line.**
- **Do NOT commit your `allowed_repos.txt` file.** It is gitignored by default. Instead, use the provided `allowed_repos.txt.example` as a template for contributors.
- Example `allowed_repos.txt`:
  ```
  PaulDuvall/gha-aws-oidc-bootstrap
  PaulDuvall/llm-guardian
  PaulDuvall/owasp_llm_top10
  ```
- The organization name must be included for each repo (e.g., `PaulDuvall/gha-aws-oidc-bootstrap`).
- To allow additional repositories, add them to `allowed_repos.txt` and rerun the setup script.

### 2. Deploy the CloudFormation Stack
Use the AWS CLI to deploy the stack:

```bash
aws cloudformation deploy \
  --template-file oidc-multi-repo-role.yaml \
  --stack-name github-oidc-multi-repo \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    GitHubOrg=YourOrg \
    AllowedRepos="repo-one,repo-two,repo-three" \
    RoleName=github-oidc-multi-repo-role
```
- Replace `YourOrg` with your GitHub organization name.
- Update the `AllowedRepos` value as needed.

### 3. Update Allowed Repositories
To add or remove repositories, update the `AllowedRepos` parameter and redeploy:

```bash
aws cloudformation deploy \
  --template-file oidc-multi-repo-role.yaml \
  --stack-name github-oidc-multi-repo \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    GitHubOrg=YourOrg \
    AllowedRepos="repo-one,repo-two,new-repo" \
    RoleName=github-oidc-multi-repo-role
```

### 4. Reference the IAM Role in GitHub Actions
In your GitHub Actions workflow, use:

```yaml
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v2
  with:
    role-to-assume: arn:aws:iam::<AWS_ACCOUNT_ID>:role/github-oidc-multi-repo-role
    aws-region: us-east-1
    audience: sts.amazonaws.com
```

---

For advanced automation or integration with existing scripts, you may modify `setup_oidc.sh` to use the new template and pass the appropriate parameters as shown above.

---

## ✅ Linting and Code Quality

This project enforces code quality and security using automated linting on every push and pull request to the `main` branch.

- **Python code** is checked with [`flake8`](https://flake8.pycqa.org/) (Python 3.11)
- **Shell scripts** are checked with [`shellcheck`](https://www.shellcheck.net/)
- All scripts and workflows are linted for both quality and security

**GitHub Actions Workflow:** [`.github/workflows/lint.yml`](.github/workflows/lint.yml)

### Run Lint Checks Locally

To check code quality before pushing changes:

```bash
# Python linting (requires Python 3.11)
pip install flake8
flake8 .

# Shell script linting
shellcheck setup_oidc.sh
```

#### Example Workflow Output

```yaml
name: Lint

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: |
          python -m pip install --upgrade pip
          pip install flake8
          flake8 .
      - uses: ludeeus/action-shellcheck@v2
```

---

## 🧪 OIDC Verification Workflow

This repository includes a manual workflow to verify OIDC authentication end-to-end. Trigger this workflow from the GitHub Actions UI to confirm that your OIDC integration is functioning correctly:

```yaml
# .github/workflows/verify_oidc.yml
name: Verify OIDC Authentication

on:
  workflow_dispatch:

jobs:
  verify:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: ${{ vars.GHA_OIDC_ROLE_ARN }}
          aws-region: us-east-1
      - name: Verify AWS identity
        run: aws sts get-caller-identity
```

Use this workflow to manually validate that your GitHub Actions runner can successfully assume the configured AWS IAM role using OIDC.

---

## ⚠️ Trust Policy Workflow

- The file `trust-policy.json` contains sensitive, account-specific information and **is not tracked in version control** (see `.gitignore`).
- To customize your AWS/GitHub OIDC integration, use the provided template: `trust-policy.example.json`.
- During setup, the script will automatically generate a `trust-policy.json` file by replacing placeholders in the example with your actual AWS account ID, GitHub organization, and repository name.
- **Never commit your real `trust-policy.json` to version control.**

**Steps:**
1. Edit `trust-policy.example.json` if you need to customize the trust policy structure.
2. Run `setup_oidc.sh`—it will prompt you for required values and generate `trust-policy.json` automatically.
3. Review `trust-policy.json` before deploying to AWS.

---

## 🛡️ Security & Best Practices

- Follows least privilege for IAM roles.
- GitHub tokens are stored securely in AWS SSM as SecureString.
- OIDC trust policy is automatically updated for your repository.
- All scripts and workflows are linted for quality and security.

---

## 📂 Directory Structure

```
.
├── setup_oidc.sh
├── trust-policy.example.json
├── allowed_repos.txt
├── allowed_repos.txt.example
├── .github/
│   └── workflows/
│       ├── lint.yml
│       └── verify_oidc.yml
├── docs/
│   └── blog_post.md
└── ...
```

- `allowed_repos.txt`: List of additional GitHub repositories (in `org/repo` format) that are permitted to assume the AWS IAM role via OIDC. Each line should contain one repository. If you only want to enable OIDC for the current repository, you do not need to edit this file.
- `allowed_repos.txt.example`: Template for `allowed_repos.txt`.
- `trust-policy.example.json`: Template for generating the trust policy used in AWS IAM. This file is used by `setup_oidc.sh` to create the actual `trust-policy.json` during setup. **Never commit your real `trust-policy.json` to version control.**
- `docs/blog_post.md`: (Optional) Contains blog post or supplementary documentation.

---

## 🤝 Contributing

1. Fork the repo and create your feature branch.
2. Run [setup_oidc.sh](setup_oidc.sh) and ensure all workflows pass.
3. Open a pull request and reference relevant changes.

---

## 📖 Additional Resources
- [GitHub Actions OIDC documentation](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [AWS OIDC provider setup](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)

---

For questions or improvements, please open an issue or pull request.

---

**Note:** This repository was previously named `ghactions-oidc`. All references have been updated to reflect the new name: `gha-aws-oidc-bootstrap`.

---

## GitHub Actions AWS OIDC Multi-Repo Bootstrap

This project automates the setup of AWS IAM roles and GitHub repository variables to enable secure, scalable OIDC authentication for multiple GitHub repositories using GitHub Actions.

## Key Features
- **Multi-Repo OIDC Automation:** Single CloudFormation stack supports multiple repositories.
- **Robust Variable Management:** Ensures the latest IAM role ARN is always set as a GitHub Actions variable (`GHA_OIDC_ROLE_ARN`) in each repo, with automatic cleanup.
- **Cross-Platform Script:** Compatible with macOS and Linux (uses portable `curl`/`sed` logic).
- **Supports Classic and Fine-Grained GitHub Tokens:** Detects and uses the correct authorization scheme.
- **Security Best Practices:** No reserved prefixes, least-privilege trust policy, and debug output never exposes secrets.

## Usage

### Prerequisites
- Python 3.11
- AWS CLI configured
- GitHub Personal Access Token (classic or fine-grained, with repo/actions:write)

### Setup
Run the setup script:
```bash
bash setup_oidc.sh --github-org <ORG> --allowed-repos <repo1,repo2,...> --region <aws-region> --github-token <GITHUB_TOKEN>
```

### What the Script Does
1. Deploys/updates a CloudFormation stack with a trust policy for all listed repos:
   - Uses `repo:<org>/<repo>:*` for each repo in the OIDC trust policy.
2. Deletes the `GHA_OIDC_ROLE_ARN` variable in each repo (if it exists) before setting it.
3. Always tries to create the variable via POST, then PATCHes if it already exists.
4. Prints debug output for each step (token is always masked).

### Example Workflow Usage
```yaml
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v2
  with:
    role-to-assume: ${{ vars.GHA_OIDC_ROLE_ARN }}
    aws-region: us-east-1
    audience: sts.amazonaws.com
```

### Troubleshooting
- If you see `Not Found` or `422` errors, the script will retry with the appropriate method.
- If you change the repo list, re-run the script to update the trust policy and variables.

### Security Notes
- The trust policy uses least-privilege by limiting `sub` to specific repos.
- No variables use the reserved `GITHUB_` prefix.

### References
- [GitHub Actions OIDC Docs](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [AWS OIDC Federation Docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)

---

## Additional Notes

- `allowed_repos.txt` is listed in `.gitignore` to prevent accidental commits of sensitive or environment-specific repo lists.
- Use `allowed_repos.txt.example` as a template for onboarding or sharing project setup instructions.
- The setup script and stack now fully support robust, multi-repo OIDC integration with dynamic trust policy generation.
