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
bash setup_oidc.sh
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
   - Sets the `AWS_ROLE_TO_ASSUME` variable in your GitHub repository, referencing the IAM Role ARN.
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
- The script uses your token to set up repository variables (like `AWS_ROLE_TO_ASSUME`) and configure GitHub Actions securely.
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
      role-to-assume: ${{ vars.AWS_ROLE_TO_ASSUME }}
      aws-region: us-east-1
      audience: sts.amazonaws.com
```

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
          role-to-assume: ${{ vars.AWS_ROLE_TO_ASSUME }}
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
- **Never commit your real `trust-policy.json` to a public repository.**

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

## 📝 User Stories & Traceability

User stories and a traceability matrix are maintained in `docs/user_stories.md` and `docs/traceability_matrix.md`.

---

## 🤝 Contributing

1. Fork the repo and create your feature branch.
2. Run [setup_oidc.sh](setup_oidc.sh) and ensure all workflows pass.
3. Open a pull request and reference relevant user stories.

---

## 📂 Directory Structure

```
.
├── setup_oidc.sh
├── trust-policy.json
├── .github/
│   └── workflows/
│       ├── lint.yml
│       └── verify_oidc.yml
├── docs/
│   ├── user_stories.md
│   └── traceability_matrix.md
└── ...
```

---

## 📖 Additional Resources
- [GitHub Actions OIDC documentation](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [AWS OIDC provider setup](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)

---

For questions or improvements, please open an issue or pull request.

---

**Note:** This repository was previously named `ghactions-oidc`. All references have been updated to reflect the new name: `gha-aws-oidc-bootstrap`.
