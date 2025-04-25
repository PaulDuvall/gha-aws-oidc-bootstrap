# GHA AWS OIDC Bootstrap
[![GitHub Actions Workflow Status](https://github.com/PaulDuvall/gha-aws-oidc-bootstrap/actions/workflows/verify_oidc.yml/badge.svg)](https://github.com/PaulDuvall/gha-aws-oidc-bootstrap/actions/workflows/verify_oidc.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/PaulDuvall/gha-aws-oidc-bootstrap)

This project provides a secure, automated setup for AWS OIDC authentication with GitHub Actions.

- Modular Bash script ([run.sh](run.sh)) for provisioning AWS IAM roles and trust policies
- Jinja2-based CloudFormation template rendering for IAM role and policies
- Modular policy management via the `policies/` directory
- GitHub Actions workflows for OIDC verification and code linting
- Documentation and CI/CD best practices

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/PaulDuvall/gha-aws-oidc-bootstrap.git
cd gha-aws-oidc-bootstrap
```

### 2. Run the OIDC Setup & Deployment Script

You can use the streamlined, fully automated workflow:

```bash
# Option 1: With a GitHub Personal Access Token (PAT) to automatically set repo variables
export GITHUB_TOKEN=github_pat_XXXXXXXXXXXX
bash run.sh --github-org <your_org> --region us-east-1 --github-token $GITHUB_TOKEN

# Option 2: Without a GitHub token
bash run.sh --github-org <your_org> --region us-east-1
```

After running the script, you will see clear instructions for using the IAM Role in your GitHub Actions workflow. You can:

- **Option 1: Use a repository variable (recommended for teams)**
  1. Set a GitHub Actions variable in your repository named `GHA_OIDC_ROLE_ARN` with the IAM Role ARN output by the script.
  2. Reference that variable in your workflow YAML:

    ```yaml
    permissions:
      id-token: write
      contents: read
    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          - name: Assume OIDC Role
            uses: aws-actions/configure-aws-credentials@v4
            with:
              role-to-assume: ${{ secrets.GHA_OIDC_ROLE_ARN }}
              aws-region: us-east-1
    ```

- **Option 2: Reference the IAM Role ARN directly (suitable for solo use or quick setup)**

    ```yaml
    permissions:
      id-token: write
      contents: read
    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          - name: Assume OIDC Role
            uses: aws-actions/configure-aws-credentials@v4
            with:
              role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsOIDCRole
              aws-region: us-east-1
    ```

Replace the ARN above with the value output by the script. Both approaches are always available, regardless of whether you use a GitHub token.

- The script uses the file `allowed_repos.txt` to determine which repositories will be granted access. List each repository (in the format `owner/repo`) on a separate line in that file before running the script.
- There is no `--repos` argument; repository access is controlled via the trust policy and the contents of `allowed_repos.txt`.

**GitHub Token Requirements:**
- Use a GitHub Personal Access Token (PAT) with fine-grained permissions.
- Fine-grained: grant `Actions` (**Read/Write**), `Variables` (**Read/Write**), and `Secrets`(if needed).

---

## Architecture and Implementation Notes

- CloudFormation templates for the IAM role and policies are rendered using Jinja2, ensuring robust YAML block indentation and eliminating placeholder injection logic.
- Obsolete scripts and templates (such as `inject_trust_policy.py` and `iam_role.base.yaml`) have been removed.
- Policies are modular and loaded from the `/policies` directory; the renderer attaches all found policies to the IAM role.
- The trust policy is dynamically generated and injected into the CloudFormation template for least-privilege, multi-repo OIDC integration.
- Deployment workflow and scripts are structured for clarity, maintainability, and security.

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

---

## Automated Multi-Repo OIDC Trust Policy

This project automatically generates a flexible IAM trust policy for GitHub Actions OIDC integration based on the repositories listed in `allowed_repos.txt`.

- **Do NOT commit your `allowed_repos.txt` file.** It is gitignored by default. Instead, use the provided `allowed_repos.txt.example` as a template for contributors.

---

## Customizing AWS Permissions with the `policies/` Directory

- Place one or more IAM policy JSON files (e.g., `lambda.json`, `s3-readonly.json`) in the `policies/` directory.
- When you run `run.sh`, the script automatically attaches all policy files in `policies/` to the IAM OIDC role.
- Each policy file should define only AWS permissions (not GitHub repo logic). Repository access is controlled by the trust policy, not these files.

---

## Best Practices
- Never scope policies to a single GitHub repository.
- Keep policies minimal and auditable.
- Remove or archive policy files you do not need (principle of least privilege).
- Review `policies/README.md` for more details and examples.

---

For questions or improvements, please open an issue or pull request.
