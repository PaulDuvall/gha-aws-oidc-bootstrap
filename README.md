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
bash run.sh --github-org <your_org> --github-repo <your_repo> --region us-east-1 --github-token $GITHUB_TOKEN

# Option 2: Without a GitHub token
bash run.sh --github-org <your_org> --github-repo <your_repo> --region us-east-1
```

- The `--github-org` and `--github-repo` arguments are required to target a specific repository. This ensures the IAM trust policy and stack name are unique per repo.
- Alternatively, you can use `allowed_repos.txt` to grant access to multiple repos at once. Each line should be in the format `owner/repo`.


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
              role-to-assume: ${{ vars.GHA_OIDC_ROLE_ARN }}
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

- The script uses the file `allowed_repos.txt` to determine which repositories will be granted access. List each repository (in the format `owner/repo`) on a separate line in that file before running the script. If you use `--github-org` and `--github-repo`, only that repo is granted access.
- There is no `--repos` argument; repository access is controlled via the trust policy and the contents of `allowed_repos.txt`.

**Stack Naming Convention:**
- The CloudFormation stack name is automatically generated to ensure uniqueness and compliance with AWS naming rules.
- **Format:** `gha-aws-oidc-<org>-<repo>` (all lowercase, hyphens only, max 64 chars)
- Example: For `PaulDuvall/gha-aws-oidc-bootstrap`, the stack name will be `gha-aws-oidc-paulduvall-gha-aws-oidc-bootstrap`
- This stack name is used for all AWS resources deployed for this integration.
- **Custom Stack Names:** You can override the default naming by providing `--stack-name <name>` when running the script:
  ```bash
  bash run.sh --github-org <org> --github-repo <repo> --stack-name my-custom-stack
  ```

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

The `policies/` directory contains example IAM policy files that you can customize for your specific AWS permissions needs.

### Getting Started with Policies

1. **Browse the example files** in `policies/` directory (files ending with `-example.json`)
2. **Copy an example** that matches your use case and remove the `-example` suffix:
   ```bash
   cp policies/s3-example.json policies/s3.json
   ```
3. **Customize the policy** by updating:
   - Resource ARNs (replace placeholders like `myproject-*` with your actual resource names)
   - Actions (only include what your workflows need)
   - Conditions (add extra security constraints if needed)
4. **Run the deployment** - the script will automatically attach all `.json` files (except `-example.json`) to your IAM role

### Using a Custom Policies Directory

You can specify a custom directory containing your policy files:

```bash
# Use policies from a custom directory
bash run.sh --github-org myorg --github-repo myrepo --policies-dir /path/to/my/policies

# The custom directory should contain .json files (not ending in -example.json)
# that follow the same IAM policy format as the examples
```

If no `--policies-dir` is specified, the script uses the default `policies/` directory in this repository.

### Example Policy Files Provided

- `s3-example.json`: S3 bucket and object management permissions
- `cloudformation-example.json`: CloudFormation stack deployment permissions  
- `minimal-example.json`: Minimal read-only S3 access example

### Important Notes

- The example files are templates - you MUST customize them for your use case
- Only `.json` files (not ending in `-example.json`) will be attached to the IAM role
- Follow the principle of least privilege - only grant permissions that are actually needed
- See `policies/README.md` for detailed configuration instructions and best practices

---

## Best Practices
- Keep policies minimal and auditable.
- Remove or archive policy files you do not need (principle of least privilege).
- Review `policies/README.md` for more details and examples.

---

For questions or improvements, please open an issue or pull request.
