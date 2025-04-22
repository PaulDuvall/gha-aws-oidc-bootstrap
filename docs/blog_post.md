# Securing CI/CD Pipelines with GitHub OIDC and AWS IAM

Modern teams that embrace DevOps face a persistent challenge: how do you empower developers to deliver quickly and securely to AWS, without ever exposing static credentials or compromising security? The answer lies in automation, least privilege, and the right blend of open source tooling—principles that have guided the creation of the `gha-aws-oidc-bootstrap` project.

This repository is more than just a collection of scripts and templates. It’s a living example of how to bootstrap secure, cloud-native CI/CD pipelines using GitHub Actions, AWS IAM, and OpenID Connect (OIDC)—all while enforcing security at every step.

You can find the project here: [https://github.com/PaulDuvall/gha-aws-oidc-bootstrap/](https://github.com/PaulDuvall/gha-aws-oidc-bootstrap/)

## From Static Secrets to Ephemeral Trust

There are varying levels of risk when it comes to AWS credentials in CI/CD:

- **Absolute worst:** Hardcoding `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` directly in your repository or codebase. This exposes your credentials to anyone with repo access and is a critical security vulnerability—you can almost guarantee your AWS account will become compromised, most likely through automated scripts in minutes or even seconds. This can also very easily happen by accident when builders store credentials in files that they mistakenly commit to the repository.
- **Still risky:** Storing `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` as [GitHub Actions Secrets](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions). While better than hardcoding, this is still risky—if the repo is compromised, those secrets can be stolen, are not automatically rotated, and may be over‑permissioned or not regularly audited.

Gone are the days of either hardcoding or storing AWS credentials in GitHub Actions Secrets. With OIDC, every workflow run gets its own short‑lived, tightly‑scoped credentials—no more static secrets to rotate, audit, or worry about leaking. This shift not only aligns with AWS and GitHub best practices, but also enables true zero trust and least privilege in your automation.

## OIDC Provider: Single Source of Trust

When setting up OIDC integration between GitHub Actions and AWS, your AWS account needs an OIDC identity provider for GitHub (`token.actions.githubusercontent.com`). AWS allows only one such provider per account.

- **If this provider already exists**, the setup process will detect and reuse it for all future OIDC-enabled workflows and roles—ensuring a single, consistent trust anchor for GitHub Actions.
- **If it doesn’t exist yet**, the setup script (or CloudFormation stack) will create it for you. This provider establishes the trust relationship between AWS and GitHub, enabling secure, short‑lived credential issuance to your workflows.

You can view and manage this provider in the AWS Console by navigating to **IAM > Identity providers**, or by running:
```bash
aws iam list-open-id-connect-providers
```
This design means you never have to manage multiple OIDC providers for GitHub in the same account—simplifying configuration and reducing risk.

## What the Automation Does for You (and How to Do It Manually)

> **Note:**  
> You do **not** need to perform the following manual steps if you use the automation described later in this guide. These steps are provided for context, so you understand what the automation is doing behind the scenes and what would be required if you set up OIDC authentication manually.

Setting up secure OIDC authentication between GitHub Actions and AWS involves several detailed steps if done manually:

1. **Create the OIDC Identity Provider in AWS IAM**
   - Go to IAM > Identity providers > Add provider
   - Choose OpenID Connect, enter `token.actions.githubusercontent.com` as the provider URL, and add the audience `sts.amazonaws.com`
2. **Create and Maintain the IAM Role and Trust Policy**
   - Create a new IAM Role
   - Write and maintain a trust policy that allows GitHub Actions from your target repo to assume the role via OIDC (this requires updating the `sub` condition if you add or change repos)
   - Attach a permissions policy granting only the required AWS actions (e.g., S3, CloudFormation)
   - To allow multiple repos, add each repo pattern to the `sub` condition.
   - With the automation, the current repo is always included by default, and you only need to add other repos to `allowed_repos.txt` if you want to grant them access.

---

## Step-by-Step: Automated Secure Setup and Usage

> **Note:**  
> By default, only the current repository will be granted access. To allow additional GitHub repositories to assume the same IAM role, you can either pass them as a comma-separated list to the `--allowed-repos` argument when running the script, **or** add their names (in org/repo format, one per line) to the `allowed_repos.txt` file before running the automation. The script will generate the correct trust policy for all repos listed by either method. You do not need to use either option for single-repo setups.
> **Caution:** Allowing multiple repositories to use the same IAM role means that any workflow in those repos can access the AWS resources permitted by that role, for the duration of the workflow run. While OIDC credentials are short-lived and tightly scoped, consider using a dedicated IAM role per repository for strict least-privilege and easier auditing.

1. **Clone the Repository**
   ```bash
   git clone https://github.com/PaulDuvall/gha-aws-oidc-bootstrap.git
   cd gha-aws-oidc-bootstrap
   ```
2. **Configure AWS CLI Credentials**
   ```bash
   aws configure
   # Ensure your credentials have IAM and CloudFormation permissions
   ```
3. **Run the OIDC Setup Script**
   ```bash
   bash setup_oidc.sh
   # Follow interactive prompts for GitHub token and AWS region
   ```
4. **Commit and Push Changes**
   ```bash
   git add .
   git commit -m "chore: setup OIDC integration"
   git push
   ```
5. **Integrate into Your Workflows**
   - Reference the generated IAM role in your GitHub Actions workflow:
     ```yaml
     permissions:
       id-token: write
       contents: read
     steps:
       - name: Configure AWS credentials
         uses: aws-actions/configure-aws-credentials@v2
         with:
           role-to-assume: ${{ vars.AWS_ROLE_TO_ASSUME }}
           aws-region: us-east-1
           audience: sts.amazonaws.com
     ```

---

### Inspect the Trust or Permissions Policy

To inspect the trust or permissions policy that the generated IAM role uses, run (e.g, my `<ROLE_NAME>` is `github-oidc-role-PaulDuvall-gha-aws-oidc-bootstrap`):
```bash
aws configure # Ensure your credentials have IAM and CloudFormation permissions
aws iam get-role --role-name <ROLE_NAME> --query 'Role.AssumeRolePolicyDocument'
aws iam list-attached-role-policies --role-name <ROLE_NAME>
aws iam list-role-policies --role-name <ROLE_NAME>
```

### Secure by Design: OIDC and IAM Roles

By configuring GitHub’s OIDC integration with AWS IAM roles, you:
- **Eliminate static secrets:** No more long‑lived AWS keys in GitHub.
- **Enforce least privilege:** IAM roles can be tightly scoped to only what CI/CD needs.
- **Enable short‑lived credentials:** AWS STS issues ephemeral tokens—automatically rotated per workflow run.
- **Align with Zero Trust:** Authentication is based on signed OIDC identity tokens, not passwords or keys.

> **Security Reminder:**
>
> Never hardcode AWS credentials or store them as long‑lived secrets in your repositories. Hardcoded or static credentials are a leading cause of cloud breaches—they are easily leaked, rarely rotated, and often over‑permissioned. OIDC with IAM roles ensures every workflow run gets short‑lived, tightly‑scoped credentials, aligning with AWS and GitHub security best practices.

## Automating Secure OIDC Integration for Multiple GitHub Repositories with AWS

OpenID Connect (OIDC) is the modern, secure way to connect GitHub Actions workflows to AWS without long-lived credentials. But what if you want to enable OIDC authentication across several repositories in your organization, and you want the setup to be repeatable, robust, and easy for anyone to follow?

In this post, I’ll show you how to automate OIDC authentication for multiple GitHub repositories using a single AWS CloudFormation stack and a cross-platform Bash script. This approach minimizes manual steps, enforces best practices, and ensures every repository always has the correct configuration.

## Why Automate OIDC Setup Across Multiple Repos?

Manually configuring IAM roles and GitHub repository variables for each repo is tedious and error-prone. By automating the process, you:
- Reduce the risk of misconfiguration
- Make onboarding new repos trivial
- Ensure all repos use the latest security settings
- Save time as your organization and CI/CD footprint grows

## How the Automation Works

### 1. CloudFormation Stack
A single stack creates an IAM role with a trust policy that allows OIDC authentication from all the GitHub repositories you specify. The trust policy uses the correct `repo:<org>/<repo>:*` subject format for each repository.

### 2. Bash Setup Script
The script:
- Deletes the `GHA_OIDC_ROLE_ARN` variable in each repo (if it exists) before setting it
- Uses the GitHub API to create the variable via POST, and PATCHes if it already exists
- Works on macOS and Linux (portable `curl`/`sed` logic)
- Handles both classic and fine-grained GitHub tokens
- Prints debug output for each step (never exposing secrets)

## Step-by-Step Example

### Deploy and Configure OIDC for Multiple Repos
```bash
bash setup_oidc.sh --github-org PaulDuvall --allowed-repos gha-aws-oidc-bootstrap,llm-guardian,owasp_llm_top10 --region us-east-1 --github-token <GITHUB_TOKEN>
```

### Use the Role in a GitHub Actions Workflow
```yaml
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v2
  with:
    role-to-assume: ${{ vars.GHA_OIDC_ROLE_ARN }}
    aws-region: us-east-1
    audience: sts.amazonaws.com
```

## Lessons Learned
- Avoid reserved prefixes for GitHub variables (never use `GITHUB_`)
- Use POST then PATCH for robust variable management
- Make scripts cross-platform for reliability
- Keep trust policies as tight as possible for security

## References
- [GitHub Actions OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [AWS OIDC Trust Policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)

## IAM Role Trust and Permissions Configuration

### Trust Policy Example
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:<org>/<repo>:*"
        }
      }
    }
  ]
}
```

### Permissions Policy Example

> **Note:** This is an example policy for S3 access. The automation does not hardcode these permissions—you should tailor the policy to your workflow’s needs (e.g., S3, CloudFormation, Lambda). Replace `my-ci-artifacts-bucket` with your actual bucket name or target resource.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject"],
      "Resource": "arn:aws:s3:::my-ci-artifacts-bucket/*"
    }
  ]
}
```

## Using the Tool: GitHub Token Requirements

To use this automation, you’ll need to provide a GitHub Personal Access Token (PAT) when prompted by the setup script. This token is required to set repository variables and manage GitHub Actions configuration programmatically.

**How to create your GitHub token:**
1. Go to [GitHub > Settings > Developer settings > Personal access tokens](https://github.com/settings/tokens)
2. Click "Generate new token" (classic) or "Fine‑grained token"
3. Give your token a descriptive name and set an expiration date
4. **Required scopes:**
   - For classic tokens: `repo` (for private repos), `workflow`, and `admin:repo_hook`
   - For fine‑grained tokens: access to the target repository with permissions for "Actions" (Read and Write), "Variables" (Read and Write), and "Secrets" (if needed)
5. Copy the token (you won’t be able to see it again)

**How it works:**
- When you run the setup script, it will prompt you to paste your GitHub token. This enables the script to set the necessary repository variables (such as `GHA_OIDC_ROLE_ARN`) and configure your GitHub Actions workflows securely and automatically.
- If secrets or tokens need to be persisted in AWS, the automation uses AWS SSM Parameter Store with SecureString for encryption and secure access.

**Note:**  
- The stack is designed to work with any target GitHub repository—not just the one containing the automation. Be sure to create your token with access to the correct repository.

> By automating AWS credential management with GitHub OIDC and IAM, you eliminate static secrets, enforce least privilege, and empower your teams to deliver software rapidly and securely.
