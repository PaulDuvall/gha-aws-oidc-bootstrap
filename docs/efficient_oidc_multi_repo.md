# Efficient OIDC Integration for Multiple GitHub Repositories

## Overview

When integrating GitHub Actions with AWS via OIDC, a common pattern is to create a dedicated IAM Role (and CloudFormation stack) for each GitHub repository. While this approach works well for a small number of repositories, it can become cumbersome and inefficient as the number of repositories grows.

This document describes a more efficient alternative: **using a single CloudFormation stack and IAM Role with a multi-repo trust policy**. This allows multiple GitHub repositories to assume the same AWS IAM Role, simplifying management and scaling OIDC integration across many repositories.

---

## Current Approach: One Stack Per Repo
- Each GitHub repository gets its own IAM Role and CloudFormation stack.
- The trust policy for each role is tailored to a single repo (or a small list from `allowed_repos.txt`).
- Adding a new repo requires creating a new stack or updating an existing one.

### Limitations
- Tedious to manage for many repos
- Harder to audit and maintain
- Requires multiple stack deployments

---

## Recommended Approach: Single Stack, Multi-Repo Trust Policy

### How It Works
- Deploy **one CloudFormation stack** that creates a single IAM Role.
- The role's trust policy allows multiple GitHub repositories by including their `sub` patterns in the `StringLike` condition.
- Maintain a central list of allowed repositories (e.g., in `allowed_repos.txt`).
- When a new repo needs access, **update the trust policy** (not the entire stack) to add the new repo.

### Example Trust Policy
```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::<AWS_ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    },
    "StringLike": {
      "token.actions.githubusercontent.com:sub": [
        "repo:YourOrg/repo-one:*",
        "repo:YourOrg/repo-two:*"
      ]
    }
  }
}
```

### Update Process
- To add or remove a repository, update the `sub` list in the trust policy.
- This can be done via the AWS Console, AWS CLI, or an automation script.
- No need to redeploy the entire CloudFormation stack.

### Pros and Cons
**Pros:**
- Centralized management (one role, one stack)
- Easier to audit and update
- Faster onboarding for new repos

**Cons:**
- All allowed repos share the same permissions (consider least privilege)
- Broader blast radius if the role is misused

---

## Usage Instructions: Single-Stack, Multi-Repo OIDC Setup

### 1. Prepare Your Repository List
Create a comma-separated list of repositories (without spaces), for example:

```
repo-one,repo-two,repo-three
```

### 2. Deploy the CloudFormation Stack
Deploy the stack using the AWS CLI:

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

### 3. Updating Allowed Repositories
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

## Other Alternatives

### Multiple Roles in a Single Stack
- Use one CloudFormation stack to create multiple IAM Roles (one per repo), each with its own trust policy.
- More complex template, but allows granular permissions per repo.

### Org-Wide Role
- Trust policy allows all repos in a GitHub org (e.g., `repo:YourOrg/*`).
- Easiest to manage, but least granular in terms of permissions.

---

## References
- [AWS Docs: OIDC Multi-Repo Pattern](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html#oidc-create-role)
- [GitHub Docs: OIDC with Multiple Repos](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)

---

## Conclusion
For organizations managing OIDC integration across many GitHub repositories, using a single IAM Role with a multi-repo trust policy is a scalable and efficient solution. It reduces operational overhead, simplifies audits, and accelerates onboarding—while still allowing for secure, short-lived AWS credentials in GitHub Actions workflows.
