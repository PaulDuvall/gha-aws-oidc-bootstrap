# Architecture Diagram Prompt: GHA AWS OIDC Bootstrap

## Context
This project automates the setup of AWS IAM roles and OIDC trust for GitHub Actions, using Python 3.11, Bash, and AWS CloudFormation. It enables secure, short-lived AWS credentials for GitHub workflows across multiple repositories, with all permissions and trust policies managed as code.

## Required Diagram
Generate a diagram that clearly shows the following components and their relationships:

- **GitHub Actions Workflow** (triggered in any allowed repository)
- **GitHub OIDC Token Service** (`token.actions.githubusercontent.com`)
- **AWS IAM OIDC Identity Provider** (created/discovered by automation)
- **AWS IAM Role** (created by CloudFormation, trust policy allows OIDC from GitHub)
- **IAM Policies** (inlined from `policies/` directory)
- **CloudFormation Stack** (manages IAM resources)
- **Bash/Python Automation** (`run.sh`, `src/cfn_deploy.py`)

### Data Flows
- Show the OIDC authentication flow from GitHub Actions to AWS.
- Show how the setup scripts automate provider/role/policy creation and updates.
- Indicate where repo variables (e.g., `GHA_OIDC_ROLE_ARN`) are set in GitHub.

## Diagram Style
- Use AWS and GitHub icons where possible.
- Prefer a layered, left-to-right or top-down flow.
- Label all components and flows clearly.

---

*Generated: 2025-04-23. Update this prompt as the architecture evolves.*
