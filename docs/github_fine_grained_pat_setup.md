# Creating a Fine-Grained GitHub Personal Access Token (PAT) for OIDC Setup

This guide explains how to create a fine-grained GitHub Personal Access Token (PAT) with the correct permissions for use with the OIDC setup and repository variables API.

---

## 1. Start the Token Creation Process
- Go to: [GitHub Personal Access Tokens (Fine-grained)](https://github.com/settings/tokens?type=beta)
- Click **"Generate new token"** → **"Generate new fine-grained token"**

## 2. Token Name, Expiration, and Repository Access
- **Token name:** Choose a descriptive name (e.g., `OIDC Setup Script Token`)
- **Expiration:** Set an appropriate expiration (shorter is more secure)
- **Resource owner:** Select your user account (or organization if needed)
- **Repositories:**  
  - **Repository access:**  
    - Choose **"Only select repositories"**
    - Select all repositories you want this script to manage (e.g., `gha-aws-oidc-bootstrap`, `llm-guardian`, etc.)

## 3. Set Repository Permissions
For each selected repository, scroll down to **Repository permissions** and set the following:

### Required permissions:
- **Actions:**  
  - Select **Read and write**
- **Variables:**  
  - Select **Read and write**
- **Metadata:**  
  - Select **Read-only** (required for API access)

### Recommended (for future-proofing):
- **Administration:**  
  - Select **Read and write** (if you want to manage webhooks, settings, etc.)
- **Contents:**  
  - Read-only is sufficient unless you want to automate file changes

> **You do NOT need to enable all permissions!**  
> Only those listed above are required for setting repository variables via the API.

## 4. Organization SSO (if applicable)
- If your org enforces SSO, you’ll see a yellow banner after creating the token. Click **"Authorize"** to authorize the token for SSO access.

## 5. Generate and Save the Token
- Click **"Generate token"**
- **Copy the token** (you won’t be able to see it again)
- Use this token in your script as the value for `GITHUB_TOKEN`

---

## Summary Table

| Permission Group | Permission         | Level        | Why Needed?                        |
|------------------|--------------------|--------------|-------------------------------------|
| Actions          | Actions            | Read & Write | To create/update Actions variables  |
| Variables        | Variables          | Read & Write | To create/update repo variables     |
| Metadata         | Metadata           | Read-only    | Required for API access             |

---

**Reference:** [GitHub Docs: Creating a fine-grained personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
