# User Stories for GHA AWS OIDC Bootstrap

This document contains user stories for the secure, automated setup of AWS OIDC authentication for GitHub Actions, following Windsurf documentation standards and global rules. Each story uses the US-XXX format and includes acceptance criteria and traceability notes.

---

## US-100: As an organization admin, I want to configure OIDC authentication for all GitHub repositories in my organization, so that I can manage AWS access securely and centrally.

**Acceptance Criteria:**
- The setup supports specifying a GitHub organization and enables OIDC for all or selected repositories.
- OIDC trust policy is generated for all repos in the org (not just one repo).
- Documentation describes multi-repo setup.
- The process requires no manual IAM console steps.

---

## US-110: As a DevOps engineer, I want to manage AWS IAM permissions for the OIDC role using policy files, so that I can easily audit and update permissions without editing CloudFormation templates.

**Acceptance Criteria:**
- There is a `policies/` directory for JSON IAM policy files.
- All policies in this directory are attached to the OIDC role by the setup script.
- Documentation describes how to add, edit, and remove policy files.
- Changes to policies are applied by re-running the setup script.

---

## US-120: As a security engineer, I want all IAM policies to follow least privilege, so that workflows only have the permissions they need.

**Acceptance Criteria:**
- Documentation emphasizes minimal, auditable policies.
- Example policies are provided for Lambda, S3, and CloudWatch Logs.
- Guidance is given to remove unused policy files.
- There are no policies scoped to a single repository.

---

## US-130: As an engineer, I want to use a fine-grained GitHub Personal Access Token (PAT) with the setup script, so that I can securely automate repository variable management.

**Acceptance Criteria:**
- Documentation describes how to create a fine-grained PAT with only required permissions.
- The setup script accepts the PAT via argument or environment variable.
- The script uses the token to set the `GHA_OIDC_ROLE_ARN` variable in all target repos.

---

## US-140: As an engineer, I want the setup script to optionally set the GHA_OIDC_ROLE_ARN variable in all allowed GitHub repos, so that workflows can easily assume the correct AWS role if desired.

**Acceptance Criteria:**
- The script can be configured to set GHA_OIDC_ROLE_ARN in every repo listed in allowed_repos.txt after deployment, but this is not required by default.
- The variable value matches the deployed IAM Role ARN when used.
- The script uses the provided GitHub PAT and documents required scopes.
- Errors (e.g., missing repo, insufficient permissions) are clearly reported.
- Documentation describes this automation, how to enable or skip it, and how to verify it.

---

## US-150: As an admin, I want to be able to update the list of allowed repositories without redeploying the entire stack, so that I can grant or revoke access efficiently.

**Acceptance Criteria:**
- The allowed repos can be updated via `allowed_repos.txt` or script arguments.
- The trust policy is regenerated and updated automatically.
- Documentation describes the update process.

---

## US-160: As a maintainer, I want all sensitive files (e.g., tokens, secrets, real trust-policy.json) to be excluded from version control, so that no secrets are accidentally leaked.

**Acceptance Criteria:**
- `.gitignore` excludes sensitive files.
- Example/template files are provided for onboarding.
- Documentation warns never to commit real secrets.

---

## US-170: As a developer, I want the setup script and stack to work on both macOS and Linux, so that the solution is portable and easy to adopt.

**Acceptance Criteria:**
- The script is POSIX-compliant or has macOS/Linux compatibility notes.
- No OS-specific commands without alternatives.
- Documentation mentions cross-platform support.

---

## US-180: As a security engineer, I want to ensure all AWS resources and permissions are auditable and can be traced to user stories and requirements.

**Acceptance Criteria:**
- Each policy file, script, and major resource references relevant user stories in comments or documentation.
- There is a traceability matrix linking user stories to implementation and test files.

---

## US-190: As a project maintainer, I want all code and documentation to follow Windsurf global rules for version control, testing, and documentation standards.

**Acceptance Criteria:**
- All user stories use the US-XXX format and have acceptance criteria.
- Code comments reference user stories where relevant.
- Semantic versioning and commit message standards are followed.
- Tests are written before implementation (TDD), and coverage is tracked. All tests must be run using `bash run.sh --test`.
- Documentation is updated as features are added or changed.

---

## Traceability
- See `traceability_matrix.md` for mapping of user stories to implementation and test files.
