# Project Tasks

| Task ID   | Description                                   | Status         | Related User Stories | Implementation Links                    | Test Links                             | Date Created | Last Updated | Notes/Blockers/Cross-Repo |
|-----------|-----------------------------------------------|----------------|---------------------|-----------------------------------------|----------------------------------------|--------------|--------------|--------------------------|
| TASK-001  | Example: Migrate OIDC setup to Python CLI     | 🟡 In Progress | [US-101](docs/user_stories.md#us-101) | [src/setup_oidc.py](src/setup_oidc.py)     | [tests/test_setup_oidc.py](tests/test_setup_oidc.py) | 2025-04-23   | 2025-04-23   | Blocked on AWS permissions |
| TASK-002  | Example: Add automated test runner script     | 🟢 Open        | [US-102](docs/user_stories.md#us-102) | [tests/run_tests.sh](tests/run_tests.sh)     | [tests/test_run_tests.sh](tests/test_run_tests.sh)   | 2025-04-23   | 2025-04-23   |                          |
| TASK-003  | Example: Update docs for new process          | ✅ Complete    | [US-103](docs/user_stories.md#us-103) | [README.md](README.md), [docs/process_exceptions.md](docs/process_exceptions.md) | [tests/test_docs.py](tests/test_docs.py)     | 2025-04-23   | 2025-04-23   |                          |
| TASK-004  | Example: Cross-repo integration with XYZ      | 🔴 Blocked     | [US-104](docs/user_stories.md#us-104) | [src/integration.py](src/integration.py)   | [tests/test_integration.py](tests/test_integration.py) | 2025-04-23   | 2025-04-23   | Blocked: Waiting for repo access; See [XYZ repo](https://github.com/org/xyz) |

<!--
Status Icons:
🟢 Open
🟡 In Progress
🔴 Blocked
✅ Complete
-->

## Task Entry Guidelines

- **Task ID:** Unique identifier (e.g., TASK-001)
- **Description:** Clear, concise summary of the task
- **Status:** Use icon and label (see above)
- **Related User Stories:** Link to user story IDs in `docs/user_stories.md`
- **Implementation Links:** Link to all relevant code files/PRs
- **Test Links:** Link to all related test files
- **Date Created/Last Updated:** Use ISO 8601 (YYYY-MM-DD)
- **Notes/Blockers/Cross-Repo:** Document blockers, cross-repo links, or special handling

## Milestone: OIDC IAM Role Stack Automation (2025-04-23)

- Fully automated deployment of an AWS IAM Role for GitHub Actions OIDC integration.
- CloudFormation template now:
  - Accepts OIDC provider ARN as a parameter for portability and compliance.
  - Inlines all policy documents from the policies/ directory.
  - Attaches all policies to the IAM role.
- Deployment workflow:
  - Requires and validates OIDC provider ARN in run.sh and cfn_deploy.py.
  - Passes all automated tests (policy attachment, inlining, CLI args, venv, etc.).
  - Stack deploys successfully with no manual steps required.
- Next: Automate GitHub Actions repo variable creation, expand integration tests, update documentation.

---

_Last updated: 2025-04-23_
