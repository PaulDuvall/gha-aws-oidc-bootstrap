# Traceability Matrix: GHA AWS OIDC Bootstrap

**Test coverage:** All test files referenced below are located in the [`tests/`](../tests/) directory unless otherwise specified.

| User Story ID | Description | Implementation File(s) | Test File(s) |
|--------------|-------------|------------------------|--------------|
| US-100 | OIDC auth for all org repos | run.sh, src/cfn_deploy.py, cloudformation/iam_role.yaml | tests/test_cfn_deploy.py, tests/test_iam_role_template.py |
| US-110 | IAM policies managed via policies/ dir | run.sh, src/cfn_deploy.py, cloudformation/iam_role.yaml, policies/*.json | tests/test_iam_role_template.py |
| US-120 | Least privilege IAM policies | policies/*.json, cloudformation/iam_role.yaml | tests/test_iam_role_template.py |
| US-130 | Fine-grained GitHub PAT support | run.sh, src/cfn_deploy.py | tests/test_cfn_deploy.py |
| US-140 | Clear documentation/examples | README.md, docs/user_stories.md | N/A |
| US-150 | Update allowed repos without redeploy | allowed_repos.txt, src/cfn_deploy.py | N/A |
| US-160 | Secrets excluded from VCS | .gitignore, allowed_repos.txt.example | N/A |
| US-170 | Cross-platform support | run.sh, setup_oidc.sh | tests/test_venv_setup.py |
| US-180 | Auditability and traceability | README.md, docs/traceability_matrix.md | tests/test_iam_role_template.py |
| US-190 | Windsurf global rules compliance | .windsurfrules.md | N/A |

*Generated: 2025-04-23. Update as new user stories or implementation files are added.*
