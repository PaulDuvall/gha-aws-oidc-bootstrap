# IAM Policy Management for OIDC Role

This directory contains IAM policy JSON files that are automatically attached to the OIDC IAM role for GitHub Actions by the `setup_oidc.sh` script.

**Important:**
- IAM policies in this directory **must not be scoped to a single repository**. They should only define AWS permissions and resources, not reference or restrict access based on specific GitHub repositories. Repository access is controlled by the role's trust policy, not by these policy files.

## Policy Files

- **lambda.json**: Example policy for granting Lambda function permissions. Replace `<region>`, `<account>`, and `<function-name>` in the `Resource` field with your actual AWS Lambda function details. Only grant the minimum actions your workflow requires (e.g., `lambda:InvokeFunction`).
- **cloudwatch-logs.json**: (Optional) Example policy for granting permissions to create and write to CloudWatch Logs. Only include if your workflows or Lambda functions require log access. Update the `Resource` field as needed.
- **s3-readonly.json**: (Optional) Example policy for granting read-only S3 access to a specified bucket. Replace the bucket name and region in the `Resource` field with your actual S3 bucket details. Only include if your workflow needs S3 read access.

## Usage

1. **Add or edit policies:**
   - To grant new permissions, add actions/resources to an existing policy file or create a new JSON file.
   - Only keep the policy files you need for your workflows.
2. **Apply changes:**
   - After updating or adding policy files, re-run `setup_oidc.sh` to attach them to the IAM OIDC role.
3. **Best practices:**
   - Use a single policy file (like `lambda.json`) for all Lambda permissions unless you need fine-grained separation.
   - Remove or archive unused policy files to minimize the IAM role's permissions (principle of least privilege).

## Example: Granting Additional Lambda Permissions

To allow more Lambda actions (e.g., `lambda:GetFunctionConfiguration`), add them to the `Action` array in `lambda.json`:

```json
{
  "Effect": "Allow",
  "Action": [
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionCode",
    "lambda:GetFunction",
    "lambda:GetFunctionConfiguration"
  ],
  "Resource": "arn:aws:lambda:<region>:<account>:function:<function-name>"
}
```

## Important
- **After any policy change, always re-run `setup_oidc.sh` to apply updates.**
- **Keep your policies minimal and auditable for security and compliance.**
