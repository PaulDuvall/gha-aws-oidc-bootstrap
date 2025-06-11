# IAM Policy Configuration Guide

This directory contains example IAM policy files that grant AWS permissions to your GitHub Actions OIDC role. 

## Important Notes

1. **These are EXAMPLES only** - The files ending with `-example.json` are templates you should customize for your specific use case.
2. **Rename before using** - Copy any example file and remove the `-example` suffix (e.g., `s3-example.json` → `s3.json`).
3. **Customize the resources** - Replace placeholder values like `myproject-*` with your actual resource names.
4. **Follow least privilege** - Only include the permissions your GitHub Actions workflows actually need.

## How It Works

When you run `bash run.sh`, the script:
1. Scans this `policies/` directory for all `.json` files (excluding `-example.json` files)
2. Attaches each policy to the IAM role created for GitHub Actions OIDC
3. The policies define what AWS actions your workflows can perform

## Example Files Included

### 1. `s3-example.json`
Basic S3 permissions for managing buckets and objects. Customize by:
- Changing `myproject-*` to your bucket naming pattern
- Adjusting actions based on your needs (read-only, write, admin)

### 2. `cloudformation-example.json`
CloudFormation stack management permissions. Customize by:
- Changing `myproject-*` to your stack naming pattern
- Adding/removing actions based on your deployment needs

### 3. `minimal-example.json`
A minimal policy for read-only S3 access. Shows the bare minimum structure.

## Creating Your Own Policies

1. Copy an example file:
   ```bash
   cp s3-example.json s3.json
   ```

2. Edit the new file to match your needs:
   - Update resource ARNs to match your AWS resources
   - Adjust actions to only what's needed
   - Add conditions for extra security

3. Run the deployment:
   ```bash
   bash run.sh --github-org yourorg --github-repo yourrepo
   ```

## Best Practices

1. **Use specific resource ARNs** instead of wildcards when possible
2. **Limit actions** to only what your workflows need
3. **Use conditions** to further restrict access (by IP, time, tags, etc.)
4. **Test thoroughly** with minimal permissions first, then expand as needed
5. **Review regularly** and remove unused permissions

## Common Patterns

### Deploy to specific S3 bucket:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:PutObject", "s3:PutObjectAcl"],
    "Resource": "arn:aws:s3:::my-website-bucket/*"
  }]
}
```

### Manage EC2 instances with specific tags:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["ec2:StartInstances", "ec2:StopInstances"],
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "ec2:ResourceTag/Environment": "staging"
      }
    }
  }]
}
```

### Read secrets from Parameter Store:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["ssm:GetParameter", "ssm:GetParameters"],
    "Resource": "arn:aws:ssm:*:*:parameter/myapp/*"
  }]
}
```

## Troubleshooting

- If permissions are denied, check CloudTrail logs to see exactly what action/resource was attempted
- Use `--policy-file` flag with run.sh to test a specific policy file
- Remember that changes require re-running the deployment script to take effect