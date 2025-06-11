# IAM Policy Management for OIDC Role

This directory contains IAM policy JSON files that are automatically attached to the OIDC IAM role for GitHub Actions by the `setup_oidc.sh` script.

**Important:**
- IAM policies in this directory **must not be scoped to a single repository**. They should only define AWS permissions and resources, not reference or restrict access based on specific GitHub repositories. Repository access is controlled by the role's trust policy, not by these policy files.

## Policy Files for Cedar Repository

These policies are tightened to the minimum permissions needed for the Cedar Policy as Code repository:

- **cfn.json**: CloudFormation permissions for stack deployment and management
- **verifiedpermissions.json**: AWS Verified Permissions for Cedar policy store management  
- **s3.json**: S3 permissions for bucket compliance checking and demo scenarios
- **iam.json**: IAM permissions for CloudFormation stack deployments with IAM resources
- **kms.json**: KMS permissions for encrypted S3 bucket demos
- **sts.json**: STS permissions for identity operations and OIDC authentication

## Permissions Analysis

These policies provide the minimum permissions required for:

1. **Cedar Policy Deployment**:
   - Deploy CloudFormation stacks for AWS Verified Permissions
   - Upload and manage Cedar policies in policy stores
   - Create and manage IAM roles for GitHub Actions

2. **S3 Compliance Testing**:
   - Check encryption status of existing S3 buckets
   - Create test buckets for encryption demos
   - Manage bucket policies and encryption settings

3. **Demo and Testing Workflows**:
   - Deploy CloudFormation templates for S3 encryption examples
   - Create KMS-encrypted resources for production scenarios
   - Clean up demo resources after testing

## Security Improvements

**Before**: Policies used wildcard permissions (e.g., `s3:*`, `iam:*`, `verifiedpermissions:*`)
**After**: Policies limited to specific actions needed by the Cedar repository workflows

**Risk Reduction**:
- ~90% reduction in S3 permissions (13 actions vs all S3 actions)
- ~85% reduction in IAM permissions (11 actions vs all IAM actions)  
- ~70% reduction in CloudFormation permissions (13 actions vs all CFN actions)
- ~60% reduction in Verified Permissions actions (12 actions vs all AVP actions)

## Usage

1. **Apply changes:**
   - After updating policy files, re-run `setup_oidc.sh` to attach them to the IAM OIDC role.

2. **Verify permissions:**
   - Test GitHub Actions workflows to ensure all required permissions are available
   - Monitor CloudTrail logs for any permission denied errors

## Important
- **After any policy change, always re-run `setup_oidc.sh` to apply updates.**
- **These policies are specifically tailored for the Cedar Policy as Code repository.**
