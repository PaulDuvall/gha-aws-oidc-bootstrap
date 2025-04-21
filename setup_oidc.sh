#!/bin/bash

set -euo pipefail

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
NC="\033[0m" # No Color

# Default values
declare REGION="us-east-1"
declare GITHUB_ORG=""
declare REPO_NAME="gha-aws-oidc-bootstrap"
declare BRANCH_NAME="main"
declare GITHUB_TOKEN=""
declare OIDC_PROVIDER_ARN=""
declare TEMP_DIR=""
declare CFN_TEMPLATE=""
declare STACK_NAME=""
declare ROLE_ARN=""
declare ROLE_NAME=""
declare SSM_PARAM_NAME=""
declare VARIABLE_SET=false
declare HAD_ERRORS=false
declare AWS_ACCOUNT_ID=""

die() {
  echo -e "${RED}$*${NC}" >&2
  exit 1
}

usage() {
  echo -e "${BOLD}Usage:${NC} $0 [options]"
  echo -e "\nSets up AWS OIDC authentication for GitHub Actions"
  echo -e "\n${BOLD}Options:${NC}"
  echo -e "  --region REGION            AWS region (default: us-east-1)"
  echo -e "  --github-org ORG_NAME      GitHub organization name (auto-detected if not provided)"
  echo -e "  --repo-name REPO_NAME      GitHub repository name (auto-detected if not provided)"
  echo -e "  --branch-name BRANCH_NAME  GitHub branch name (default: main)"
  echo -e "  --github-token TOKEN       GitHub personal access token (required)"
  echo -e "                             Token must have 'repo' and 'admin:repo_hook' permissions"
  echo -e "  --oidc-provider-arn ARN    ARN of the existing GitHub OIDC provider (optional)"
  echo -e "  --help                     Display this help message"
  exit 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --region)
        REGION="$2"; shift 2;;
      --github-org)
        GITHUB_ORG="$2"; shift 2;;
      --repo-name)
        REPO_NAME="$2"; shift 2;;
      --branch-name)
        BRANCH_NAME="$2"; shift 2;;
      --github-token)
        GITHUB_TOKEN="$2"; shift 2;;
      --oidc-provider-arn)
        OIDC_PROVIDER_ARN="$2"; shift 2;;
      --help)
        usage;;
      *)
        die "Unknown option: $1";;
    esac
  done
}

detect_github_repo() {
  if [[ -z "$GITHUB_ORG" || -z "$REPO_NAME" ]]; then
    REMOTE_URL=$(git config --get remote.origin.url)
    echo "DEBUG: remote URL is $REMOTE_URL"
    if [[ "$REMOTE_URL" =~ github.com[:/]{1}([^/]+)/([^/]+)(\.git)?$ ]]; then
      GITHUB_ORG="${BASH_REMATCH[1]}"
      REPO_NAME="${BASH_REMATCH[2]%.*}"
      echo "DEBUG: extracted org=$GITHUB_ORG repo=$REPO_NAME"
    else
      die "Failed to extract org/repo from remote URL"
    fi
  fi
  if [[ -z "$GITHUB_ORG" || -z "$REPO_NAME" ]]; then
    die "GitHub organization and repository name are required"
  fi
}

prompt_for_github_token() {
  SSM_PARAM_NAME="/${GITHUB_ORG}/gha-aws-oidc-bootstrap/GITHUB_TOKEN"
  GITHUB_TOKEN=$(aws ssm get-parameter --name "$SSM_PARAM_NAME" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || echo "")
  if [[ -z "$GITHUB_TOKEN" ]]; then
    echo -e "${YELLOW}You will be prompted to enter a GitHub personal access token with 'repo' and 'admin:repo_hook' scopes.${NC}"
    local input1 input2
    read -rsp $'Enter your GitHub personal access token: ' input1; echo
    read -rsp $'Re-enter your token to confirm: ' input2; echo
    if [[ -z "$input1" || "$input1" != "$input2" ]]; then
      die "Tokens did not match or were blank. Exiting."
    fi
    aws ssm put-parameter --name "$SSM_PARAM_NAME" --value "$input1" --type SecureString --overwrite
    GITHUB_TOKEN=$(aws ssm get-parameter --name "$SSM_PARAM_NAME" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || echo "")
    if [[ -z "$GITHUB_TOKEN" ]]; then
      die "Failed to store token in SSM. Please check your AWS CLI permissions and try again."
    fi
    echo -e "${GREEN}GitHub token successfully stored in SSM and loaded for use!${NC}"
  fi
}

deploy_cloudformation_stack() {
  SANITIZED_REPO_NAME=$(echo "$REPO_NAME" | tr '_' '-')
  STACK_NAME="$SANITIZED_REPO_NAME"
  echo -e "${YELLOW}Using stack name: $STACK_NAME${NC}"
  TEMP_DIR=$(mktemp -d)
  CFN_TEMPLATE="$TEMP_DIR/${REPO_NAME}-template.yaml"
  cat > "$CFN_TEMPLATE" <<'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Description: 'GitHub Actions OIDC Integration for AWS Authentication'
Parameters:
  GitHubOrg:
    Type: String
    Description: GitHub organization name
  RepoName:
    Type: String
    Description: GitHub repository name
  BranchName:
    Type: String
    Description: GitHub branch name
  OIDCProviderArn:
    Type: String
    Description: ARN of the existing GitHub OIDC provider
    Default: ''
Conditions:
  CreateOIDCProvider: !Equals [!Ref OIDCProviderArn, '']
Resources:
  GitHubOIDCProvider:
    Type: AWS::IAM::OIDCProvider
    Condition: CreateOIDCProvider
    Properties:
      Url: https://token.actions.githubusercontent.com
      ClientIdList:
        - sts.amazonaws.com
      ThumbprintList:
        - 6938fd4d98bab03faadb97b34396831e3780aea1
      Tags:
        - Key: Project
          Value: !Sub "${GitHubOrg}-${RepoName}"
        - Key: ManagedBy
          Value: CloudFormation
        - Key: Environment
          Value: prod
  GitHubActionsRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Join ['-', ['github-oidc-role', !Ref GitHubOrg, !Ref RepoName]]
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Federated: !If [CreateOIDCProvider, !GetAtt GitHubOIDCProvider.Arn, !Ref OIDCProviderArn]
            Action: 'sts:AssumeRoleWithWebIdentity'
            Condition:
              StringEquals:
                token.actions.githubusercontent.com:aud: 'sts.amazonaws.com'
              StringLike:
                token.actions.githubusercontent.com:sub:
                  - !Sub 'repo:${GitHubOrg}/${RepoName}:*'
                  - !Sub 'repo:${GitHubOrg}/${RepoName}:ref:*'
                  - !Sub 'repo:${GitHubOrg}/${RepoName}:environment:*'
                  - !Sub 'repo:${GitHubOrg}/${RepoName}:pull_request'
                  - !Sub 'repo:${GitHubOrg}/${RepoName}:workflow:*'
                  - !Sub 'repo:${GitHubOrg}/${RepoName}:branch:*'
      ManagedPolicyArns:
        - !Ref GitHubActionsPolicy
      Tags:
        - Key: Project
          Value: !Sub "${GitHubOrg}-${RepoName}"
        - Key: ManagedBy
          Value: CloudFormation
        - Key: Environment
          Value: prod
  GitHubActionsPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Description: !Sub 'Policy for GitHub Actions OIDC integration with ${GitHubOrg}/${RepoName}'
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - 'cloudformation:*'
              - 'iam:GetRole'
              - 'iam:CreateRole'
              - 'iam:AttachRolePolicy'
              - 'iam:PutRolePolicy'
              - 'logs:*'
              - 'ssm:*'
              - 's3:*'
            Resource: '*'
Outputs:
  RoleArn:
    Description: ARN of the IAM role for GitHub Actions
    Value: !GetAtt GitHubActionsRole.Arn
EOF
  echo -e "\n${BOLD}Step 1:${NC} Deploying CloudFormation stack for OIDC integration..."
  if ! command -v aws &> /dev/null; then die "AWS CLI is not installed. Please install it first."; fi
  if ! aws sts get-caller-identity &> /dev/null; then die "AWS credentials are not configured. Please run 'aws configure' first."; fi
  EXISTING_PROVIDER=$(aws iam list-open-id-connect-providers --query "OpenIDConnectProviderList[?contains(Arn, 'token.actions.githubusercontent.com')].Arn" --output text)
  if [ -n "$EXISTING_PROVIDER" ]; then
    echo -e "${YELLOW}Found existing GitHub OIDC provider: $EXISTING_PROVIDER${NC}"
    OIDC_PROVIDER_ARN="$EXISTING_PROVIDER"
    echo -e "Using existing provider ARN: $OIDC_PROVIDER_ARN"
  fi
  echo -e "Deploying CloudFormation stack $STACK_NAME in region $REGION..."
  aws cloudformation deploy \
    --template-file "$CFN_TEMPLATE" \
    --stack-name "$STACK_NAME" \
    --parameter-overrides \
      GitHubOrg="$GITHUB_ORG" \
      RepoName="$REPO_NAME" \
      BranchName="$BRANCH_NAME" \
      OIDCProviderArn="$OIDC_PROVIDER_ARN" \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "$REGION"
  echo -e "${GREEN}Successfully deployed CloudFormation stack $STACK_NAME${NC}"
}

get_role_arn() {
  ROLE_ARN=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='RoleArn'].OutputValue" \
    --output text)
  ROLE_NAME=$(echo "$ROLE_ARN" | sed 's/.*role\///')
  echo -e "${GREEN}Successfully retrieved IAM Role:${NC} $ROLE_NAME"
  echo -e "${GREEN}Role ARN:${NC} $ROLE_ARN"
  if [[ "$ROLE_NAME" != *"$GITHUB_ORG"* || "$ROLE_NAME" != *"gha-aws-oidc-bootstrap"* ]]; then
    echo -e "${YELLOW}Warning: The role name does not contain both organization and repository name.${NC}"
    echo -e "${YELLOW}This may indicate a problem with the CloudFormation template.${NC}"
    echo -e "${YELLOW}Expected pattern: github-oidc-role-$GITHUB_ORG-gha-aws-oidc-bootstrap${NC}"
    echo -e "${YELLOW}Actual role name: $ROLE_NAME${NC}"
    HAD_ERRORS=true
  fi
}

set_github_variable() {
  local name=$1 value=$2 org=$3 repo=$4 token=$5
  echo -e "${YELLOW}Setting GitHub repository variable $name...${NC}"
  local response check_result
  check_result=$(curl -s -H "Authorization: token $token" "https://api.github.com/repos/$org/$repo/actions/variables/$name")
  if [[ "$check_result" == *"Not Found"* || "$check_result" == *"Resource not found"* ]]; then
    response=$(curl -s -X POST \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: token $token" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "https://api.github.com/repos/$org/$repo/actions/variables" \
      -d "{\"name\":\"$name\",\"value\":\"$value\"}")
    echo -e "${YELLOW}Create result:${NC} $response"
  else
    response=$(curl -s -X PATCH \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: token $token" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "https://api.github.com/repos/$org/$repo/actions/variables/$name" \
      -d "{\"name\":\"$name\",\"value\":\"$value\"}")
    echo -e "${YELLOW}Update result:${NC} $response"
  fi
  VERIFY_VARIABLE=$(curl -s -H "Authorization: token $token" \
    "https://api.github.com/repos/$org/$repo/actions/variables/$name")
  if [[ "$VERIFY_VARIABLE" == *"$name"* ]]; then
    echo -e "${GREEN}Successfully verified GitHub repository variable $name is set to $value${NC}"
    VARIABLE_SET=true
  else
    echo -e "${YELLOW}Warning: Could not verify if the variable was set. Please check manually.${NC}"
    echo -e "${YELLOW}You may need to manually set the $name variable in GitHub with value: $value${NC}"
  fi
}

read_allowed_repos() {
  local allowed_repos_file="allowed_repos.txt"
  local repo_patterns=()
  # Always include the current repo detected by the script
  local current_repo="${GITHUB_ORG}/${REPO_NAME}"
  repo_patterns+=("repo:${current_repo}:*" "repo:${current_repo}:ref:*" "repo:${current_repo}:environment:*" "repo:${current_repo}:pull_request" "repo:${current_repo}:workflow:*" "repo:${current_repo}:branch:*")
  if [[ -f "$allowed_repos_file" ]]; then
    while IFS= read -r line; do
      [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
      # Skip duplicate of current repo
      [[ "$line" == "$current_repo" ]] && continue
      repo_patterns+=("repo:${line}:*" "repo:${line}:ref:*" "repo:${line}:environment:*" "repo:${line}:pull_request" "repo:${line}:workflow:*" "repo:${line}:branch:*")
    done < "$allowed_repos_file"
  fi
  printf '%s\n' "${repo_patterns[@]}"
}

update_trust_policy() {
  local role_name=$1 provider_arn=$2
  echo -e "\n${BOLD}Updating trust policy for role:${NC} $role_name"
  local temp_policy_file=$(mktemp)
  local repo_patterns_json
  # Build the JSON array for StringLike
  local repo_patterns=( $(read_allowed_repos) )
  repo_patterns_json=$(printf '"%s",' "${repo_patterns[@]}")
  repo_patterns_json="${repo_patterns_json%,}"
  cat > "$temp_policy_file" << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "$provider_arn"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": [
            $repo_patterns_json
          ]
        }
      }
    }
  ]
}
EOF
  cp "$temp_policy_file" "trust-policy.json"
  echo -e "${YELLOW}Saved trust policy to trust-policy.json for reference${NC}"
  aws iam update-assume-role-policy --role-name "$role_name" --policy-document file://"$temp_policy_file" --region "$REGION"
  rm "$temp_policy_file"
  echo -e "${GREEN}Successfully updated trust policy for role: $role_name${NC}"
  echo -e "${GREEN}Trust policy now includes patterns from allowed_repos.txt${NC}"
}

generate_trust_policy_from_template() {
  local template_file="trust-policy.example.json"
  local output_file="trust-policy.json"
  local aws_account_id="$1"
  local github_org="$2"
  local repo_name="$3"

  if [[ ! -f "$template_file" ]]; then
    echo -e "${RED}Template $template_file not found. Please ensure it exists in the project root.${NC}"
    exit 1
  fi

  sed \
    -e "s|<YOUR-AWS-ACCOUNT-ID>|$aws_account_id|g" \
    -e "s|<YOUR-GITHUB-ORG>|$github_org|g" \
    -e "s|<YOUR-REPO>|$repo_name|g" \
    "$template_file" > "$output_file"

  echo -e "${GREEN}Generated $output_file from $template_file.${NC}"
}

cleanup() {
  [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
}

main() {
  parse_args "$@"
  detect_github_repo
  prompt_for_github_token
  AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
  deploy_cloudformation_stack
  get_role_arn
  set_github_variable "AWS_ROLE_TO_ASSUME" "$ROLE_ARN" "$GITHUB_ORG" "gha-aws-oidc-bootstrap" "$GITHUB_TOKEN"
  generate_trust_policy_from_template "$AWS_ACCOUNT_ID" "$GITHUB_ORG" "$REPO_NAME"
  update_trust_policy "$ROLE_NAME" "$OIDC_PROVIDER_ARN"
  cleanup
  echo -e "\n${GREEN}OIDC setup completed successfully!${NC}"
  echo -e "${GREEN}Your GitHub Actions workflow can now authenticate with AWS using OIDC.${NC}"
  echo -e "\n${YELLOW}Next steps:${NC}"
  echo -e "1. Commit and push the changes to your GitHub repository"
  echo -e "2. Run the GitHub Actions workflow manually to test the OIDC authentication"
  echo -e "3. Check the workflow logs for any authentication errors"
  if [[ "$HAD_ERRORS" == false && "$VARIABLE_SET" == true ]]; then
    echo -e "\n${GREEN}${BOLD}✓ OIDC authentication setup complete!${NC}"
    echo -e "\n${BOLD}To use OIDC authentication in your GitHub Actions workflow:${NC}"
    cat <<EOF
   - name: Configure AWS credentials
     uses: aws-actions/configure-aws-credentials@v2
     with:
       role-to-assume: \${{ vars.AWS_ROLE_TO_ASSUME }}
       aws-region: $REGION
       audience: sts.amazonaws.com
EOF
    echo -e "\n${BOLD}Your GitHub Actions workflows can now securely authenticate with AWS!${NC}"
  elif [[ "$VARIABLE_SET" == true && "$HAD_ERRORS" == true ]]; then
    echo -e "\n${YELLOW}${BOLD}⚠ OIDC authentication setup completed with minor warnings.${NC}"
    echo -e "${YELLOW}The GitHub variable was set successfully, but there were some warnings.${NC}"
    echo -e "\n${BOLD}Your workflow should use:${NC}"
    cat <<EOF
   - name: Configure AWS credentials
     uses: aws-actions/configure-aws-credentials@v2
     with:
       role-to-assume: \${{ vars.AWS_ROLE_TO_ASSUME }}
       aws-region: $REGION
       audience: sts.amazonaws.com
EOF
  else
    echo -e "\n${YELLOW}${BOLD}⚠ OIDC authentication setup completed with issues.${NC}"
    echo -e "${YELLOW}Please address the issues above before running your GitHub Actions workflow.${NC}"
    echo -e "\n${BOLD}Once issues are resolved, your workflow should use:${NC}"
    cat <<EOF
   - name: Configure AWS credentials
     uses: aws-actions/configure-aws-credentials@v2
     with:
       role-to-assume: \${{ vars.AWS_ROLE_TO_ASSUME }}
       aws-region: $REGION
       audience: sts.amazonaws.com
EOF
  fi
}

trap cleanup EXIT
main "$@"
