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
declare GITHUB_TOKEN_ARG=""
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
declare ALLOWED_REPOS=""
declare MULTI_REPO_MODE=false

die() {
  echo -e "${RED}$*${NC}" >&2
  usage
}

usage() {
  echo -e "${BOLD}Usage:${NC} $0 [options]"
  echo -e "\nSets up AWS OIDC authentication for GitHub Actions."
  echo -e "\n${BOLD}Current mode:${NC} This stack is configured to allow OIDC access for ALL repositories in your GitHub organization (e.g., PaulDuvall/*)."
  echo -e "  You do NOT need to specify --allowed-repos or use allowed_repos.txt."
  echo -e "\n${BOLD}Example usage:${NC}"
  echo -e "  bash setup_oidc.sh --github-org PaulDuvall --region us-east-1 --github-token \"<YOUR_GITHUB_TOKEN>\"\n"
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
    case $1 in
      --github-org)
        GITHUB_ORG="$2"; shift 2;;
      --region)
        REGION="$2"; shift 2;;
      --github-token)
        GITHUB_TOKEN_ARG="$2"; shift 2;;
      *)
        echo "Unknown argument: $1"; exit 1;;
    esac
  done
  if [[ -z "$GITHUB_ORG" ]]; then
    echo -e "${RED}--github-org is required${NC}"; usage; exit 1;
  fi
  if [[ -z "$GITHUB_TOKEN_ARG" ]]; then
    echo -e "${RED}--github-token is required${NC}"; usage; exit 1;
  fi
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

set_github_variable() {
  local org="$1"
  local repo="$2"
  local token="$3"
  local role_arn="$4"
  local var_name="GHA_OIDC_ROLE_ARN"

  # Debug: Print token for diagnostics
  echo "TOKEN_RAW=[$token]"
  echo "$token" | od -c

  # Step 1: Try to delete the variable if it exists
  echo "DEBUG: Attempting to delete variable $var_name in $org/$repo before creation."
  delete_github_variable "$org" "$repo" "$token" "$var_name"

  # Step 2: Try to create the variable with POST
  echo "DEBUG: Attempting to create variable $var_name in $org/$repo via POST."
  response=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: token $token" \
    -H "Content-Type: application/json" \
    "https://api.github.com/repos/$org/$repo/actions/variables" \
    -d "{\"name\":\"$var_name\",\"value\":\"$role_arn\"}")
  http_code=$(echo "$response" | tail -n 1)
  body=$(echo "$response" | sed '$d')

  if [[ "$http_code" == "201" ]]; then
    echo "Successfully created variable $var_name in $org/$repo."
    return 0
  elif [[ "$http_code" == "409" ]]; then
    echo "DEBUG: Variable already exists, attempting PATCH to update value."
    patch_response=$(curl -s -w "\n%{http_code}" -X PATCH \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: token $token" \
      -H "Content-Type: application/json" \
      "https://api.github.com/repos/$org/$repo/actions/variables/$var_name" \
      -d "{\"name\":\"$var_name\",\"value\":\"$role_arn\"}")
    patch_http_code=$(echo "$patch_response" | tail -n 1)
    patch_body=$(echo "$patch_response" | sed '$d')
    if [[ "$patch_http_code" == "200" ]]; then
      echo "Successfully updated variable $var_name in $org/$repo with PATCH."
      return 0
    else
      echo "ERROR: PATCH failed for $var_name in $org/$repo. Response: $patch_body"
      return 1
    fi
  else
    echo "ERROR: Failed to create variable $var_name in $org/$repo. HTTP $http_code. Response: $body"
    return 1
  fi
}

delete_github_variable() {
  local org=$1
  local repo=$2
  local token=$3
  local var_name=$4
  local auth_scheme="token"
  if [[ "$token" == github_pat_* || "$token" == gho_* || "$token" == ghu_* || "$token" == ghr_* ]]; then
    auth_scheme="Bearer"
  fi
  echo "Deleting variable $var_name in $org/$repo if it exists..."
  curl -s -X DELETE \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: $auth_scheme $token" \
    "https://api.github.com/repos/$org/$repo/actions/variables/$var_name"
}

deploy_cloudformation_stack() {
  SANITIZED_REPO_NAME=$(echo "$REPO_NAME" | tr '_' '-')
  STACK_NAME="$SANITIZED_REPO_NAME"
  echo -e "${YELLOW}Using stack name: $STACK_NAME${NC}"
  TEMP_DIR=$(mktemp -d)
  CFN_TEMPLATE="$TEMP_DIR/${REPO_NAME}-template.yaml"
  cat > "$CFN_TEMPLATE" <<EOF
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
          Value: !Sub "${GITHUB_ORG}-${REPO_NAME}"
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
                  - !Sub 'repo:${GITHUB_ORG}/*'
                  - !Sub 'repo:${GITHUB_ORG}/*:ref:*'
                  - !Sub 'repo:${GITHUB_ORG}/*:environment:*'
                  - !Sub 'repo:${GITHUB_ORG}/*:pull_request'
                  - !Sub 'repo:${GITHUB_ORG}/*:workflow:*'
                  - !Sub 'repo:${GITHUB_ORG}/*:branch:*'
      ManagedPolicyArns:
        - !Ref GitHubActionsPolicy
      Tags:
        - Key: Project
          Value: !Sub "${GITHUB_ORG}-${REPO_NAME}"
        - Key: ManagedBy
          Value: CloudFormation
        - Key: Environment
          Value: prod
  GitHubActionsPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Description: !Sub 'Policy for GitHub Actions OIDC integration with ${GITHUB_ORG}/${REPO_NAME}'
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

set_variable_allowed_repos() {
  local org="$1"
  local token="$2"
  local role_arn="$3"
  local repos
  repos=( $(fetch_allowed_repos) )
  if [[ ${#repos[@]} -eq 0 ]]; then
    echo -e "${YELLOW}No repositories found in allowed_repos.txt. Skipping variable setup.${NC}"
    return
  fi
  for repo_full in "${repos[@]}"; do
    # Support both org/repo and just repo (assume org if missing)
    if [[ "$repo_full" == */* ]]; then
      org_name="${repo_full%%/*}"
      repo_name="${repo_full##*/}"
    else
      org_name="$org"
      repo_name="$repo_full"
    fi
    # Debug: Show constructed API URL and arguments
    echo "DEBUG: set_github_variable org=[$org_name] repo=[$repo_name] token=[${token:0:5}...] role_arn=[$role_arn]"
    echo "DEBUG: API URL=https://api.github.com/repos/$org_name/$repo_name/actions/variables"
    set_github_variable "$org_name" "$repo_name" "$token" "$role_arn"
  done
}

fetch_allowed_repos() {
  local allowed_file="allowed_repos.txt"
  local repos=()
  if [[ ! -f "$allowed_file" ]]; then
    echo -e "${YELLOW}No allowed_repos.txt found. No repos will be processed.${NC}"
    echo ""
    return
  fi
  while IFS= read -r line; do
    # Skip comments and blank lines
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    # Extract repo name (support both org/repo and just repo)
    repo_name=$(echo "$line" | xargs)
    [[ -n "$repo_name" ]] && repos+=("$repo_name")
  done < "$allowed_file"
  echo "${repos[@]}"
}

print_github_actions_yaml() {
  cat <<EOF
  - name: Configure AWS credentials
    uses: aws-actions/configure-aws-credentials@v2
    with:
      role-to-assume: \${{ vars.GHA_OIDC_ROLE_ARN }}
      aws-region: $REGION
      audience: sts.amazonaws.com
EOF
}

generate_trust_policy_from_template() {
  local aws_account_id="$1"
  local github_org="$2"
  local repo_name="$3"
  local template_file="trust-policy.example.json"
  local output_file="trust-policy.json"

  if [[ ! -f "$template_file" ]]; then
    echo "Template $template_file not found. Please ensure it exists in the project root."
    exit 1
  fi

  sed \
    -e "s|<YOUR-AWS-ACCOUNT-ID>|$aws_account_id|g" \
    -e "s|<YOUR-GITHUB-ORG>|$github_org|g" \
    -e "s|<YOUR-REPO>|$repo_name|g" \
    "$template_file" > "$output_file"

  echo "Generated $output_file from $template_file."
}

update_trust_policy() {
  local role_name=$1
  local provider_arn=$2
  echo -e "\nUpdating trust policy for role: $role_name"
  local temp_policy_file=$(mktemp)
  cp trust-policy.json "$temp_policy_file"
  aws iam update-assume-role-policy --role-name "$role_name" --policy-document file://"$temp_policy_file" --region "$REGION"
  rm "$temp_policy_file"
  echo "Successfully updated trust policy for role: $role_name"
}

cleanup() {
  [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
}

main() {
  parse_args "$@"
  if [[ "$MULTI_REPO_MODE" == true ]]; then
    multi_repo_deploy
    exit 0
  fi
  detect_github_repo
  AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
  deploy_cloudformation_stack
  get_role_arn
  # Set the variable only in allowed repos from allowed_repos.txt
  set_variable_allowed_repos "$GITHUB_ORG" "$GITHUB_TOKEN_ARG" "$ROLE_ARN"
  generate_trust_policy_from_template "$AWS_ACCOUNT_ID" "$GITHUB_ORG" "$REPO_NAME"
  update_trust_policy "$ROLE_NAME" "$OIDC_PROVIDER_ARN"
  cleanup
  echo -e "\n${GREEN}OIDC setup completed successfully!${NC}"
  echo -e "\n${BOLD}Your GitHub Actions workflow can now authenticate with AWS using OIDC.${NC}"
  echo -e "\n${BOLD}Next steps:${NC}"
  echo "1. Commit and push the changes to your GitHub repository"
  echo "2. Run the GitHub Actions workflow manually to test the OIDC authentication"
  echo "3. Check the workflow logs for any authentication errors"
  echo -e "\n${BOLD}Once issues are resolved, your workflow should use:${NC}"
  print_github_actions_yaml
}

trap cleanup EXIT
main "$@"
