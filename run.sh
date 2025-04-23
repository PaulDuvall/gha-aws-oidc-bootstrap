#!/usr/bin/env bash
# US-XXX: Automated setup script for Python 3.11 OIDC trust policy generator
# This script sets up a Python 3.11 virtual environment, installs dependencies, and runs tests.
# Usage: bash run.sh

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_VERSION="3.11"
VENV_DIR="$PROJECT_ROOT/.venv"
REQUIREMENTS_FILE="$PROJECT_ROOT/requirements.txt"

# Check for Python 3.11
if ! command -v python3.11 &>/dev/null; then
  echo "Python 3.11 not found. Please install Python 3.11 and re-run this script." >&2
  exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
  python3.11 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r "$REQUIREMENTS_FILE"

# Set PYTHONPATH for src imports in tests
export PYTHONPATH="$PROJECT_ROOT/src"

# Default values
GITHUB_ORG=""
REGION="us-east-1"
GITHUB_TOKEN=""
OIDC_PROVIDER_ARN=""

# Parse arguments
RUN_TESTS=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --github-org)
      GITHUB_ORG="$2"; shift 2;;
    --region)
      REGION="$2"; shift 2;;
    --github-token)
      GITHUB_TOKEN="$2"; shift 2;;
    --oidc-provider-arn)
      OIDC_PROVIDER_ARN="$2"; shift 2;;
    --test|--tests)
      RUN_TESTS=true; shift;;
    *)
      echo "Unknown argument: $1" >&2; exit 1;;
  esac
done

# Set PYTHONPATH to ensure src/ is always importable
export PYTHONPATH="$(pwd)"

if [ "$RUN_TESTS" = true ]; then
  echo "Running all tests via pytest..."
  pytest -v
  exit $?
fi

# Always generate trust policy before deploying stack
python3 src/generate_trust_policy.py --repos-file allowed_repos.txt --output cloudformation/trust_policy.json
# Render IAM Role CloudFormation template from Jinja2
python3 src/render_iam_template.py

# Build up the command
CFN_ARGS=(--github-org "$GITHUB_ORG" --region "$REGION" --github-token "$GITHUB_TOKEN")
if [[ -n "$OIDC_PROVIDER_ARN" ]]; then
  CFN_ARGS+=(--oidc-provider-arn "$OIDC_PROVIDER_ARN")
fi
python3 src/cfn_deploy.py "${CFN_ARGS[@]}"

# Example usage of generator
# python src/generate_trust_policy.py --github-org ExampleOrg
