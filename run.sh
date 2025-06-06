#!/usr/bin/env bash
# US-XXX: Automated setup script for Python 3.11 OIDC trust policy generator
# This script sets up a Python 3.11 virtual environment, installs dependencies, and runs tests.
# Usage: bash run.sh

set -euo pipefail
set -x

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
GITHUB_REPO=""
REGION="us-east-1"
GITHUB_TOKEN=""
OIDC_PROVIDER_ARN=""

# Parse arguments
RUN_TESTS=false
RENDER_ONLY=false
POLICY_FILE=""
OUTPUT_FILE="cloudformation/generated/iam_role.yaml"

while [[ $# -gt 0 ]]; do
  case $1 in
    --github-org)
      GITHUB_ORG="$2"; shift 2;;
    --github-repo)
      GITHUB_REPO="$2"; shift 2;;
    --region)
      REGION="$2"; shift 2;;
    --github-token)
      GITHUB_TOKEN="$2"; shift 2;;
    --oidc-provider-arn)
      OIDC_PROVIDER_ARN="$2"; shift 2;;
    --policy-file)
      POLICY_FILE="$2"; shift 2;;
    --output)
      OUTPUT_FILE="$2"; shift 2;;
    --test|--tests)
      RUN_TESTS=true; shift;;
    --render-only)
      RENDER_ONLY=true; shift;;
    *)
      echo "Unknown argument: $1" >&2; exit 1;;
  esac
done

# Set PYTHONPATH to ensure src/ is always importable
export PYTHONPATH="$(pwd)"

# Always generate trust policy and template
mkdir -p cloudformation/generated
PYTHON_ARGS=""
if [[ -n "$POLICY_FILE" ]]; then
  PYTHON_ARGS="$PYTHON_ARGS --policy-file $POLICY_FILE"
fi
if [[ -n "$OUTPUT_FILE" ]]; then
  PYTHON_ARGS="$PYTHON_ARGS --output $OUTPUT_FILE"
fi
python3 src/generate_trust_policy.py --repos-file allowed_repos.txt --output cloudformation/generated/trust_policy.json
# Pass owner and repo to template renderer
python3 src/render_iam_template.py --owner "$GITHUB_ORG" --repo "$GITHUB_REPO" $PYTHON_ARGS

if [ "$RENDER_ONLY" = true ]; then
  echo "Rendered trust policy and IAM template only."
  exit 0
fi

if [ "$RUN_TESTS" = true ]; then
  echo "Running all tests via pytest..."
  pytest -v
  exit $?
fi

# Build up the command
CFN_ARGS=(--github-org "$GITHUB_ORG" --github-repo "$GITHUB_REPO" --region "$REGION" --github-token "$GITHUB_TOKEN")
if [[ -n "$OIDC_PROVIDER_ARN" ]]; then
  CFN_ARGS+=(--oidc-provider-arn "$OIDC_PROVIDER_ARN")
fi
python3 src/cfn_deploy.py "${CFN_ARGS[@]}"

# Example usage of generator
# python src/generate_trust_policy.py --github-org ExampleOrg
