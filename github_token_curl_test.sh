#!/bin/bash
# Minimal test for GitHub token with repo variable API
# Usage: bash github_token_curl_test.sh <token> <repo>

REPO="$2"
VAR_NAME="TEST_VAR_CASCADE"
VAR_VALUE="test-value-$(date +%s)"
TOKEN="$1"

if [[ -z "$TOKEN" || -z "$REPO" ]]; then
  echo "Usage: bash $0 <github_token> <repo>"
  exit 1
fi

# Print token info for debug
echo "TOKEN_RAW=[$TOKEN]"
echo -n "$TOKEN" | od -c

# Try to create a repo variable
curl -v -X POST \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: token $TOKEN" \
  "https://api.github.com/repos/$REPO/actions/variables" \
  -d "{\"name\":\"$VAR_NAME\",\"value\":\"$VAR_VALUE\"}"
