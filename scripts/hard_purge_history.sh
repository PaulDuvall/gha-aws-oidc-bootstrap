#!/usr/bin/env bash
# US-XXX: Comprehensive hard purge of sensitive files and directories from git history
# This script will remove all traces of specified files/directories from the entire git history
# and force-push the rewritten history to the remote repository.
#
# Usage: bash scripts/hard_purge_history.sh
#
# WARNING: This is DESTRUCTIVE. All collaborators must re-clone after use.

set -euo pipefail

REPO_URL=$(git config --get remote.origin.url)
REPO_NAME=$(basename -s .git "$REPO_URL")
TIMESTAMP=$(date +%Y%m%d%H%M%S)
MIRROR_DIR="temp-purge-$REPO_NAME-$TIMESTAMP.git"

# List of files/directories to purge (relative to repo root)
PURGE_PATHS=(
  "cloudformation/iam_role.yaml"
  "cloudformation/trust_policy.json"
  "cloudformation/generated/"
)

# Confirm destructive action
read -p "This will rewrite git history and force-push to $REPO_URL. Continue? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
  echo "Aborted."
  exit 1
fi

# Ensure git-filter-repo is installed
if ! command -v git-filter-repo &>/dev/null; then
  echo "git-filter-repo not found. Installing..."
  if command -v brew &>/dev/null; then
    brew install git-filter-repo
  else
    pip3 install --user git-filter-repo
    export PATH="$HOME/.local/bin:$PATH"
  fi
fi

echo "Cloning bare mirror to $MIRROR_DIR..."
git clone --mirror "$REPO_URL" "$MIRROR_DIR"
cd "$MIRROR_DIR"

# Build filter-repo arguments
FILTER_ARGS=()
for path in "${PURGE_PATHS[@]}"; do
  FILTER_ARGS+=("--path" "$path" "--invert-path")
done

echo "Running git-filter-repo to purge: ${PURGE_PATHS[*]}"
git filter-repo "${FILTER_ARGS[@]}"

echo "Force-pushing rewritten history to origin..."
git remote remove origin
git remote add origin "$REPO_URL"
git push --force --all
if git show-ref --tags | grep -q .; then
  git push --force --tags
fi

cd ..
echo "Cleaning up $MIRROR_DIR..."
rm -rf "$MIRROR_DIR"

echo "Purge complete! All traces of sensitive files and directories have been removed from history."
echo "All collaborators MUST re-clone the repository."
