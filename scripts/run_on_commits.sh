#!/bin/bash

# Script to run a command on each commit in a git range
# Usage: ./run_on_commits.sh <base_commit> <tip_commit> [command]

set -euo pipefail

# Check if we have the correct number of arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <base_commit> <tip_commit> [command]"
    echo "Example: $0 HEAD~5 HEAD 'cargo test'"
    echo "If no command is specified, 'cargo build' will be used"
    exit 1
fi

BASE_COMMIT="$1"
TIP_COMMIT="$2"
shift 2      # Remove first two arguments, leaving the command
COMMAND="$*" # Join remaining arguments into a single command string

# Default to 'cargo build' if no command is specified
if [ -z "$COMMAND" ]; then
    COMMAND="cargo build"
fi

# Verify we're in a git repository
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "Error: Not in a git repository"
    exit 1
fi

# Verify commits exist
if ! git rev-parse --verify "$BASE_COMMIT" >/dev/null 2>&1; then
    echo "Error: Base commit '$BASE_COMMIT' does not exist"
    exit 1
fi

if ! git rev-parse --verify "$TIP_COMMIT" >/dev/null 2>&1; then
    echo "Error: Tip commit '$TIP_COMMIT' does not exist"
    exit 1
fi

# Check if working tree is clean
if ! git diff-index --quiet HEAD --; then
    echo "Error: Working tree is dirty. Please commit or stash your changes before running this script."
    exit 1
fi

# Check if there are untracked files
if [ -n "$(git ls-files --others --exclude-standard)" ]; then
    echo "Error: There are untracked files. Please add, commit or remove them before running this script."
    exit 1
fi

# Store the current branch/commit to restore later
ORIGINAL_HEAD=$(git rev-parse HEAD)
ORIGINAL_BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null || echo "")

# Function to cleanup on exit
cleanup() {
    echo "Restoring original state..."
    if [ -n "$ORIGINAL_BRANCH" ]; then
        git checkout "$ORIGINAL_BRANCH" >/dev/null 2>&1 || true
    else
        git checkout "$ORIGINAL_HEAD" >/dev/null 2>&1 || true
    fi
}

# Set trap to cleanup on script exit
trap cleanup EXIT

# Get list of commits in reverse order (oldest first)
COMMITS=$(git rev-list --reverse "$BASE_COMMIT..$TIP_COMMIT")

if [ -z "$COMMITS" ]; then
    echo "No commits found in range $BASE_COMMIT..$TIP_COMMIT"
    exit 0
fi

echo "Running command '$COMMAND' on commits in range $BASE_COMMIT..$TIP_COMMIT"
echo "Found $(echo "$COMMITS" | wc -l) commits to process"
echo

COMMIT_COUNT=0
TOTAL_COMMITS=$(echo "$COMMITS" | wc -l)

for commit in $COMMITS; do
    COMMIT_COUNT=$((COMMIT_COUNT + 1))
    SHORT_COMMIT=$(git rev-parse --short "$commit")
    COMMIT_MESSAGE=$(git log --format=%s -n 1 "$commit")

    echo "[$COMMIT_COUNT/$TOTAL_COMMITS] Processing commit $SHORT_COMMIT: $COMMIT_MESSAGE"

    # Checkout the commit
    git checkout "$commit" >/dev/null 2>&1

    # Clean the working tree to ensure pristine state
    git clean -fd >/dev/null 2>&1
    git reset --hard >/dev/null 2>&1

    # Run the command
    echo "Running: $COMMAND"
    eval "$COMMAND"
    COMMAND_EXIT_CODE=$?
    if [ $COMMAND_EXIT_CODE -ne 0 ]; then
        echo "Command failed on commit $SHORT_COMMIT with exit code $COMMAND_EXIT_CODE"
        exit $COMMAND_EXIT_CODE
    fi

    echo "✓ Command succeeded on commit $SHORT_COMMIT"
    echo
done

echo "Successfully ran command on all $TOTAL_COMMITS commits!"
