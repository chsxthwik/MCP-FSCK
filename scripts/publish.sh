#!/usr/bin/env bash
# Publish mcp-fsck to your GitHub account.
#
# Usage:  GH_TOKEN=ghp_xxx bash scripts/publish.sh [your-username] [repo-name]
#
# The token needs the "repo" scope (fine-grained: "Administration" read/write
# for repo creation + "Contents" read/write). It is used for one API call and
# one push, and is never written to disk or to git config.
set -euo pipefail

: "${GH_TOKEN:?Set GH_TOKEN to a GitHub personal access token}"
REPO_NAME="${2:-mcp-fsck}"
API="https://api.github.com"

auth() { curl -sS -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" "$@"; }

# 1. resolve username (or use the one passed in)
USER_NAME="${1:-}"
if [ -z "$USER_NAME" ]; then
  USER_NAME="$(auth "$API/user" | grep -o '"login": *"[^"]*"' | head -1 | sed 's/.*"login": *"\([^"]*\)"/\1/')"
  [ -n "$USER_NAME" ] || { echo "could not resolve username from token"; exit 1; }
fi
echo "→ publishing to github.com/$USER_NAME/$REPO_NAME"

# 2. stamp the real repo URL into package.json and amend the commit
sed -i "s|github.com/YOUR_GITHUB_USERNAME/mcp-fsck|github.com/$USER_NAME/$REPO_NAME|" package.json
if ! git diff --quiet package.json 2>/dev/null; then
  git add package.json
  git -c user.name="$USER_NAME" -c user.email="$USER_NAME@users.noreply.github.com" commit -q --amend --no-edit --reset-author
fi

# 3. create the repo if it does not exist yet
HTTP="$(auth -o /dev/null -w '%{http_code}' -X POST "$API/user/repos" \
  -d "{\"name\":\"$REPO_NAME\",\"description\":\"Integrity check for MCP server configs — audits Claude, Cursor, VS Code and Windsurf agent configs for secrets, injection, tool poisoning and dangerous capability combos\",\"has_issues\":true,\"has_wiki\":false}")"
case "$HTTP" in
  201) echo "→ created repository" ;;
  422) echo "→ repository already exists, pushing to it" ;;
  *)   echo "→ unexpected API response: $HTTP"; exit 1 ;;
esac

# 4. push (token used one-shot on the URL, never stored)
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$USER_NAME/$REPO_NAME.git"
git push -u "https://x-access-token:$GH_TOKEN@github.com/$USER_NAME/$REPO_NAME.git" main
echo "✓ done: https://github.com/$USER_NAME/$REPO_NAME"
