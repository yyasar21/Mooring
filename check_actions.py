#!/usr/bin/env python3
"""Check GitHub Actions workflow run status for a repository."""

import json
import os
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

def fetch_json(url, token=None):
    """Fetch JSON from a URL using GitHub API."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        print(f"  HTTP Error {e.code}: {e.reason}")
        return None
    except URLError as e:
        print(f"  URL Error: {e.reason}")
        return None

def check_actions(repo_owner, repo_name, token=None):
    """Check recent workflow runs for a repository."""
    base_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
    
    print(f"Repository: {repo_owner}/{repo_name}")
    print("=" * 60)
    
    # Get repo info
    repo_info = fetch_json(f"{base_url}/actions/runs", token)
    if not repo_info:
        print("Failed to fetch workflow runs.")
        return
    
    # Get recent workflow runs
    runs = repo_info.get("workflow_runs", [])
    if not runs:
        print("No recent workflow runs found.")
        return
    
    print(f"\nRecent Workflow Runs:")
    print("-" * 60)
    
    for run in runs[:10]:  # Show last 10 runs
        status = run.get("status", "?")
        conclusion = run.get("conclusion", "?")
        name = run.get("name", "Unknown")
        branch = run.get("head_branch", "?")
        sha = run.get("head_sha", "?")[:8]
        created = run.get("created_at", "?")
        url = run.get("html_url", "?")
        
        # Emoji for status
        if conclusion == "success":
            icon = "✅"
        elif conclusion == "failure":
            icon = "❌"
        elif conclusion == "cancelled":
            icon = "⚠️"
        else:
            icon = "🔄"
        
        print(f"\n{icon} {name}")
        print(f"   Branch: {branch} | SHA: {sha}")
        print(f"   Status: {status} | Conclusion: {conclusion}")
        print(f"   Created: {created}")
        print(f"   URL: {url}")
    
    # Check for vulnerabilities
    print(f"\n{'=' * 60}")
    print("Security Advisories:")
    print("-" * 60)
    
    advisories = fetch_json(f"{base_url}/vulnerability-alerts", token)
    if advisories:
        print(f"Vulnerability alerts: {'enabled' if advisories.get('state') else 'disabled'}")
    else:
        print("Could not check vulnerability alerts.")

if __name__ == "__main__":
    repo_owner = "yyasar21"
    repo_name = "Mooring"
    token = os.environ.get("GITHUB_TOKEN")
    
    check_actions(repo_owner, repo_name, token)
