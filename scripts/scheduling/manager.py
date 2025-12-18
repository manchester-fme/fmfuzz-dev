#!/usr/bin/env python3
"""Manager job - checks commits, updates build queue and fuzzing schedule"""

import os
import sys
from datetime import datetime, timezone
from typing import List, Optional

scripts_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, scripts_dir)

from scheduling.s3_state import get_state_manager, S3StateError, DEFAULT_STATE_VERSION
from scheduling.detect_cpp_changes import detect_cpp_changes

try:
    import requests
except ImportError:
    requests = None

try:
    import boto3
except ImportError:
    boto3 = None


def get_commits_from_github(repo_url: str, since_commit: Optional[str] = None, token: Optional[str] = None, max_commits: Optional[int] = None) -> List[str]:
    """Get commits from GitHub.
    
    Args:
        repo_url: Repository URL
        since_commit: Only fetch commits after this commit (None = start from beginning)
        token: GitHub token
        max_commits: Maximum number of commits to fetch (None = unlimited, used when starting fresh)
    """
    if requests is None:
        raise RuntimeError("requests library required")
    
    repo_path = repo_url.replace('https://github.com/', '').replace('.git', '')
    api_url = f"https://api.github.com/repos/{repo_path}/commits"
    headers = {'Authorization': f'token {token}'} if token else {}
    params = {'per_page': 100}
    
    commits = []
    page = 1
    while True:
        params['page'] = page
        try:
            response = requests.get(api_url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            if not data:
                break
            
            for commit in data:
                commit_hash = commit['sha']
                
                # Stop if we've reached the last checked commit (we've seen all new commits)
                if since_commit and commit_hash == since_commit:
                    return commits
                
                # Add commit to list (skip the last checked commit itself)
                if not (since_commit and commit_hash == since_commit):
                    commits.append(commit_hash)
                    
                    # Stop if we've reached max_commits limit
                    if max_commits and len(commits) >= max_commits:
                        return commits
            
            if len(data) < 100:
                break
            page += 1
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                break
            raise RuntimeError(f"GitHub API error: {e}")
    return commits


def run_manager(solver: str, repo_url: str, token: Optional[str] = None):
    manager = get_state_manager(solver)
    last_checked = manager.get_last_checked_commit()
    print(f"Last checked commit: {last_checked or 'None'}")
    
    # When starting fresh (no last_checked), limit to recent commits to avoid checking entire history
    # We'll fetch up to 100 commits and then filter to last 4 with C++ changes
    max_commits = None if last_checked else 100
    
    try:
        commits = get_commits_from_github(repo_url, last_checked, token, max_commits=max_commits)
    except Exception as e:
        print(f"❌ Error getting commits: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Track NEW commits added from GitHub
    new_commits_added_to_schedule = []
    
    # Process new commits from GitHub
    if commits:
        print(f"Found {len(commits)} commit(s) to check")
        
        new_commits_with_cpp = []
        for commit in commits:
            try:
                has_cpp, _ = detect_cpp_changes(repo_url, commit, token)
                if has_cpp:
                    print(f"✅ Commit {commit[:8]} has C++ changes")
                    new_commits_with_cpp.append(commit)
                else:
                    print(f"⏭️  Commit {commit[:8]} has no C++ changes")
            except Exception as e:
                print(f"⚠️  Error checking commit {commit[:8]}: {e}", file=sys.stderr)
                continue
        
        # When starting fresh (no last_checked), limit to last 4 commits with C++ changes
        # Note: commits come from GitHub API in reverse chronological order (newest first)
        # So [:4] gets the 4 newest commits with C++ changes
        if not last_checked and new_commits_with_cpp:
            if len(new_commits_with_cpp) > 4:
                print(f"📋 Starting fresh: limiting to last 4 commits with C++ changes (found {len(new_commits_with_cpp)})")
                new_commits_with_cpp = new_commits_with_cpp[:4]  # Keep first 4 (newest)
        
        if new_commits_with_cpp:
            # Add ONLY the latest commit to build queue
            # Commits are in reverse chronological order (newest first), so [0] is the latest
            latest_commit = new_commits_with_cpp[0]  # First in list is latest (newest)
            try:
                manager.add_to_build_queue(latest_commit)
                print(f"✅ Added latest commit {latest_commit[:8]} to build queue")
            except Exception as e:
                print(f"❌ Error adding latest commit to build queue: {e}", file=sys.stderr)
            
            # Add ALL commits with C++ changes directly to fuzzing schedule
            for commit in new_commits_with_cpp:
                try:
                    manager.add_to_fuzzing_schedule(commit)
                    new_commits_added_to_schedule.append(commit)
                    print(f"✅ Added {commit[:8]} to fuzzing schedule")
                except Exception as e:
                    print(f"❌ Error adding {commit[:8]} to fuzzing schedule: {e}", file=sys.stderr)
        
        manager.update_last_checked_commit(commits[0])
        print(f"✅ Updated last checked commit to {commits[0][:8]}")
    else:
        print("✅ No new commits to check")
    
    # Manage fuzzing schedule size when adding NEW commits from GitHub
    # If schedule has 4+ commits and we're adding new ones, remove oldest fuzzed commit
    schedule = manager.get_fuzzing_schedule()
    if new_commits_added_to_schedule and len(schedule) >= 4:
        # Find oldest fuzzed commit (first in list with fuzz_count > 0)
        oldest_fuzzed = None
        for commit_info in schedule:
            if commit_info.get('fuzz_count', 0) > 0:
                oldest_fuzzed = commit_info['hash']
                break
        
        if oldest_fuzzed:
            manager.remove_from_fuzzing_schedule(oldest_fuzzed)
            print(f"✅ Removed oldest fuzzed commit {oldest_fuzzed[:8]} to make room for new commit")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Manager job for fuzzing system')
    parser.add_argument('solver', choices=['z3', 'cvc5'], help='Solver name')
    parser.add_argument('repo_url', help='Repository URL')
    parser.add_argument('--token', help='GitHub token', default=os.getenv('GITHUB_TOKEN'))
    
    args = parser.parse_args()
    
    try:
        run_manager(args.solver, args.repo_url, args.token)
    except S3StateError as e:
        print(f"❌ S3 State Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
