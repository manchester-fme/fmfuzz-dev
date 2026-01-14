#!/usr/bin/env python3
"""Manager job - checks commits, updates build queue and fuzzing schedule"""

import os
import sys
from datetime import datetime, timezone, timedelta
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


def verify_commit_is_newer(repo_url: str, newer_commit: str, older_commit: str, token: Optional[str] = None) -> bool:
    """Verify that newer_commit is actually newer than older_commit by comparing commit dates.
    
    Args:
        repo_url: Repository URL
        newer_commit: Commit hash that should be newer
        older_commit: Commit hash that should be older
        token: GitHub token
    Returns:
        True if newer_commit is actually newer, False otherwise
    """
    if requests is None:
        return True  # Can't verify, assume correct to avoid blocking
    
    try:
        repo_path = repo_url.replace('https://github.com/', '').replace('.git', '')
        newer_date = None
        older_date = None
        
        # Get both commit dates
        for commit_hash, commit_type in [(newer_commit, "newer"), (older_commit, "older")]:
            api_url = f"https://api.github.com/repos/{repo_path}/commits/{commit_hash}"
            headers = {'Authorization': f'token {token}'} if token else {}
            
            response = requests.get(api_url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            commit_date_str = data.get('commit', {}).get('author', {}).get('date')
            if commit_date_str:
                commit_date = datetime.fromisoformat(commit_date_str.replace('Z', '+00:00'))
                if commit_type == "newer":
                    newer_date = commit_date
                else:
                    older_date = commit_date
        
        # Verify we got both dates
        if newer_date is None or older_date is None:
            print(f"⚠️  Could not get commit dates for verification, assuming correct order", file=sys.stderr)
            return True
        
        # Verify newer_commit is actually newer
        if newer_date <= older_date:
            print(f"❌ ERROR: Commit {newer_commit[:8]} ({newer_date}) is NOT newer than {older_commit[:8]} ({older_date})", file=sys.stderr)
            return False
        
        return True
    except Exception as e:
        print(f"⚠️  Error verifying commit order: {e}", file=sys.stderr)
        # If we can't verify, assume correct to avoid blocking (but log warning)
        return True


def check_if_commit_too_old(repo_url: str, commit_hash: str, token: Optional[str] = None, max_age_days: int = 30) -> bool:
    """Check if a commit is too old (older than max_age_days).
    
    Args:
        repo_url: Repository URL
        commit_hash: Commit hash to check
        token: GitHub token
        max_age_days: Maximum age in days (default: 30)
    Returns:
        True if commit is too old, False otherwise
    """
    if requests is None:
        return False  # Can't check, assume not too old
    
    try:
        repo_path = repo_url.replace('https://github.com/', '').replace('.git', '')
        api_url = f"https://api.github.com/repos/{repo_path}/commits/{commit_hash}"
        headers = {'Authorization': f'token {token}'} if token else {}
        
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Get commit date
        commit_date_str = data.get('commit', {}).get('author', {}).get('date')
        if commit_date_str:
            commit_date = datetime.fromisoformat(commit_date_str.replace('Z', '+00:00'))
            age_days = (datetime.now(timezone.utc) - commit_date).days
            return age_days > max_age_days
    except Exception as e:
        print(f"⚠️  Error checking commit age for {commit_hash[:8]}: {e}", file=sys.stderr)
        # If we can't check, assume it's not too old to be safe
        return False
    
    return False


def run_manager(solver: str, repo_url: str, token: Optional[str] = None):
    manager = get_state_manager(solver)
    last_checked = manager.get_last_checked_commit()
    print(f"Last checked commit: {last_checked or 'None'}")
    
    # Check if last_checked commit is too old (e.g., > 30 days)
    # If too old, treat as "starting fresh" to avoid fetching thousands of commits
    old_commit_reset = False
    if last_checked:
        is_too_old = check_if_commit_too_old(repo_url, last_checked, token, max_age_days=30)
        if is_too_old:
            print(f"⚠️  Last checked commit {last_checked[:8]} is too old (>30 days), resetting to start fresh")
            old_commit_reset = True
            last_checked = None
            # Note: We'll update last_checked_commit at the end with the new commit
    
    # Always limit max_commits to prevent fetching too many commits
    # Even if last_checked exists, limit to reasonable number to avoid rate limits
    max_commits = 200 if last_checked else 100
    
    try:
        commits = get_commits_from_github(repo_url, last_checked, token, max_commits=max_commits)
    except Exception as e:
        print(f"❌ Error getting commits: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Track NEW commits added from GitHub
    new_commits_added_to_schedule = []
    
    # Track errors during processing - if too many, fail rather than update state incorrectly
    processing_errors = 0
    max_processing_errors = 10  # Allow some errors (rate limits, etc.) but fail if too many
    
    # Process new commits from GitHub
    if commits:
        print(f"Found {len(commits)} commit(s) to check")
        
        # CRITICAL VALIDATION: If we had a last_checked commit, verify commits[0] is actually newer
        # This prevents updating to an old commit if something went wrong
        if last_checked and commits[0] != last_checked:
            if not verify_commit_is_newer(repo_url, commits[0], last_checked, token):
                print(f"❌ FATAL: Newest commit {commits[0][:8]} is not newer than last_checked {last_checked[:8]}", file=sys.stderr)
                print(f"❌ Aborting to prevent updating state to incorrect commit", file=sys.stderr)
                sys.exit(1)
        
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
                processing_errors += 1
                print(f"⚠️  Error checking commit {commit[:8]}: {e}", file=sys.stderr)
                if processing_errors > max_processing_errors:
                    print(f"❌ FATAL: Too many errors ({processing_errors}) during commit processing", file=sys.stderr)
                    print(f"❌ Aborting to prevent updating state incorrectly", file=sys.stderr)
                    sys.exit(1)
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
        
        # Update last_checked_commit to the newest commit (commits[0] is newest since GitHub API returns reverse chronological order)
        # This ensures we don't re-check commits we've already processed
        # IMPORTANT: commits[0] should always be HEAD (newest commit) when fetched from GitHub API
        # If last_checked was set, commits[0] is the first commit AFTER last_checked (i.e., newer)
        # If last_checked was None, commits[0] is HEAD (newest)
        # 
        # FAIL-SAFE: Only update if we didn't have too many processing errors
        # This prevents updating state when something went wrong
        if processing_errors > max_processing_errors:
            print(f"❌ FATAL: Too many processing errors ({processing_errors}). Not updating last_checked_commit to prevent incorrect state.", file=sys.stderr)
            sys.exit(1)
        
        newest_commit = commits[0]
        manager.update_last_checked_commit(newest_commit)
        print(f"✅ Updated last checked commit to {newest_commit[:8]} (newest commit from fetched batch)")
        
        if last_checked and last_checked != newest_commit:
            print(f"📝 Updated from {last_checked[:8]} to {newest_commit[:8]}")
    else:
        print("✅ No new commits to check")
        # If we reset due to old commit but got no commits, update to HEAD to prevent re-checking
        if old_commit_reset:
            print("⚠️  Old commit was reset but no commits found, fetching HEAD to update state")
            try:
                # Get HEAD commit to update state
                repo_path = repo_url.replace('https://github.com/', '').replace('.git', '')
                api_url = f"https://api.github.com/repos/{repo_path}/commits/HEAD"
                headers = {'Authorization': f'token {token}'} if token else {}
                response = requests.get(api_url, headers=headers, timeout=10)
                response.raise_for_status()
                head_commit = response.json().get('sha')
                if head_commit:
                    manager.update_last_checked_commit(head_commit)
                    print(f"✅ Updated last checked commit to HEAD: {head_commit[:8]}")
            except Exception as e:
                print(f"⚠️  Could not update last checked commit to HEAD: {e}", file=sys.stderr)
    
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
