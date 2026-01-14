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
    
    print(f"📡 Fetching commits from GitHub: {repo_path}")
    print(f"   Parameters: since_commit={since_commit[:8] if since_commit else 'None'}, max_commits={max_commits}, token={'***' if token else 'None'}")
    
    commits = []
    page = 1
    while True:
        params['page'] = page
        try:
            print(f"   Fetching page {page}...", end='', flush=True)
            response = requests.get(api_url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            if not data:
                print(" (no more commits)")
                break
            
            print(f" (got {len(data)} commits)")
            for commit in data:
                commit_hash = commit['sha']
                
                # Stop if we've reached the last checked commit (we've seen all new commits)
                if since_commit and commit_hash == since_commit:
                    print(f"   ✅ Found last_checked commit {since_commit[:8]} on page {page}, stopping fetch")
                    return commits
                
                # Add commit to list (skip the last checked commit itself)
                if not (since_commit and commit_hash == since_commit):
                    commits.append(commit_hash)
                    
                    # Stop if we've reached max_commits limit
                    if max_commits and len(commits) >= max_commits:
                        print(f"   ⚠️  Reached max_commits limit ({max_commits}), stopping fetch")
                        return commits
            
            if len(data) < 100:
                print(f"   ✅ Reached end of commits (last page had {len(data)} commits)")
                break
            page += 1
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(f"   ⚠️  Repository not found (404), stopping")
                break
            print(f"   ❌ HTTP error: {e}", file=sys.stderr)
            raise RuntimeError(f"GitHub API error: {e}")
    
    print(f"📊 Total commits fetched: {len(commits)}")
    if commits:
        print(f"   First commit (newest): {commits[0][:8]}")
        print(f"   Last commit (oldest): {commits[-1][:8]}")
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
    print(f"🔍 Verifying commit order: {newer_commit[:8]} should be newer than {older_commit[:8]}")
    
    if requests is None:
        print(f"   ⚠️  requests library not available, skipping verification")
        return True  # Can't verify, assume correct to avoid blocking
    
    try:
        repo_path = repo_url.replace('https://github.com/', '').replace('.git', '')
        newer_date = None
        older_date = None
        
        # Get both commit dates
        for commit_hash, commit_type in [(newer_commit, "newer"), (older_commit, "older")]:
            print(f"   Fetching {commit_type} commit {commit_hash[:8]}...", end='', flush=True)
            api_url = f"https://api.github.com/repos/{repo_path}/commits/{commit_hash}"
            headers = {'Authorization': f'token {token}'} if token else {}
            
            response = requests.get(api_url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            commit_date_str = data.get('commit', {}).get('author', {}).get('date')
            if commit_date_str:
                commit_date = datetime.fromisoformat(commit_date_str.replace('Z', '+00:00'))
                print(f" date={commit_date.isoformat()}")
                if commit_type == "newer":
                    newer_date = commit_date
                else:
                    older_date = commit_date
            else:
                print(" (no date found)")
        
        # Verify we got both dates
        if newer_date is None or older_date is None:
            print(f"   ⚠️  Could not get commit dates for verification, assuming correct order", file=sys.stderr)
            return True
        
        # Verify newer_commit is actually newer
        if newer_date <= older_date:
            print(f"   ❌ VALIDATION FAILED: {newer_commit[:8]} ({newer_date}) is NOT newer than {older_commit[:8]} ({older_date})", file=sys.stderr)
            print(f"   ❌ Date difference: {older_date - newer_date if newer_date < older_date else newer_date - older_date}", file=sys.stderr)
            return False
        
        print(f"   ✅ Validation passed: {newer_commit[:8]} ({newer_date}) is newer than {older_commit[:8]} ({older_date})")
        print(f"   ✅ Date difference: {newer_date - older_date}")
        return True
    except Exception as e:
        print(f"   ⚠️  Error verifying commit order: {e}", file=sys.stderr)
        import traceback
        print(f"   Traceback: {traceback.format_exc()}", file=sys.stderr)
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
    print(f"📅 Checking age of commit {commit_hash[:8]} (max_age={max_age_days} days)")
    
    if requests is None:
        print(f"   ⚠️  requests library not available, assuming not too old")
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
            print(f"   Commit date: {commit_date.isoformat()}")
            print(f"   Age: {age_days} days")
            is_too_old = age_days > max_age_days
            if is_too_old:
                print(f"   ⚠️  Commit is too old ({age_days} days > {max_age_days} days)")
            else:
                print(f"   ✅ Commit age is acceptable ({age_days} days <= {max_age_days} days)")
            return is_too_old
        else:
            print(f"   ⚠️  Could not get commit date, assuming not too old")
            return False
    except Exception as e:
        print(f"   ⚠️  Error checking commit age for {commit_hash[:8]}: {e}", file=sys.stderr)
        import traceback
        print(f"   Traceback: {traceback.format_exc()}", file=sys.stderr)
        # If we can't check, assume it's not too old to be safe
        return False
    
    return False


def run_manager(solver: str, repo_url: str, token: Optional[str] = None):
    print(f"=" * 80)
    print(f"🚀 Starting manager for solver: {solver}")
    print(f"   Repository: {repo_url}")
    print(f"   Token: {'***' if token else 'None'}")
    print(f"=" * 80)
    
    manager = get_state_manager(solver)
    print(f"📂 State manager initialized for solver: {solver}")
    
    last_checked = manager.get_last_checked_commit()
    print(f"📋 Last checked commit from state: {last_checked or 'None'}")
    
    # Check if last_checked commit is too old (e.g., > 30 days)
    # If too old, treat as "starting fresh" to avoid fetching thousands of commits
    old_commit_reset = False
    if last_checked:
        print(f"\n🔍 Checking if last_checked commit is too old...")
        is_too_old = check_if_commit_too_old(repo_url, last_checked, token, max_age_days=30)
        if is_too_old:
            print(f"\n⚠️  Last checked commit {last_checked[:8]} is too old (>30 days), resetting to start fresh")
            old_commit_reset = True
            last_checked = None
            print(f"   ✅ Reset last_checked to None (will start fresh)")
            # Note: We'll update last_checked_commit at the end with the new commit
        else:
            print(f"   ✅ Last checked commit is recent enough, continuing with it")
    else:
        print(f"   ℹ️  No last_checked commit found, starting fresh")
    
    # Always limit max_commits to prevent fetching too many commits
    # Even if last_checked exists, limit to reasonable number to avoid rate limits
    max_commits = 200 if last_checked else 100
    print(f"\n📊 Commit fetch configuration:")
    print(f"   max_commits: {max_commits}")
    print(f"   since_commit: {last_checked[:8] if last_checked else 'None (starting from HEAD)'}")
    
    try:
        print(f"\n📡 Fetching commits from GitHub...")
        commits = get_commits_from_github(repo_url, last_checked, token, max_commits=max_commits)
    except Exception as e:
        print(f"\n❌ FATAL: Error getting commits: {e}", file=sys.stderr)
        import traceback
        print(f"Traceback:\n{traceback.format_exc()}", file=sys.stderr)
        sys.exit(1)
    
    # Track NEW commits added from GitHub
    new_commits_added_to_schedule = []
    
    # Track errors during processing - if too many, fail rather than update state incorrectly
    processing_errors = 0
    max_processing_errors = 10  # Allow some errors (rate limits, etc.) but fail if too many
    
    # Process new commits from GitHub
    if commits:
        print(f"\n📝 Processing {len(commits)} commit(s) to check for C++ changes...")
        
        # CRITICAL VALIDATION: If we had a last_checked commit, verify commits[0] is actually newer
        # This prevents updating to an old commit if something went wrong
        if last_checked and commits[0] != last_checked:
            print(f"\n🔍 CRITICAL VALIDATION: Verifying commit order...")
            if not verify_commit_is_newer(repo_url, commits[0], last_checked, token):
                print(f"\n❌ FATAL: Validation failed - newest commit {commits[0][:8]} is not newer than last_checked {last_checked[:8]}", file=sys.stderr)
                print(f"❌ Aborting to prevent updating state to incorrect commit", file=sys.stderr)
                sys.exit(1)
            print(f"   ✅ Validation passed, continuing...")
        elif last_checked and commits[0] == last_checked:
            print(f"   ⚠️  WARNING: commits[0] equals last_checked, this shouldn't happen")
        
        print(f"\n🔍 Checking commits for C++ changes...")
        new_commits_with_cpp = []
        for idx, commit in enumerate(commits, 1):
            print(f"   [{idx}/{len(commits)}] Checking {commit[:8]}...", end='', flush=True)
            try:
                has_cpp, changed_files = detect_cpp_changes(repo_url, commit, token)
                if has_cpp:
                    print(f" ✅ C++ changes ({len(changed_files)} files)")
                    new_commits_with_cpp.append(commit)
                else:
                    print(f" ⏭️  No C++ changes")
            except Exception as e:
                processing_errors += 1
                print(f" ❌ ERROR: {e}", file=sys.stderr)
                print(f"   Error count: {processing_errors}/{max_processing_errors}", file=sys.stderr)
                if processing_errors > max_processing_errors:
                    print(f"\n❌ FATAL: Too many errors ({processing_errors}) during commit processing", file=sys.stderr)
                    print(f"❌ Aborting to prevent updating state incorrectly", file=sys.stderr)
                    import traceback
                    print(f"Last error traceback:\n{traceback.format_exc()}", file=sys.stderr)
                    sys.exit(1)
                continue
        
        print(f"\n📊 Summary: Found {len(new_commits_with_cpp)} commit(s) with C++ changes out of {len(commits)} total")
        
        # When starting fresh (no last_checked), limit to last 4 commits with C++ changes
        # Note: commits come from GitHub API in reverse chronological order (newest first)
        # So [:4] gets the 4 newest commits with C++ changes
        if not last_checked and new_commits_with_cpp:
            if len(new_commits_with_cpp) > 4:
                print(f"\n📋 Starting fresh: limiting to last 4 commits with C++ changes (found {len(new_commits_with_cpp)})")
                print(f"   Keeping: {', '.join([c[:8] for c in new_commits_with_cpp[:4]])}")
                new_commits_with_cpp = new_commits_with_cpp[:4]  # Keep first 4 (newest)
        
        if new_commits_with_cpp:
            print(f"\n📦 Adding commits to queues...")
            # Add ONLY the latest commit to build queue
            # Commits are in reverse chronological order (newest first), so [0] is the latest
            latest_commit = new_commits_with_cpp[0]  # First in list is latest (newest)
            print(f"   Adding latest commit {latest_commit[:8]} to build queue...", end='', flush=True)
            try:
                manager.add_to_build_queue(latest_commit)
                print(f" ✅")
            except Exception as e:
                print(f" ❌ ERROR: {e}", file=sys.stderr)
                import traceback
                print(f"   Traceback: {traceback.format_exc()}", file=sys.stderr)
            
            # Add ALL commits with C++ changes directly to fuzzing schedule
            print(f"   Adding {len(new_commits_with_cpp)} commit(s) to fuzzing schedule...")
            for commit in new_commits_with_cpp:
                print(f"     Adding {commit[:8]}...", end='', flush=True)
                try:
                    manager.add_to_fuzzing_schedule(commit)
                    new_commits_added_to_schedule.append(commit)
                    print(f" ✅")
                except Exception as e:
                    print(f" ❌ ERROR: {e}", file=sys.stderr)
                    import traceback
                    print(f"       Traceback: {traceback.format_exc()}", file=sys.stderr)
        
        # Update last_checked_commit to the newest commit (commits[0] is newest since GitHub API returns reverse chronological order)
        # This ensures we don't re-check commits we've already processed
        # IMPORTANT: commits[0] should always be HEAD (newest commit) when fetched from GitHub API
        # If last_checked was set, commits[0] is the first commit AFTER last_checked (i.e., newer)
        # If last_checked was None, commits[0] is HEAD (newest)
        # 
        # FAIL-SAFE: Only update if we didn't have too many processing errors
        # This prevents updating state when something went wrong
        print(f"\n💾 Updating last_checked_commit state...")
        print(f"   Processing errors: {processing_errors}/{max_processing_errors}")
        
        if processing_errors > max_processing_errors:
            print(f"❌ FATAL: Too many processing errors ({processing_errors}). Not updating last_checked_commit to prevent incorrect state.", file=sys.stderr)
            sys.exit(1)
        
        newest_commit = commits[0]
        print(f"   Updating to: {newest_commit[:8]} (commits[0] from fetched batch)")
        if last_checked:
            print(f"   Previous value: {last_checked[:8]}")
        
        try:
            manager.update_last_checked_commit(newest_commit)
            print(f"   ✅ Successfully updated last_checked_commit to {newest_commit[:8]}")
            if last_checked and last_checked != newest_commit:
                print(f"   📝 State transition: {last_checked[:8]} → {newest_commit[:8]}")
        except Exception as e:
            print(f"   ❌ ERROR updating last_checked_commit: {e}", file=sys.stderr)
            import traceback
            print(f"   Traceback: {traceback.format_exc()}", file=sys.stderr)
            raise
    else:
        print(f"\n✅ No new commits to check")
        # If we reset due to old commit but got no commits, update to HEAD to prevent re-checking
        if old_commit_reset:
            print(f"\n⚠️  Old commit was reset but no commits found, fetching HEAD to update state")
            try:
                # Get HEAD commit to update state
                repo_path = repo_url.replace('https://github.com/', '').replace('.git', '')
                api_url = f"https://api.github.com/repos/{repo_path}/commits/HEAD"
                headers = {'Authorization': f'token {token}'} if token else {}
                print(f"   Fetching HEAD commit...", end='', flush=True)
                response = requests.get(api_url, headers=headers, timeout=10)
                response.raise_for_status()
                head_commit = response.json().get('sha')
                if head_commit:
                    print(f" {head_commit[:8]}")
                    print(f"   Updating last_checked_commit to HEAD...", end='', flush=True)
                    manager.update_last_checked_commit(head_commit)
                    print(f" ✅")
                else:
                    print(f" ❌ No SHA found in response")
            except Exception as e:
                print(f" ❌ ERROR: {e}", file=sys.stderr)
                import traceback
                print(f"   Traceback: {traceback.format_exc()}", file=sys.stderr)
    
    # Manage fuzzing schedule size when adding NEW commits from GitHub
    # If schedule has 4+ commits and we're adding new ones, remove oldest fuzzed commit
    print(f"\n📋 Managing fuzzing schedule size...")
    schedule = manager.get_fuzzing_schedule()
    print(f"   Current schedule size: {len(schedule)} commit(s)")
    print(f"   New commits added: {len(new_commits_added_to_schedule)}")
    
    if new_commits_added_to_schedule and len(schedule) >= 4:
        print(f"   Schedule is full ({len(schedule)} >= 4), looking for oldest fuzzed commit to remove...")
        # Find oldest fuzzed commit (first in list with fuzz_count > 0)
        oldest_fuzzed = None
        for commit_info in schedule:
            if commit_info.get('fuzz_count', 0) > 0:
                oldest_fuzzed = commit_info['hash']
                print(f"   Found oldest fuzzed commit: {oldest_fuzzed[:8]} (fuzz_count={commit_info.get('fuzz_count', 0)})")
                break
        
        if oldest_fuzzed:
            print(f"   Removing {oldest_fuzzed[:8]} from schedule...", end='', flush=True)
            try:
                manager.remove_from_fuzzing_schedule(oldest_fuzzed)
                print(f" ✅")
            except Exception as e:
                print(f" ❌ ERROR: {e}", file=sys.stderr)
                import traceback
                print(f"   Traceback: {traceback.format_exc()}", file=sys.stderr)
        else:
            print(f"   ℹ️  No fuzzed commits found to remove")
    else:
        print(f"   ℹ️  No schedule cleanup needed (schedule size: {len(schedule)}, new commits: {len(new_commits_added_to_schedule)})")
    
    print(f"\n" + "=" * 80)
    print(f"✅ Manager completed successfully")
    print(f"=" * 80)


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
