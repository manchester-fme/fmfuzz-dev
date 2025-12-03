#!/usr/bin/env python3
"""Manager job - checks commits, updates build queue and fuzzing schedule"""

import os
import sys
from datetime import datetime, timezone
from typing import List, Optional

scripts_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, scripts_dir)

from scheduling.s3_state import get_state_manager, S3StateError
from scheduling.detect_cpp_changes import detect_cpp_changes

try:
    import requests
except ImportError:
    requests = None

try:
    import boto3
except ImportError:
    boto3 = None


def get_commits_from_github(repo_url: str, since_commit: Optional[str] = None, token: Optional[str] = None) -> List[str]:
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
    
    try:
        commits = get_commits_from_github(repo_url, last_checked, token)
    except Exception as e:
        print(f"❌ Error getting commits: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Check built commits and move to fuzzing schedule (even if no new commits)
    built_commits = manager.get_built_commits()
    new_commits_added_to_schedule = []
    if boto3:
        from botocore.exceptions import ClientError
        for commit in built_commits:
            try:
                s3_key = f"solvers/{solver}/builds/production/{commit}.tar.gz"
                manager.s3_client.head_object(Bucket=manager.bucket, Key=s3_key)
                manager.add_to_fuzzing_schedule(commit)
                manager.remove_from_built(commit)
                new_commits_added_to_schedule.append(commit)
                print(f"✅ Moved {commit[:8]} to fuzzing schedule")
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == '404':
                    print(f"⚠️  Binary not found for {commit[:8]}")
                else:
                    print(f"❌ Error processing {commit[:8]}: {e}", file=sys.stderr)
            except Exception as e:
                print(f"❌ Error processing {commit[:8]}: {e}", file=sys.stderr)
    
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
        
        if new_commits_with_cpp:
            # Clear build queue v2 when new commits arrive (optimization)
            manager.clear_build_queue_v2()
            print("🧹 Cleared build queue v2")
            
            # Add ONLY the latest commit to build queue v2
            latest_commit = new_commits_with_cpp[-1]  # Last in list is latest
            try:
                manager.add_to_build_queue_v2(latest_commit)
                print(f"✅ Added latest commit {latest_commit[:8]} to build queue v2")
            except Exception as e:
                print(f"❌ Error adding latest commit to build queue: {e}", file=sys.stderr)
            
            # Add ALL commits with C++ changes directly to fuzzing schedule
            # Assumption: We'll have time to build latest commit and use it for next fuzzing
            newly_added_commits = set()
            for commit in new_commits_with_cpp:
                try:
                    manager.add_to_fuzzing_schedule(commit)
                    newly_added_commits.add(commit)
                    print(f"✅ Added {commit[:8]} to fuzzing schedule")
                except Exception as e:
                    print(f"❌ Error adding {commit[:8]} to fuzzing schedule: {e}", file=sys.stderr)
        else:
            newly_added_commits = set()
        
        manager.update_last_checked_commit(commits[0])
        print(f"✅ Updated last checked commit to {commits[0][:8]}")
    else:
        print("✅ No new commits to check")
        newly_added_commits = set()
    
    # Clean up commits from fuzzing schedule if binaries are missing (7-day lifecycle)
    # Skip binary check for commits that were just added or are in build queue (being built)
    schedule = manager.get_fuzzing_schedule()
    if boto3:
        from botocore.exceptions import ClientError
        commits_to_remove = []
        # Get current build queue to check if commits are being built
        build_queue = manager.read_state('build-queue-v2.json', default={'queue': [], 'built': [], 'failed': []})
        build_queue_commits = set(build_queue.get('queue', []))
        
        for commit_info in schedule:
            commit_hash = commit_info['hash']
            # Skip binary check for commits that were just added in this run
            if commit_hash in newly_added_commits:
                continue
            # Skip binary check for commits that are in build queue (being built)
            if commit_hash in build_queue_commits:
                continue
            try:
                s3_key = f"solvers/{solver}/builds/production/{commit_hash}.tar.gz"
                manager.s3_client.head_object(Bucket=manager.bucket, Key=s3_key)
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == '404':
                    commits_to_remove.append(commit_hash)
                    print(f"⚠️  Binary missing for {commit_hash[:8]}, removing from schedule")
        
        for commit_hash in commits_to_remove:
            manager.remove_from_fuzzing_schedule(commit_hash)
        schedule = manager.get_fuzzing_schedule()
    
    # Manage fuzzing schedule size only when adding new commits
    # If schedule has 4+ commits and we're adding new ones, remove oldest fuzzed commit
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
