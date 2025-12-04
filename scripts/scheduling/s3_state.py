#!/usr/bin/env python3
"""S3 State File Utilities - Read/write JSON state files from S3 with atomic operations"""

import json
import os
import sys
import time
from typing import Any, Callable, Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("Error: boto3 is required. Install with: pip install boto3", file=sys.stderr)
    sys.exit(1)


class S3StateError(Exception):
    pass


class S3StateNotFoundError(S3StateError):
    pass


class S3StateConflictError(S3StateError):
    pass


# Default state version - change this to switch versions (e.g., "v3" for next version)
DEFAULT_STATE_VERSION = "v2"


class S3StateManager:
    def __init__(self, bucket: str, solver: str, region: Optional[str] = None):
        self.bucket = bucket
        self.solver = solver
        self.region = region or os.getenv('AWS_REGION', 'eu-north-1')
        self.base_path = f"solvers/{solver}/fuzzing-state"
        try:
            self.s3_client = boto3.client('s3', region_name=self.region)
        except NoCredentialsError:
            raise S3StateError("AWS credentials not found. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
    
    def _get_s3_key(self, filename: str) -> str:
        return f"{self.base_path}/{filename}"
    
    def _get_versioned_filename(self, base_filename: str, version: Optional[str] = None) -> str:
        """Get versioned filename. If version is None, returns base_filename unchanged.
        
        Pattern:
        - state.json + v2 -> statev2.json
        - fuzzing-schedule.json + v2 -> fuzzing-schedulev2.json
        - build-queue.json + v2 -> build-queue-v2.json
        
        For v3+, uses same pattern: base + version + .json
        """
        if version is None:
            return base_filename
        
        # Handle special case: build-queue uses hyphen
        if base_filename == 'build-queue.json':
            return f"build-queue-{version}.json"
        
        # For other files, insert version before .json
        if base_filename.endswith('.json'):
            return base_filename[:-5] + version + '.json'
        
        # Fallback: append version
        return f"{base_filename}-{version}"
    
    def read_state(self, filename: str, default: Optional[Any] = None) -> Any:
        s3_key = self._get_s3_key(filename)
        try:
            response = self.s3_client.get_object(Bucket=self.bucket, Key=s3_key)
            return json.loads(response['Body'].read().decode('utf-8'))
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'NoSuchKey':
                if default is not None:
                    return default
                raise S3StateNotFoundError(f"State file not found: {s3_key}")
            raise S3StateError(f"Failed to read state file {s3_key}: {e}")
        except json.JSONDecodeError as e:
            raise S3StateError(f"Invalid JSON in state file {s3_key}: {e}")
    
    def write_state(self, filename: str, data: Any, retries: int = 3) -> None:
        s3_key = self._get_s3_key(filename)
        content = json.dumps(data, indent=2, sort_keys=True).encode('utf-8')
        for attempt in range(retries):
            try:
                self.s3_client.put_object(Bucket=self.bucket, Key=s3_key, Body=content, ContentType='application/json')
                return
            except (ClientError, Exception) as e:
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise S3StateError(f"Failed to write state file {s3_key} after {retries} attempts: {e}")
    
    def update_state(self, filename: str, update_fn: Callable[[Any], Any], 
                     default: Optional[Any] = None, max_retries: int = 5) -> Any:
        for attempt in range(max_retries):
            try:
                try:
                    current_data = self.read_state(filename, default=None)
                except S3StateNotFoundError:
                    current_data = default if default is not None else None
                    if current_data is None:
                        raise
                updated_data = update_fn(current_data)
                self.write_state(filename, updated_data, retries=1)
                return updated_data
            except S3StateError as e:
                if attempt < max_retries - 1:
                    time.sleep(0.1 * (2 ** attempt))
                    continue
                if 'concurrent' in str(e).lower() or 'conflict' in str(e).lower():
                    raise S3StateConflictError(f"State file {self._get_s3_key(filename)} was modified concurrently")
                raise
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(0.1 * (2 ** attempt))
                    continue
                raise S3StateError(f"Unexpected error updating state file {self._get_s3_key(filename)}: {e}")
        raise S3StateConflictError(f"Failed to update state file {self._get_s3_key(filename)} after {max_retries} attempts")
    
    def file_exists(self, filename: str) -> bool:
        try:
            self.s3_client.head_object(Bucket=self.bucket, Key=self._get_s3_key(filename))
            return True
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == '404':
                return False
            raise S3StateError(f"Error checking if state file exists {self._get_s3_key(filename)}: {e}")
    
    def delete_state(self, filename: str) -> None:
        try:
            self.s3_client.delete_object(Bucket=self.bucket, Key=self._get_s3_key(filename))
        except ClientError as e:
            raise S3StateError(f"Failed to delete state file {self._get_s3_key(filename)}: {e}")
    
    # Build queue operations (versioned core, defaults to DEFAULT_STATE_VERSION)
    def add_to_build_queue(self, commit_hash: str, version: Optional[str] = None) -> None:
        """Add commit to build queue (versioned).
        
        Args:
            commit_hash: Commit hash to add
            version: Version string (defaults to DEFAULT_STATE_VERSION, None for v1)
        """
        version = version if version is not None else DEFAULT_STATE_VERSION
        filename = self._get_versioned_filename('build-queue.json', version)
        def update(queue):
            if commit_hash not in queue.get('queue', []):
                queue.setdefault('queue', []).append(commit_hash)
            return queue
        self.update_state(filename, update, default={'queue': []})
    
    def remove_from_build_queue(self, commit_hash: str, version: Optional[str] = None) -> bool:
        """Remove commit from build queue (versioned). Returns True if removed, False if not found.
        
        Args:
            commit_hash: Commit hash to remove
            version: Version string (defaults to DEFAULT_STATE_VERSION, None for v1)
        """
        version = version if version is not None else DEFAULT_STATE_VERSION
        filename = self._get_versioned_filename('build-queue.json', version)
        queue = self.read_state(filename, default={'queue': []})
        if commit_hash in queue.get('queue', []):
            queue['queue'].remove(commit_hash)
            self.write_state(filename, queue)
            return True
        return False
    
    def clear_build_queue(self, version: Optional[str] = None) -> None:
        """Clear build queue (versioned) - remove all commits from queue.
        
        Args:
            version: Version string (defaults to DEFAULT_STATE_VERSION, None for v1)
        """
        version = version if version is not None else DEFAULT_STATE_VERSION
        filename = self._get_versioned_filename('build-queue.json', version)
        def update(queue):
            queue['queue'] = []
            return queue
        self.update_state(filename, update, default={'queue': []})
    
    def is_in_build_queue(self, commit_hash: str, version: Optional[str] = None) -> bool:
        """Check if commit is in build queue (versioned). Returns True if in queue, False otherwise.
        
        Args:
            commit_hash: Commit hash to check
            version: Version string (defaults to DEFAULT_STATE_VERSION, None for v1)
        """
        version = version if version is not None else DEFAULT_STATE_VERSION
        filename = self._get_versioned_filename('build-queue.json', version)
        queue = self.read_state(filename, default={'queue': []})
        return commit_hash in queue.get('queue', [])
    
    # Fuzzing schedule operations (versioned core, defaults to DEFAULT_STATE_VERSION)
    def add_to_fuzzing_schedule(self, commit_hash: str, version: Optional[str] = None) -> None:
        """Add commit to fuzzing schedule (versioned). If not already present, adds with fuzz_count=0.
        
        Args:
            commit_hash: Commit hash to add
            version: Version string (defaults to DEFAULT_STATE_VERSION, None for v1)
        """
        version = version if version is not None else DEFAULT_STATE_VERSION
        filename = self._get_versioned_filename('fuzzing-schedule.json', version)
        def update(schedule):
            schedule = schedule if isinstance(schedule, list) else []
            if not any(c.get('hash') == commit_hash for c in schedule):
                schedule.append({'hash': commit_hash, 'fuzz_count': 0})
            return schedule
        self.update_state(filename, update, default=[])
    
    def remove_from_fuzzing_schedule(self, commit_hash: str, version: Optional[str] = None) -> bool:
        """Remove commit from fuzzing schedule (versioned). Returns True if removed, False if not found.
        
        Args:
            commit_hash: Commit hash to remove
            version: Version string (defaults to DEFAULT_STATE_VERSION, None for v1)
        """
        version = version if version is not None else DEFAULT_STATE_VERSION
        filename = self._get_versioned_filename('fuzzing-schedule.json', version)
        schedule = self.get_fuzzing_schedule(version=version)
        original_len = len(schedule)
        schedule = [c for c in schedule if c.get('hash') != commit_hash]
        if len(schedule) < original_len:
            self.write_state(filename, schedule)
            return True
        return False
    
    def select_and_increment_least_fuzzed(self, version: Optional[str] = None) -> Optional[str]:
        """Atomically select the least-fuzzed commit and increment its fuzz_count (versioned).
        Returns the commit hash if found, None if schedule is empty.
        This prevents race conditions where multiple workflows select the same commit.
        
        Args:
            version: Version string (defaults to DEFAULT_STATE_VERSION, None for v1)
        """
        version = version if version is not None else DEFAULT_STATE_VERSION
        filename = self._get_versioned_filename('fuzzing-schedule.json', version)
        def update(schedule):
            schedule = schedule if isinstance(schedule, list) else []
            if not schedule:
                return schedule
            
            # Find minimum fuzz_count
            min_fuzz_count = min(c.get('fuzz_count', 0) for c in schedule)
            
            # Find first commit with minimum fuzz_count (oldest among least-fuzzed)
            for commit in schedule:
                if commit.get('fuzz_count', 0) == min_fuzz_count:
                    # Atomically increment fuzz_count
                    commit['fuzz_count'] = commit.get('fuzz_count', 0) + 1
                    return schedule
            
            return schedule
        
        schedule_before = self.get_fuzzing_schedule(version=version)
        if not schedule_before:
            return None
        
        # Find which commit will be selected (before increment)
        min_fuzz_count = min(c.get('fuzz_count', 0) for c in schedule_before)
        selected_commit = None
        for commit in schedule_before:
            if commit.get('fuzz_count', 0) == min_fuzz_count:
                selected_commit = commit.get('hash')
                break
        
        if selected_commit:
            # Atomically update: select and increment in one operation
            self.update_state(filename, update, default=[])
            return selected_commit
        
        return None
    
    def increment_fuzz_count(self, commit_hash: str, version: Optional[str] = None) -> bool:
        """Increment fuzz_count for a commit (versioned). Returns True if updated, False if not found.
        This is idempotent - if called multiple times, it will keep incrementing.
        
        Args:
            commit_hash: Commit hash to increment
            version: Version string (defaults to DEFAULT_STATE_VERSION, None for v1)
        """
        version = version if version is not None else DEFAULT_STATE_VERSION
        filename = self._get_versioned_filename('fuzzing-schedule.json', version)
        def update(schedule):
            schedule = schedule if isinstance(schedule, list) else []
            for commit in schedule:
                if commit.get('hash') == commit_hash:
                    commit['fuzz_count'] = commit.get('fuzz_count', 0) + 1
                    return schedule
            return schedule
        schedule_before = self.get_fuzzing_schedule(version=version)
        self.update_state(filename, update, default=[])
        return any(c.get('hash') == commit_hash for c in schedule_before)
    
    def get_fuzzing_schedule(self, version: Optional[str] = None) -> list:
        """Get fuzzing schedule (versioned).
        
        Args:
            version: Version string (defaults to DEFAULT_STATE_VERSION, None for v1)
        """
        version = version if version is not None else DEFAULT_STATE_VERSION
        filename = self._get_versioned_filename('fuzzing-schedule.json', version)
        return self.read_state(filename, default=[])
    
    # State operations (versioned core, defaults to DEFAULT_STATE_VERSION)
    def update_last_checked_commit(self, commit_hash: str, version: Optional[str] = None) -> None:
        """Update last checked commit in state file (versioned).
        
        Args:
            commit_hash: Commit hash to store
            version: Version string (defaults to DEFAULT_STATE_VERSION, None for v1)
        """
        version = version if version is not None else DEFAULT_STATE_VERSION
        filename = self._get_versioned_filename('state.json', version)
        self.update_state(filename, lambda s: {'last_checked_commit': commit_hash}, default={'last_checked_commit': None})
    
    def get_last_checked_commit(self, version: Optional[str] = None) -> Optional[str]:
        """Get last checked commit from state file (versioned).
        
        Args:
            version: Version string (defaults to DEFAULT_STATE_VERSION, None for v1)
        """
        version = version if version is not None else DEFAULT_STATE_VERSION
        filename = self._get_versioned_filename('state.json', version)
        state = self.read_state(filename, default={'last_checked_commit': None})
        return state.get('last_checked_commit')
    
    def get_latest_available_build(self, version: Optional[str] = None) -> Optional[str]:
        """Get the latest available build commit hash from S3.
        Lists all production builds and returns the most recent one (by LastModified timestamp).
        Returns None if no builds are available.
        
        Args:
            version: Version string (defaults to DEFAULT_STATE_VERSION, None for v1)
        """
        version = version if version is not None else DEFAULT_STATE_VERSION
        try:
            from botocore.exceptions import ClientError
            
            prefix = f"solvers/{self.solver}/builds/{version}/production/"
            
            # List all objects in the production builds directory
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=self.bucket, Prefix=prefix)
            
            latest_commit = None
            latest_time = None
            found_count = 0
            
            for page in pages:
                if 'Contents' not in page:
                    continue
                
                for obj in page['Contents']:
                    # Extract commit hash from key: solvers/{solver}/builds/{version}/production/{commit_hash}.tar.gz
                    key = obj['Key']
                    if key.endswith('.tar.gz'):
                        found_count += 1
                        # Extract commit hash (full 40-char hash)
                        commit_hash = key[len(prefix):-7]  # Remove prefix and .tar.gz
                        
                        # Use LastModified timestamp to find latest
                        last_modified = obj['LastModified']
                        
                        if latest_time is None or last_modified > latest_time:
                            latest_time = last_modified
                            latest_commit = commit_hash
            
            if found_count == 0:
                print(f"⚠️  No builds found in S3 at prefix: {prefix}", file=sys.stderr)
            else:
                print(f"✅ Found {found_count} build(s) in S3, latest: {latest_commit[:8] if latest_commit else 'None'}", file=sys.stderr)
            
            return latest_commit
        except Exception as e:
            # Check if it's a ClientError
            error_type = type(e).__name__
            if 'ClientError' in error_type or 'NoCredentialsError' in error_type:
                print(f"❌ S3 ClientError listing builds: {e}", file=sys.stderr)
                raise S3StateError(f"Failed to list builds from S3: {e}")
            else:
                print(f"❌ Unexpected error finding latest build: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc(file=sys.stderr)
                raise S3StateError(f"Unexpected error finding latest build: {e}")


def get_state_manager(solver: str) -> S3StateManager:
    bucket = os.getenv('AWS_S3_BUCKET')
    if not bucket:
        raise S3StateError("AWS_S3_BUCKET environment variable not set")
    return S3StateManager(bucket=bucket, solver=solver, region=os.getenv('AWS_REGION', 'eu-north-1'))


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='S3 State Management CLI')
    parser.add_argument('solver', choices=['z3', 'cvc5'], help='Solver name')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Build queue commands (defaults to v2)
    build_queue_parser = subparsers.add_parser('build-queue', help='Build queue operations (defaults to v2)')
    build_queue_sub = build_queue_parser.add_subparsers(dest='action')
    
    p = build_queue_sub.add_parser('add', help='Add commit to build queue')
    p.add_argument('commit', help='Commit hash')
    p = build_queue_sub.add_parser('remove', help='Remove commit from build queue')
    p.add_argument('commit', help='Commit hash')
    p = build_queue_sub.add_parser('clear', help='Clear build queue')
    p = build_queue_sub.add_parser('check', help='Check if commit is in build queue')
    p.add_argument('commit', help='Commit hash')
    
    # Fuzzing schedule commands (defaults to v2)
    fuzzing_parser = subparsers.add_parser('fuzzing-schedule', help='Fuzzing schedule operations (defaults to v2)')
    fuzzing_sub = fuzzing_parser.add_subparsers(dest='action')
    
    p = fuzzing_sub.add_parser('add', help='Add commit to fuzzing schedule')
    p.add_argument('commit', help='Commit hash')
    p = fuzzing_sub.add_parser('remove', help='Remove commit from fuzzing schedule')
    p.add_argument('commit', help='Commit hash')
    p = fuzzing_sub.add_parser('increment-fuzz-count', help='Increment fuzz count for commit')
    p.add_argument('commit', help='Commit hash')
    fuzzing_sub.add_parser('get', help='Get fuzzing schedule')
    
    # State commands (defaults to v2)
    state_parser = subparsers.add_parser('state', help='State operations (defaults to v2)')
    state_sub = state_parser.add_subparsers(dest='action')
    
    p = state_sub.add_parser('update-last-checked', help='Update last checked commit')
    p.add_argument('commit', help='Commit hash')
    state_sub.add_parser('get-last-checked', help='Get last checked commit')
    
    # Raw file operations (for debugging)
    raw_parser = subparsers.add_parser('raw', help='Raw file operations')
    raw_sub = raw_parser.add_subparsers(dest='action')
    p = raw_sub.add_parser('read', help='Read state file')
    p.add_argument('filename', help='State file name')
    p = raw_sub.add_parser('write', help='Write state file')
    p.add_argument('filename', help='State file name')
    p.add_argument('data', help='JSON data')
    p = raw_sub.add_parser('exists', help='Check if file exists')
    p.add_argument('filename', help='State file name')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        manager = get_state_manager(args.solver)
        
        if args.command == 'build-queue':
            if args.action == 'add':
                manager.add_to_build_queue(args.commit)
                print(f"✅ Added {args.commit} to build queue")
            elif args.action == 'remove':
                if manager.remove_from_build_queue(args.commit):
                    print(f"✅ Removed {args.commit} from build queue")
                else:
                    print(f"⚠️  {args.commit} not found in build queue")
            elif args.action == 'clear':
                manager.clear_build_queue()
                print(f"✅ Cleared build queue")
            elif args.action == 'check':
                try:
                    in_queue = manager.is_in_build_queue(args.commit)
                    if in_queue:
                        print("true", file=sys.stdout)
                        sys.stdout.flush()
                    else:
                        # Debug: check what's actually in the queue
                        queue = manager.read_state(manager._get_versioned_filename('build-queue.json', DEFAULT_STATE_VERSION), default={'queue': []})
                        queue_commits = queue.get('queue', [])
                        print(f"DEBUG: Checking commit {args.commit[:8]}", file=sys.stderr)
                        print(f"DEBUG: Queue has {len(queue_commits)} commit(s): {[c[:8] for c in queue_commits]}", file=sys.stderr)
                        print("false", file=sys.stdout)
                        sys.stdout.flush()
                except Exception as e:
                    print(f"ERROR in check: {e}", file=sys.stderr)
                    print("false", file=sys.stdout)
                    sys.stdout.flush()
                    raise
        
        elif args.command == 'fuzzing-schedule':
            if args.action == 'add':
                manager.add_to_fuzzing_schedule(args.commit)
                print(f"✅ Added {args.commit} to fuzzing schedule")
            elif args.action == 'remove':
                if manager.remove_from_fuzzing_schedule(args.commit):
                    print(f"✅ Removed {args.commit} from fuzzing schedule")
                else:
                    print(f"⚠️  {args.commit} not found in fuzzing schedule")
            elif args.action == 'increment-fuzz-count':
                if manager.increment_fuzz_count(args.commit):
                    print(f"✅ Incremented fuzz count for {args.commit}")
                else:
                    print(f"⚠️  {args.commit} not found in fuzzing schedule")
            elif args.action == 'get':
                schedule = manager.get_fuzzing_schedule()
                print(json.dumps(schedule, indent=2))
        
        elif args.command == 'state':
            if args.action == 'update-last-checked':
                manager.update_last_checked_commit(args.commit)
                print(f"✅ Updated last checked commit to {args.commit}")
            elif args.action == 'get-last-checked':
                commit = manager.get_last_checked_commit()
                print(commit if commit else "None")
        
        elif args.command == 'raw':
            if args.action == 'read':
                data = manager.read_state(args.filename, default={})
                print(json.dumps(data, indent=2))
            elif args.action == 'write':
                manager.write_state(args.filename, json.loads(args.data))
                print(f"✅ Written to {args.filename}")
            elif args.action == 'exists':
                exists = manager.file_exists(args.filename)
                print(f"File exists: {exists}")
        
    except S3StateError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        # If this was a check command, still output false
        if hasattr(args, 'action') and args.action == 'check':
            print("false", file=sys.stdout)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        # If this was a check command, still output false
        if hasattr(args, 'action') and args.action == 'check':
            print("false", file=sys.stdout)
        sys.exit(1)
