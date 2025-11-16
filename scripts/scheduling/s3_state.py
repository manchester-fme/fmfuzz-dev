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
    
    # Build queue operations
    def add_to_build_queue(self, commit_hash: str) -> None:
        """Add commit to build queue"""
        def update(queue):
            if commit_hash not in queue.get('queue', []):
                queue.setdefault('queue', []).append(commit_hash)
            return queue
        self.update_state('build-queue.json', update, default={'queue': [], 'built': [], 'failed': []})
    
    def remove_from_build_queue(self, commit_hash: str) -> bool:
        """Remove commit from build queue. Returns True if removed, False if not found"""
        queue = self.read_state('build-queue.json', default={'queue': [], 'built': [], 'failed': []})
        if commit_hash in queue.get('queue', []):
            queue['queue'].remove(commit_hash)
            self.write_state('build-queue.json', queue)
            return True
        return False
    
    def move_to_built(self, commit_hash: str) -> bool:
        """Move commit from queue to built. Returns True if moved, False if not in queue"""
        def update(queue):
            queue.setdefault('queue', [])
            queue.setdefault('built', [])
            if commit_hash in queue['queue']:
                queue['queue'].remove(commit_hash)
                if commit_hash not in queue['built']:
                    queue['built'].append(commit_hash)
            return queue
        queue_before = self.read_state('build-queue.json', default={'queue': [], 'built': [], 'failed': []})
        was_in_queue = commit_hash in queue_before.get('queue', [])
        self.update_state('build-queue.json', update, default={'queue': [], 'built': [], 'failed': []})
        return was_in_queue
    
    def move_to_failed(self, commit_hash: str) -> bool:
        """Move commit from queue to failed. Returns True if moved, False if not in queue"""
        def update(queue):
            queue.setdefault('queue', [])
            queue.setdefault('failed', [])
            if commit_hash in queue['queue']:
                queue['queue'].remove(commit_hash)
                if commit_hash not in queue['failed']:
                    queue['failed'].append(commit_hash)
            return queue
        queue_before = self.read_state('build-queue.json', default={'queue': [], 'built': [], 'failed': []})
        was_in_queue = commit_hash in queue_before.get('queue', [])
        self.update_state('build-queue.json', update, default={'queue': [], 'built': [], 'failed': []})
        return was_in_queue
    
    def get_built_commits(self) -> list:
        """Get list of commits in 'built' array"""
        queue = self.read_state('build-queue.json', default={'queue': [], 'built': [], 'failed': []})
        return queue.get('built', [])
    
    def remove_from_built(self, commit_hash: str) -> bool:
        """Remove commit from built array. Returns True if removed, False if not found"""
        queue = self.read_state('build-queue.json', default={'queue': [], 'built': [], 'failed': []})
        if commit_hash in queue.get('built', []):
            queue['built'].remove(commit_hash)
            self.write_state('build-queue.json', queue)
            return True
        return False
    
    # Fuzzing schedule operations
    def add_to_fuzzing_schedule(self, commit_hash: str) -> None:
        """Add commit to fuzzing schedule (if not already present)"""
        def update(schedule):
            schedule = schedule if isinstance(schedule, list) else []
            if not any(c.get('hash') == commit_hash for c in schedule):
                schedule.append({'hash': commit_hash, 'fuzz_count': 0})
            return schedule
        self.update_state('fuzzing-schedule.json', update, default=[])
    
    def remove_from_fuzzing_schedule(self, commit_hash: str) -> bool:
        """Remove commit from fuzzing schedule. Returns True if removed, False if not found"""
        schedule = self.get_fuzzing_schedule()
        original_len = len(schedule)
        schedule = [c for c in schedule if c.get('hash') != commit_hash]
        if len(schedule) < original_len:
            self.write_state('fuzzing-schedule.json', schedule)
            return True
        return False
    
    def increment_fuzz_count(self, commit_hash: str) -> bool:
        """Increment fuzz_count for a commit. Returns True if updated, False if not found"""
        def update(schedule):
            schedule = schedule if isinstance(schedule, list) else []
            for commit in schedule:
                if commit.get('hash') == commit_hash:
                    commit['fuzz_count'] = commit.get('fuzz_count', 0) + 1
                    return schedule
            return schedule
        schedule_before = self.get_fuzzing_schedule()
        self.update_state('fuzzing-schedule.json', update, default=[])
        return any(c.get('hash') == commit_hash for c in schedule_before)
    
    def get_fuzzing_schedule(self) -> list:
        """Get fuzzing schedule"""
        return self.read_state('fuzzing-schedule.json', default=[])
    
    # State operations
    def update_last_checked_commit(self, commit_hash: str) -> None:
        """Update last checked commit in state.json"""
        self.update_state('state.json', lambda s: {'last_checked_commit': commit_hash}, default={'last_checked_commit': None})
    
    def get_last_checked_commit(self) -> Optional[str]:
        """Get last checked commit from state.json"""
        state = self.read_state('state.json', default={'last_checked_commit': None})
        return state.get('last_checked_commit')


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
    
    # Build queue commands
    build_queue_parser = subparsers.add_parser('build-queue', help='Build queue operations')
    build_queue_sub = build_queue_parser.add_subparsers(dest='action')
    
    build_queue_sub.add_parser('add', help='Add commit to build queue').add_argument('commit', help='Commit hash')
    build_queue_sub.add_parser('remove', help='Remove commit from build queue').add_argument('commit', help='Commit hash')
    build_queue_sub.add_parser('move-to-built', help='Move commit from queue to built').add_argument('commit', help='Commit hash')
    build_queue_sub.add_parser('move-to-failed', help='Move commit from queue to failed').add_argument('commit', help='Commit hash')
    build_queue_sub.add_parser('get-built', help='Get list of built commits')
    build_queue_sub.add_parser('remove-from-built', help='Remove commit from built array').add_argument('commit', help='Commit hash')
    
    # Fuzzing schedule commands
    fuzzing_parser = subparsers.add_parser('fuzzing-schedule', help='Fuzzing schedule operations')
    fuzzing_sub = fuzzing_parser.add_subparsers(dest='action')
    
    fuzzing_sub.add_parser('add', help='Add commit to fuzzing schedule').add_argument('commit', help='Commit hash')
    fuzzing_sub.add_parser('remove', help='Remove commit from fuzzing schedule').add_argument('commit', help='Commit hash')
    fuzzing_sub.add_parser('increment-fuzz-count', help='Increment fuzz count for commit').add_argument('commit', help='Commit hash')
    fuzzing_sub.add_parser('get', help='Get fuzzing schedule')
    
    # State commands
    state_parser = subparsers.add_parser('state', help='State operations')
    state_sub = state_parser.add_subparsers(dest='action')
    
    state_sub.add_parser('update-last-checked', help='Update last checked commit').add_argument('commit', help='Commit hash')
    state_sub.add_parser('get-last-checked', help='Get last checked commit')
    
    # Raw file operations (for debugging)
    raw_parser = subparsers.add_parser('raw', help='Raw file operations')
    raw_sub = raw_parser.add_subparsers(dest='action')
    raw_sub.add_parser('read', help='Read state file').add_argument('filename', help='State file name')
    raw_sub.add_parser('write', help='Write state file').add_argument('filename', help='State file name').add_argument('data', help='JSON data')
    raw_sub.add_parser('exists', help='Check if file exists').add_argument('filename', help='State file name')
    
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
            elif args.action == 'move-to-built':
                if manager.move_to_built(args.commit):
                    print(f"✅ Moved {args.commit} to built")
                else:
                    print(f"⚠️  {args.commit} not found in queue")
            elif args.action == 'move-to-failed':
                if manager.move_to_failed(args.commit):
                    print(f"✅ Moved {args.commit} to failed")
                else:
                    print(f"⚠️  {args.commit} not found in queue")
            elif args.action == 'get-built':
                commits = manager.get_built_commits()
                print(json.dumps(commits, indent=2))
            elif args.action == 'remove-from-built':
                if manager.remove_from_built(args.commit):
                    print(f"✅ Removed {args.commit} from built")
                else:
                    print(f"⚠️  {args.commit} not found in built")
        
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
        sys.exit(1)
