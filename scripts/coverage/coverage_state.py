#!/usr/bin/env python3
"""
Manage coverage test count state in S3.
Determines when to rebuild coverage mappings based on test count changes and time elapsed.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import boto3
from botocore.exceptions import ClientError


class CoverageStateManager:
    """
    Manages coverage state stored in S3 to determine when full coverage rebuilds are needed.

    State is stored at: s3://{bucket}/solvers/{solver}/coverage-state/test-count-state.json
    """

    STATE_FILE_NAME = 'test-count-state.json'
    SCHEMA_VERSION = '1.0'
    REBUILD_THRESHOLD_DAYS = 30

    def __init__(self, bucket: str, solver: str, region: str = 'us-east-1'):
        """
        Initialize state manager.

        Args:
            bucket: S3 bucket name
            solver: Solver name (cvc5 or z3)
            region: AWS region
        """
        self.bucket = bucket
        self.solver = solver
        self.region = region
        self.s3_key = f"solvers/{solver}/coverage-state/{self.STATE_FILE_NAME}"

        # Initialize S3 client
        self.s3_client = boto3.client('s3', region_name=region)

    def get_state(self) -> Optional[Dict]:
        """
        Download current state from S3.

        Returns:
            State dictionary if exists, None otherwise
        """
        try:
            response = self.s3_client.get_object(Bucket=self.bucket, Key=self.s3_key)
            state_json = response['Body'].read().decode('utf-8')
            state = json.loads(state_json)

            # Validate schema
            required_fields = ['test_count', 'last_build_timestamp', 'commit_hash', 'solver_version']
            if not all(field in state for field in required_fields):
                print(f"Warning: State file missing required fields, treating as corrupted", file=sys.stderr)
                return None

            return state

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                print(f"No existing state found at s3://{self.bucket}/{self.s3_key}", file=sys.stderr)
                return None
            else:
                print(f"Warning: Failed to download state: {e}", file=sys.stderr)
                return None
        except json.JSONDecodeError as e:
            print(f"Warning: State file contains invalid JSON: {e}", file=sys.stderr)
            return None

    def should_rebuild(self, current_test_count: int) -> Dict:
        """
        Determine if coverage mapping should be rebuilt.

        Decision logic:
        1. No state file exists → REBUILD (first run)
        2. Test count > old count → REBUILD (new tests added)
        3. Days since last > 30 → REBUILD (safety net)
        4. Test count < old count → REBUILD (tests removed, investigate)
        5. Otherwise → SKIP (no changes, <30 days)

        Args:
            current_test_count: Current number of tests

        Returns:
            Dictionary with:
                - should_rebuild: bool
                - reason: str
                - old_count: int (or None)
                - new_count: int
                - days_since_last: float (or None)
        """
        state = self.get_state()

        # Case 1: No state file exists (first run or error downloading)
        if state is None:
            return {
                'should_rebuild': True,
                'reason': 'First coverage build (no state file)',
                'old_count': None,
                'new_count': current_test_count,
                'days_since_last': None
            }

        old_test_count = state['test_count']
        last_build_timestamp = datetime.fromisoformat(state['last_build_timestamp'].replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        days_since_last = (now - last_build_timestamp).total_seconds() / 86400

        # Case 2: Test count increased (new tests added)
        if current_test_count > old_test_count:
            return {
                'should_rebuild': True,
                'reason': f'Test count increased: {old_test_count} → {current_test_count} (+{current_test_count - old_test_count})',
                'old_count': old_test_count,
                'new_count': current_test_count,
                'days_since_last': days_since_last
            }

        # Case 3: 30-day threshold exceeded (safety net)
        if days_since_last > self.REBUILD_THRESHOLD_DAYS:
            return {
                'should_rebuild': True,
                'reason': f'30-day threshold exceeded ({days_since_last:.1f} days since last build)',
                'old_count': old_test_count,
                'new_count': current_test_count,
                'days_since_last': days_since_last
            }

        # Case 4: Test count decreased (tests removed/disabled)
        if current_test_count < old_test_count:
            return {
                'should_rebuild': True,
                'reason': f'Test count decreased: {old_test_count} → {current_test_count} (-{old_test_count - current_test_count})',
                'old_count': old_test_count,
                'new_count': current_test_count,
                'days_since_last': days_since_last
            }

        # Case 5: No changes, skip rebuild
        return {
            'should_rebuild': False,
            'reason': f'No changes (count={current_test_count}, last_build={days_since_last:.1f} days ago)',
            'old_count': old_test_count,
            'new_count': current_test_count,
            'days_since_last': days_since_last
        }

    def update_state(self, test_count: int, commit_hash: str, solver_version: str = 'main',
                     updated_by: str = 'coverage-mapper') -> None:
        """
        Update state after successful coverage build.

        Args:
            test_count: Number of tests in the build
            commit_hash: Solver commit hash
            solver_version: Solver version/branch
            updated_by: Workflow/script that updated the state
        """
        now = datetime.now(timezone.utc)

        state = {
            'test_count': test_count,
            'last_build_timestamp': now.isoformat().replace('+00:00', 'Z'),
            'commit_hash': commit_hash,
            'solver_version': solver_version,
            'updated_by': updated_by,
            'schema_version': self.SCHEMA_VERSION
        }

        try:
            state_json = json.dumps(state, indent=2)
            self.s3_client.put_object(
                Bucket=self.bucket,
                Key=self.s3_key,
                Body=state_json.encode('utf-8'),
                ContentType='application/json'
            )
            print(f"✅ Updated coverage state: {test_count} tests at commit {commit_hash[:8]}", file=sys.stderr)

        except ClientError as e:
            print(f"Error: Failed to update state: {e}", file=sys.stderr)
            raise


def main():
    parser = argparse.ArgumentParser(
        description='Manage coverage test count state in S3',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check if rebuild needed
  python3 scripts/coverage/coverage_state.py cvc5 check --test-count 12345 --output decision.json

  # Update state after successful build
  python3 scripts/coverage/coverage_state.py cvc5 update --test-count 12345 --commit-hash abc123

  # Get current state (debugging)
  python3 scripts/coverage/coverage_state.py cvc5 get

Environment variables:
  AWS_S3_BUCKET: S3 bucket name (required)
  AWS_REGION: AWS region (default: us-east-1)
        """
    )

    parser.add_argument(
        'solver',
        choices=['cvc5', 'z3'],
        help='Solver name'
    )

    parser.add_argument(
        'command',
        choices=['check', 'update', 'get'],
        help='Command to execute'
    )

    parser.add_argument(
        '--test-count',
        type=int,
        help='Current test count (required for check and update)'
    )

    parser.add_argument(
        '--commit-hash',
        help='Solver commit hash (required for update)'
    )

    parser.add_argument(
        '--solver-version',
        default='main',
        help='Solver version/branch (default: main)'
    )

    parser.add_argument(
        '--updated-by',
        default='coverage-mapper',
        help='Workflow/script updating the state (default: coverage-mapper)'
    )

    parser.add_argument(
        '--output',
        type=Path,
        help='Output JSON file path (prints to stdout if not specified)'
    )

    args = parser.parse_args()

    # Get AWS configuration from environment
    bucket = os.environ.get('AWS_S3_BUCKET')
    if not bucket:
        print("Error: AWS_S3_BUCKET environment variable is required", file=sys.stderr)
        return 1

    region = os.environ.get('AWS_REGION', 'us-east-1')

    # Initialize state manager
    manager = CoverageStateManager(bucket=bucket, solver=args.solver, region=region)

    # Execute command
    if args.command == 'get':
        state = manager.get_state()
        if state:
            output_json = json.dumps(state, indent=2)
            if args.output:
                args.output.write_text(output_json)
            else:
                print(output_json)
        else:
            print("No state file exists", file=sys.stderr)
            return 1

    elif args.command == 'check':
        if args.test_count is None:
            parser.error('--test-count is required for check command')

        decision = manager.should_rebuild(args.test_count)

        # Print decision summary to stderr
        if decision['should_rebuild']:
            print(f"✅ Decision: REBUILD - {decision['reason']}", file=sys.stderr)
        else:
            print(f"⏭️  Decision: SKIP - {decision['reason']}", file=sys.stderr)

        # Output full decision JSON
        output_json = json.dumps(decision, indent=2)
        if args.output:
            args.output.write_text(output_json)
        else:
            print(output_json)

    elif args.command == 'update':
        if args.test_count is None:
            parser.error('--test-count is required for update command')
        if not args.commit_hash:
            parser.error('--commit-hash is required for update command')

        manager.update_state(
            test_count=args.test_count,
            commit_hash=args.commit_hash,
            solver_version=args.solver_version,
            updated_by=args.updated_by
        )

    return 0


if __name__ == '__main__':
    sys.exit(main())
