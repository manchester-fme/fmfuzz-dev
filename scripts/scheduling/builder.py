#!/usr/bin/env python3
"""Builder job - checks build queue and returns next commit to build"""

import os
import sys
from typing import Optional

scripts_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, scripts_dir)

from scheduling.s3_state import get_state_manager, S3StateError


def get_next_commit_to_build(solver: str) -> Optional[str]:
    """Get the next commit from build queue. Returns None if queue is empty."""
    manager = get_state_manager(solver)
    queue = manager.read_state('build-queue.json', default={'queue': [], 'built': [], 'failed': []})
    queue_list = queue.get('queue', [])
    return queue_list[0] if queue_list else None


def run_builder(solver: str) -> Optional[str]:
    """Run builder check - returns commit hash if available, None otherwise."""
    try:
        commit = get_next_commit_to_build(solver)
        if commit:
            print(f"✅ Found commit in queue: {commit}", file=sys.stderr)
            return commit
        else:
            print("⏭️  No commits in build queue", file=sys.stderr)
            return None
    except S3StateError as e:
        print(f"❌ S3 State Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Builder job - check build queue')
    parser.add_argument('solver', choices=['z3', 'cvc5'], help='Solver name')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    commit = run_builder(args.solver)
    
    if args.json:
        import json
        print(json.dumps({'commit': commit} if commit else {'commit': None}))
    else:
        if commit:
            print(commit)
            sys.exit(0)
        else:
            sys.exit(1)

