# Scheduling System Design Decisions

## Architecture

**Manager-Builder-Fuzzer** architecture with S3-based state management.

- **Manager**: Checks commits, detects C++ changes, manages queues
- **Builder**: Builds commits from queue, uploads binaries
- **Fuzzer**: Selects commits from schedule, runs fuzzing

## Scheduling Strategy

### Manager
- **Schedule**: Every 15 minutes starting at 00:00 (`*/15 * * * *`)
- **Rationale**: Frequent checks ensure new commits are detected quickly

### Builder
- **Schedule**: Every 30 minutes starting at 00:05 (`5,35 * * * *`)
- **Rationale**: Runs 5 minutes after manager to allow queue updates, staggered to avoid resource contention

### Fuzzer
- **Schedule**: Every 6 hours starting at 00:45 (`45 0,6,12,18 * * *`)
- **Duration**: 6 hours per run
- **Rationale**: Runs at :45 to give builds time to complete, 6-hour intervals provide continuous coverage

### Coverage Mapper
- **Schedule**: Monthly on 1st at 00:00 (`0 0 1 * *`)
- **Rationale**: Coverage mappings are expensive, monthly is sufficient

## State Management

### Three State Files Per Solver
1. `state.json` - Last checked commit
   ```json
   {
     "last_checked_commit": "abc123..."
   }
   ```

2. `build-queue.json` - Queue, built, failed arrays
   ```json
   {
     "queue": ["commit1", "commit2"],
     "built": ["commit3"],
     "failed": ["commit4"]
   }
   ```

3. `fuzzing-schedule.json` - Ordered array with fuzz counts (oldest first)
   ```json
   [
     {"hash": "commit1", "fuzz_count": 2},
     {"hash": "commit2", "fuzz_count": 0}
   ]
   ```

**Rationale**: Minimal files reduce S3 operations, clear separation of concerns

### S3 Storage
- State: `solvers/{solver}/fuzzing-state/`
- Binaries: `solvers/{solver}/builds/{production|coverage}/`
- 7-day lifecycle policy for binaries (automatic cleanup)

### Atomic Operations
- All state updates use read-modify-write with retry logic
- Handles concurrent access from multiple workflow runs
- Optimistic locking prevents race conditions

## Queue Management

### Build Queue Flow
1. Manager detects C++ changes → adds to `queue` array (FIFO)
2. Builder picks first commit from `queue` → builds both binaries
3. After successful build: moved from `queue` to `built` array
4. After failed build: moved from `queue` to `failed` array
5. Manager checks `built` array → verifies binary exists → moves to fuzzing schedule → removes from `built`

**Builder Commit Selection**:
- FIFO: Always picks `queue[0]` (first commit)
- Commit stays in queue until build completes (success or failure)
- Multiple builder runs won't pick same commit (still in queue until moved)

**Rationale**: FIFO ensures oldest commits built first, commit remains in queue until completion for error handling

### Fuzzing Schedule Rules

**Minimum Size**: 4 commits (always maintain)

**Commit Selection**:
- Fuzzer selects least-fuzzed commit (minimum `fuzz_count`)
- If multiple commits have same `fuzz_count`, selects oldest (first in array)
- Verifies binary exists before fuzzing

**Size Management**:
- Manager: When adding new commits, if schedule >= 4, removes oldest fuzzed commit (`fuzz_count > 0`)
- Fuzzer: After incrementing fuzz count, if schedule > 4 AND all commits have been fuzzed at most once (`fuzz_count <= 1`), removes the commit that was just fuzzed

**Rationale**: Ensures every commit fuzzed at least once, prevents unbounded growth, prioritizes new commits while maintaining minimum coverage

## Commit Detection

**Only Today's Commits**: Manager checks from `last_checked_commit` to HEAD (today only)

**C++ Detection**: Files with extensions `.cpp`, `.cc`, `.cxx`, `.c`, `.h`, `.hpp`, `.hxx`, `.hh`

**Rationale**: Reduces API calls, focuses on recent changes, frequent manager runs catch all commits

## Build Requirements

**Both Binaries Required**: Production AND coverage binaries must be uploaded before marking as "built"

**Rationale**: Ensures complete build, both needed for fuzzing and coverage mapping

## Workflow Execution Flow

### Manager Workflow
1. Check `last_checked_commit` from `state.json`
2. Fetch commits from GitHub (from `last_checked_commit` to HEAD, today only)
3. For each commit: detect C++ changes → add to build queue if found
4. Check `built` array: verify binaries exist → move to fuzzing schedule → remove from `built`
5. Clean up fuzzing schedule: remove commits with missing binaries
6. Manage schedule size: remove oldest fuzzed if adding new and schedule >= 4
7. Update `last_checked_commit` to latest

### Builder Workflow
1. Check if manual commit provided → add to queue if yes
2. Otherwise: call `builder.py` → get first commit from queue
3. If commit found: checkout → build production binary → build coverage binary
4. Upload both binaries to S3
5. `mark-as-built` job: move from `queue` to `built` (only if both builds succeeded)
6. `mark-as-failed` job: move from `queue` to `failed` (if either build failed)

### Fuzzer Workflow
1. Check if manual commit provided → add to fuzzing schedule if yes
2. Otherwise: call `fuzzer.py select` → get least-fuzzed commit
3. Verify binary exists in S3
4. If found: checkout → download coverage mapping → run fuzzing for 6 hours
5. After fuzzing: `update-fuzz-count` job calls `fuzzer.py increment`
6. Increment fuzz count → manage schedule size if needed

## Error Handling

- **Failed builds**: Moved to `failed` array (not retried automatically, can be manually re-added)
- **Missing binaries**: Removed from fuzzing schedule (7-day lifecycle cleanup)
- **Concurrent access**: Atomic S3 operations with retry logic (3 retries by default)
- **Binary verification**: Both manager and fuzzer verify binary exists before proceeding

## Manual Triggers

All workflows support `workflow_dispatch` with optional commit hash input:

- **Manager**: Adds commit directly to build queue
- **Builder**: Adds commit directly to build queue (skips manager)
- **Fuzzer**: Adds commit directly to fuzzing schedule (skips build queue)

**Use case**: Testing specific commits, re-adding failed commits, prioritizing important commits

