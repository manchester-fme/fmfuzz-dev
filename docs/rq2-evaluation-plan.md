# RQ2 Evaluation Plan: Does FMFuzz direct fuzzing towards committed changes?

## Overview

Compare FMFuzz (directed fuzzing towards committed changes) against a baseline (random test selection).

## Experimental Setup

### Baseline
- Random test selection from full regression test suite
- No commit analysis, no coverage mapping

### FMFuzz Variant 1
- Changed functions → covering tests via coverage mapping
- Perfect coverage mapping (fresh for each commit)

### Constraints
- 20 jobs max in parallel
- 256 jobs max per workflow
- 6 hours max per job
- Both z3 and cvc5 (execute separately)
- Storage: `evaluation/rq2/{solver}/`

## Stage 1: Commit Selection

### Workflow
- **Z3**: `.github/workflows/z3-evaluation-rq2-commit-selection.yml`
- **CVC5**: `.github/workflows/cvc5-evaluation-rq2-commit-selection.yml`
- **Script**: `scripts/evaluation/rq2/commit_selection.py`

### Process
1. **Discover commits** (last 2 years with C++ changes)
   - Query GitHub API with pagination
   - Filter commits with C++ changes using `detect_cpp_changes.py`
   - Store: `evaluation/rq2/{solver}/raw-commits.json`
   ```json
   [
     {"hash": "commit1", "date": "2023-01-15", ...},
     ...
   ]
   ```

2. **Analyze changed functions**
   - For each commit: use `tree-sitter-cpp` to parse C++ code and identify changed functions
   - No build required - analyzes git diffs and source code directly
   - Incremental: skips already analyzed commits
   - Store: `evaluation/rq2/{solver}/commit-statistics.json`
   ```json
   {
     "commits": [
       {
         "hash": "commit1",
         "date": "2023-01-15",
         "changed_functions_count": 3,
         "changed_functions": [
           {"file": "src/solver.cpp", "function": "solve", "line": 42},
           ...
         ]
       },
       ...
     ],
     "statistics": {
       "total": 150,
       "small": 50,
       "medium": 70,
       "large": 30
     }
   }
   ```

3. **Select commits** (distributed across small/medium/large)
   - Default: 17 small + 17 medium + 16 large = 50 commits total
   - Categories:
     - Small: 1-5 changed functions (threshold: 5)
     - Medium: 6-20 changed functions (threshold: 20)
     - Large: 21+ changed functions
   - Store: `evaluation/rq2/{solver}/selected-commits.json`
   ```json
   ["commit1", "commit2", ...]
   ```

### Parameters
- `--years`: Number of years to look back (default: 2)
- `--small-count`: Number of small commits (default: 17)
- `--medium-count`: Number of medium commits (default: 17)
- `--large-count`: Number of large commits (default: 16)
- `--small-threshold`: Max functions for "small" (default: 5)
- `--medium-threshold`: Max functions for "medium" (default: 20)
- `--max-commits`: Limit total selected commits (for testing)
- `--skip-analysis`: Skip function analysis (use existing stats)
- `--skip-selection`: Skip selection (use existing selection)

### Workflow Inputs
- `max_commits`: Maximum total commits to select (for testing)
- `small_count`, `medium_count`, `large_count`: Override defaults

## Stage 2: Binary Building

### Workflow
- **Z3**: `.github/workflows/z3-evaluation-rq2-build.yml`
- **CVC5**: `.github/workflows/cvc5-evaluation-rq2-build.yml`
- **Script**: `scripts/evaluation/rq2/generate_build_matrix.py`

### Process
1. **Generate matrix** from selected commits
   - Reads `evaluation/rq2/{solver}/selected-commits.json` from S3
   - Creates matrix with all commit hashes

2. **Build binaries for each commit** (parallel matrix job)
   - For each commit:
     - Checkout commit
     - Build production binary (`--static`)
     - Build coverage binary (`--static --coverage`)
     - Collect artifacts (binary, headers, compile_commands.json)
     - Compress and upload to S3
   - Store: `evaluation/rq2/{solver}/builds/production/{commit}.tar.gz`
   - Store: `evaluation/rq2/{solver}/builds/coverage/{commit}.tar.gz`

3. **Build in parallel** (up to 20 jobs)
   - Each job builds both binaries for one commit
   - Timeout: 6 hours per job

### Timing
- Production binary: ~30-60 minutes per commit
- Coverage binary: ~30-60 minutes per commit
- Total per commit: ~1-2 hours
- With 50 commits, 20 parallel: ~2.5-5 hours wall-clock time

## Stage 3: Coverage Mapping (Variant 1)

### Workflow
- **Z3**: `.github/workflows/z3-evaluation-rq2-coverage-mapping.yml`
- **CVC5**: `.github/workflows/cvc5-evaluation-rq2-coverage-mapping.yml`
- **Script**: `scripts/evaluation/rq2/generate_coverage_matrix.py`

### Process
1. **Generate combined matrix** (commit × chunk)
   - Downloads one coverage binary to discover tests
   - Discovers all tests and calculates chunks:
     - Z3: ~4 chunks (target: ~1 hour per chunk)
     - CVC5: ~6 chunks (target: ~3 hours per chunk)
   - Creates matrix of (commit, chunk) pairs
   - Example: 50 commits × 4 chunks = 200 jobs for Z3

2. **Run coverage analysis** (parallel matrix job)
   - For each (commit, chunk) pair:
     - Download coverage binary for that commit
     - Extract to build directory
     - Run coverage mapping for test range (chunk)
     - Produces partial mapping: `coverage_mapping_{start}_{end}.json`
     - Uploads as GitHub Actions artifact

3. **Join coverage mappings** (parallel per commit)
   - For each commit:
     - Downloads all chunks for that commit
     - Merges partial mappings into one
     - Removes duplicates and sorts
     - Compresses: `coverage_mapping.json.gz`
     - Uploads to S3
   - Store: `evaluation/rq2/{solver}/coverage-mappings/variant1/coverage_mapping-{commit}.json.gz`

### Chunking Strategy
- **Why chunking?** Coverage mapping is time-intensive:
  - Z3: 4 chunks × ~1 hour = ~1 hour total (parallel)
  - CVC5: 6 chunks × ~3 hours = ~3 hours total (parallel)
- **How it works:**
  - Tests are split into ranges (e.g., tests 1-250, 251-500, etc.)
  - Each chunk runs independently
  - Partial mappings are merged by function signature

### Parameters
- `max_commits`: Limit number of commits to process (for testing)

### Workflow Inputs
- `max_commits`: Maximum commits to process (e.g., "5" for testing)

### Timing
- **Z3**: 50 commits × 4 chunks = 200 jobs
  - 200 jobs ÷ 20 parallel = 10 batches
  - Each batch: ~1 hour
  - Total: ~10 hours wall-clock time
- **CVC5**: 50 commits × 6 chunks = 300 jobs
  - 300 jobs ÷ 20 parallel = 15 batches
  - Each batch: ~3 hours
  - Total: ~45 hours wall-clock time

## Storage Structure

```
evaluation/rq2/
├── z3/
│   ├── raw-commits.json
│   ├── commit-statistics.json
│   ├── selected-commits.json
│   ├── builds/
│   │   ├── production/{commit}.tar.gz
│   │   └── coverage/{commit}.tar.gz
│   └── coverage-mappings/
│       └── variant1/coverage_mapping-{commit}.json.gz
└── cvc5/
    └── [same structure]
```

## Execution Timeline

### Stage 1: Commit Selection
- **Z3**: ~2-4 hours (function analysis, incremental)
- **CVC5**: ~2-4 hours (function analysis, incremental)
- **Total**: ~4-8 hours (can run in parallel)

### Stage 2: Binary Building
- **Z3**: 50 commits, 20 parallel → ~2.5-5 hours
- **CVC5**: 50 commits, 20 parallel → ~2.5-5 hours
- **Total**: ~5-10 hours (run separately)

### Stage 3: Coverage Mapping
- **Z3**: 200 jobs, 20 parallel → ~10 hours
- **CVC5**: 300 jobs, 20 parallel → ~45 hours
- **Total**: ~55 hours (run separately)

### Grand Total
- **Sequential execution**: ~64-73 hours (~2.5-3 days)
- **With parallel stages**: ~59-63 hours (~2.5 days)

## Testing

All workflows support testing with smaller commit counts:

1. **Commit Selection**: Use `max_commits` input (e.g., "5")
2. **Binary Building**: Processes all selected commits (no limit parameter yet)
3. **Coverage Mapping**: Use `max_commits` input (e.g., "5")

**Example test run:**
- Select 5 commits → Build 5 binaries → Generate 5 coverage mappings
- Z3: 5 commits × 4 chunks = 20 jobs (~1 hour)
- CVC5: 5 commits × 6 chunks = 30 jobs (~3 hours)

## Implementation Status

✅ **Stage 1**: Implemented
- Commit discovery and filtering
- Function analysis with tree-sitter-cpp
- Commit categorization and selection
- Workflows created with testing parameters

✅ **Stage 2**: Implemented
- Binary building workflows
- Matrix generation from selected commits
- Parallel building (20 jobs max)

✅ **Stage 3**: Implemented
- Coverage mapping with chunking
- Combined matrix generation (commit × chunk)
- Parallel coverage analysis
- Join and merge mappings

## Next Steps (Future)

1. **Fuzzing Stage** (not yet implemented)
   - Baseline: Random test selection
   - FMFuzz Variant 1: Use coverage mappings to direct fuzzing
   - Compare results

2. **Analysis Stage** (not yet implemented)
   - Compare coverage achieved
   - Compare bugs found
   - Statistical analysis
