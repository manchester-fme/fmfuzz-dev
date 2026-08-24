#!/usr/bin/env python3
"""Procedure Report (see docs/report.txt / docs/architecture.txt):

Input: a single confirmed bug-triggering .smt2 file (as produced by
dedup.py / minimized by reduce.py -- named 'incorrect-...smt2' for a
soundness bug or 'crash-...smt2' for a crash)
Output: a GitHub issue title + body for --repo's issue tracker (default:
the current directory's git remote)

Re-confirms the bug with dedup.py's confirm_crash()/confirm_soundness()
(the same logic dedup.py and reduce.py use) so a report can't be filed for
a trigger that no longer reproduces. By default this only prints the
drafted title/body (a dry run); actually filing the issue via `gh issue
create` requires the explicit --post flag, since that's a real,
externally-visible, hard-to-reverse action.
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

import dedup

CAST_ORG = json.loads((Path(__file__).resolve().parent.parent / "util" / "defaults.json").read_text())["cast_org"]

ERR_USAGE = 2

SORTS = ["Bool", "Int", "Real", "BitVec", "Array", "String"]


def error(msg):
    print(f"error: {msg}", flush=True)
    exit(ERR_USAGE)


def datatypes_from_bitstring(dtype):
    names = [sort for bit, sort in zip(dtype, SORTS) if bit == "1"]
    return ", ".join(names) if names else "no declared sorts"


def pretty_print_smt2(text):
    """One top-level form per line for display in the issue body -- creduce
    tends to squash a reduced trigger onto a single line. Uses dedup's own
    tokenizer, so this never touches the actual reproducer file."""
    forms = dedup.split_toplevel_forms(text)
    return "\n".join(forms) if forms else text


def confirm(path, target_cmd, oracle_cmd):
    kind = dedup.classify(path)
    if kind is None:
        error(
            f'"{path.name}" is not named like a dedup.py bug trigger '
            '(expected an "incorrect-...smt2" or "crash-...smt2" prefix)'
        )
    if kind == "soundness":
        if not oracle_cmd:
            error("--oracle-cmd is required to report a soundness bug")
        text = path.read_text(errors="ignore")
        msg = dedup.confirm_soundness(path, text, target_cmd, oracle_cmd)
    else:
        msg = dedup.confirm_crash(path, target_cmd)

    if msg is None:
        error(
            f'"{path.name}" does not currently reproduce a {kind} bug '
            "against the given solver command(s) -- nothing to report"
        )
    return kind, msg


def solver_commit_hash(target_cmd):
    """Short commit hash of the target solver's build, for the report body
    -- the binary is always built from a git checkout in CAST's pipeline,
    so this is more useful than a solver's verbose --version banner."""
    solver_bin = target_cmd.split(" ")[0]
    resolved = shutil.which(solver_bin) or solver_bin

    try:
        commit_dir = str(Path(resolved).resolve().parent)
        out = subprocess.run(
            ["git", "-C", commit_dir, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass

    return "unknown"


DISPLAY_NAME = "bug.smt2"


def build_report(path, target_cmd, oracle_cmd, kind, msg, commit_hash=None):
    text = path.read_text(errors="ignore")
    datatypes = datatypes_from_bitstring(dedup.datatype_bitstring(text))

    if kind == "soundness":
        title = f"[CAST] {msg.capitalize()} Soundness bug related to {datatypes}"
    else:
        title = f"[CAST] Crash: {msg} related to {datatypes}"

    # the real trigger's filename is an internal, creduce-mangled name;
    # show it in the issue under a generic name instead (see docs/report.txt)
    transcript = []
    _, target_out = dedup.run_solver(target_cmd, path)
    transcript += [f"$ {target_cmd} {DISPLAY_NAME}", target_out.strip(), ""]
    if kind == "soundness":
        _, oracle_out = dedup.run_solver(oracle_cmd, path)
        transcript += [f"$ {oracle_cmd} {DISPLAY_NAME}", oracle_out.strip(), ""]
    transcript += [f"$ cat {DISPLAY_NAME}", pretty_print_smt2(text)]

    # commit_hash, when given, is the solver commit CAST actually built and
    # fuzzed (known from S3/the caller's own inputs) - prefer it over
    # solver_commit_hash()'s git introspection, which only works when the
    # binary sits inside a live git checkout. In CI the binary is always a
    # prebuilt tarball extracted with no .git dir, so that introspection
    # silently falls back to "unknown" on every real run (see caller sites).
    commit = commit_hash[:7] if commit_hash else solver_commit_hash(target_cmd)

    lines = [f"commit: {commit}", "", "```bash"]
    lines += transcript
    lines += ["```", "", "---", f"Found with [CAST](https://github.com/{CAST_ORG}/CAST)"]

    return title, "\n".join(lines) + "\n"


def find_existing_issue(title, repo=None):
    """Search open and closed issues for an exact title match. Callers must
    check the returned item's state themselves -- a closed match means the
    bug was previously fixed, not that it's still an open duplicate, so it
    should not by itself suppress filing a new report (see #67: this is
    what makes a regression of a fixed bug reappear as a fresh issue
    instead of being silently swallowed)."""
    cmd = ["gh", "issue", "list", "--search", f'"{title}" in:title', "--state", "all",
           "--json", "number,title,url,state", "--limit", "5"]
    if repo:
        cmd += ["--repo", repo]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    for item in json.loads(result.stdout or "[]"):
        if item["title"] == title:
            return item
    return None


def post_issue(title, body, repo=None):
    cmd = ["gh", "issue", "create", "--title", title, "--body", body]
    if repo:
        cmd += ["--repo", repo]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("error: gh issue create failed:\n" + result.stderr, flush=True)
        exit(1)
    print(result.stdout.strip(), flush=True)  # gh prints the created issue's URL


def report(path, target_cmd, oracle_cmd, post, out, repo=None, commit_hash=None):
    dedup.check_solver_installed(target_cmd)
    if oracle_cmd:
        dedup.check_solver_installed(oracle_cmd)

    kind, msg = confirm(path, target_cmd, oracle_cmd)
    title, body = build_report(path, target_cmd, oracle_cmd, kind, msg, commit_hash)

    print(f"--- title ---\n{title}\n--- body ---\n{body}")

    if out:
        Path(out).write_text(f"{title}\n\n{body}")
        print(f"saved draft to {out}")

    if not post:
        print("(dry run -- pass --post to actually file this issue on GitHub)")
        return

    if shutil.which("gh") is None:
        error("gh CLI not found on PATH -- required for --post")
    if subprocess.run(["gh", "auth", "status"], capture_output=True).returncode != 0:
        error("gh is not authenticated -- run `gh auth login` first")

    existing = find_existing_issue(title, repo)
    if existing and existing["state"] == "OPEN":
        print(f"an open issue with this exact title already exists: {existing['url']} -- not filing a duplicate")
        return

    if existing:  # closed -- possible regression, file a new report but link the old one
        print(f"a closed issue with this exact title exists: {existing['url']} -- filing as a possible regression")
        body += f"\nPossible regression of #{existing['number']} (closed): {existing['url']}\n"

    post_issue(title, body, repo)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="report.py",
        description="Report a confirmed dedup.py bug trigger to this repository's issue tracker.",
    )
    parser.add_argument("smt2_file", help="the confirmed bug-triggering .smt2 file to report")
    parser.add_argument(
        "--target-cmd",
        required=True,
        help="target solver command line, e.g. 'z3 model_validate=true'",
    )
    parser.add_argument(
        "--oracle-cmd",
        help="oracle solver command line, required for soundness ('incorrect-...') triggers",
    )
    parser.add_argument(
        "--post",
        action="store_true",
        help="actually file the issue with `gh issue create` (default: dry run, print only)",
    )
    parser.add_argument("--out", help="also save the drafted title/body to this file")
    parser.add_argument(
        "--repo",
        help="file the issue on this repo (owner/name) instead of the current directory's git remote",
    )
    parser.add_argument(
        "--commit-hash",
        help="solver commit this trigger was found against (preferred over introspecting the "
        "binary's own directory, which only works when it sits inside a live git checkout)",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    report(
        Path(args.smt2_file), args.target_cmd, args.oracle_cmd, args.post, args.out, args.repo,
        args.commit_hash,
    )
