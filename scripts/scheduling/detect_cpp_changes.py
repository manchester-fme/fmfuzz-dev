#!/usr/bin/env python3
"""Detect if a commit has C++ code changes"""

import os
import sys
import subprocess
from typing import List, Optional
import argparse

try:
    import git
except ImportError:
    print("Error: GitPython is required. Install with: pip install GitPython", file=sys.stderr)
    sys.exit(1)

try:
    import requests
except ImportError:
    requests = None

CPP_EXTENSIONS = {'.cpp', '.cc', '.cxx', '.c', '.h', '.hpp', '.hxx', '.hh'}


def has_cpp_extension(filename: str) -> bool:
    return any(filename.lower().endswith(ext) for ext in CPP_EXTENSIONS)


def detect_cpp_changes_git(repo_path: str, commit_hash: str) -> tuple[bool, List[str]]:
    try:
        repo = git.Repo(repo_path)
        commit = repo.commit(commit_hash)
        parents = commit.parents
        parent_hash = parents[0].hexsha if parents else None
        diff = commit.diff(parent_hash if parent_hash else git.NULL_TREE)
        
        cpp_files = []
        for item in diff:
            for path in [item.a_path, item.b_path]:
                if path and has_cpp_extension(path) and path not in cpp_files:
                    cpp_files.append(path)
        return len(cpp_files) > 0, cpp_files
    except git.exc.BadName:
        raise ValueError(f"Invalid commit hash: {commit_hash}")
    except Exception as e:
        raise RuntimeError(f"Error detecting C++ changes: {e}")


def detect_cpp_changes_github_api(repo_url: str, commit_hash: str, token: Optional[str] = None) -> tuple[bool, List[str]]:
    if requests is None:
        raise RuntimeError("requests library required. Install with: pip install requests")
    
    if repo_url.startswith('https://github.com/'):
        repo_path = repo_url.replace('https://github.com/', '').replace('.git', '')
    elif repo_url.startswith('git@github.com:'):
        repo_path = repo_url.replace('git@github.com:', '').replace('.git', '')
    elif '/' in repo_url:
        repo_path = repo_url.replace('.git', '')
    else:
        raise ValueError(f"Invalid repo URL: {repo_url}")
    
    api_url = f"https://api.github.com/repos/{repo_path}/commits/{commit_hash}"
    headers = {'Authorization': f'token {token}'} if token else {}
    
    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        commit_data = response.json()
        
        cpp_files = []
        for file_info in commit_data.get('files', []):
            filename = file_info.get('filename', '')
            if has_cpp_extension(filename) and filename not in cpp_files:
                cpp_files.append(filename)
        return len(cpp_files) > 0, cpp_files
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            raise ValueError(f"Commit not found: {commit_hash}")
        elif e.response.status_code == 403:
            raise RuntimeError("GitHub API rate limit exceeded. Use GITHUB_TOKEN.")
        raise RuntimeError(f"GitHub API error: {e}")
    except Exception as e:
        raise RuntimeError(f"Error: {e}")


def detect_cpp_changes(repo_path_or_url: str, commit_hash: str, token: Optional[str] = None) -> tuple[bool, List[str]]:
    if 'github.com' in repo_path_or_url:
        return detect_cpp_changes_github_api(repo_path_or_url, commit_hash, token)
    return detect_cpp_changes_git(repo_path_or_url, commit_hash)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Detect C++ changes in a commit')
    parser.add_argument('repo', help='Repository path or GitHub URL')
    parser.add_argument('commit', help='Commit hash')
    parser.add_argument('--token', help='GitHub token', default=os.getenv('GITHUB_TOKEN'))
    parser.add_argument('--list-files', action='store_true', help='List changed C++ files')
    
    args = parser.parse_args()
    
    try:
        has_cpp, cpp_files = detect_cpp_changes(args.repo, args.commit, args.token)
        
        if args.list_files:
            print('\n'.join(cpp_files) if cpp_files else '', end='')
        else:
            print(f"✅ Commit {args.commit} has C++ changes ({len(cpp_files)} files)" if has_cpp 
                  else f"❌ Commit {args.commit} has no C++ changes")
            sys.exit(0 if has_cpp else 1)
    except (ValueError, RuntimeError) as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
