#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify this component's selected import without building or executing it."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess


class SourceError(Exception):
    """A stable source-admission failure code."""


def need(value, code):
    if not value:
        raise SourceError(code)


def relative(value):
    need(isinstance(value, str) and value and not value.startswith('/'), 'unsafe_path')
    parts = value.split('/')
    need(all(p not in ('', '.', '..') for p in parts), 'unsafe_path')
    need(not any(c in value for c in ('\\', '\x00', '\n', '\r')), 'unsafe_path')
    return PurePosixPath(value)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_entry(root, entry):
    name = relative(entry['path'])
    current = root
    for part in name.parts[:-1]:
        current = current / part
        need(current.is_dir() and not current.is_symlink(), 'aliased_parent')
    path = root / name
    need(path.exists() or path.is_symlink(), 'missing_source')
    info = path.lstat()
    mode = entry['mode']
    if mode == '120000':
        need(stat.S_ISLNK(info.st_mode), 'source_kind')
        data = os.readlink(path).encode('utf-8')
    else:
        need(mode in ('100644', '100755'), 'manifest_mode')
        need(stat.S_ISREG(info.st_mode), 'source_kind')
        need(bool(info.st_mode & 0o111) == (mode == '100755'), 'source_mode')
        data = path.read_bytes()
    need(re.fullmatch(r'[0-9a-f]{64}', entry['sha256']) is not None, 'manifest_digest')
    need(len(data) == entry['size_bytes'] and digest(data) == entry['sha256'], 'source_identity')


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], check=False,
                            capture_output=True, timeout=60)
    need(result.returncode == 0, 'git_identity')
    return result.stdout


def verify(root, peers=None):
    root = root.resolve()
    manifest = json.loads((root / 'pear/source-manifest.json').read_text())
    need(manifest['schema_version'] == 1, 'manifest_version')
    need(git(root, 'rev-parse', '--is-shallow-repository').strip() == b'false', 'shallow_history')
    git(root, 'merge-base', '--is-ancestor', manifest['upstream']['commit'], 'HEAD')
    rows = manifest['selected_files']
    names = [r['path'] for r in rows]
    need(len(names) == len(set(names)), 'duplicate_source')
    for entry in rows:
        verify_entry(root, entry)
    tracked = git(root, 'ls-files', '-z').split(b'\0')
    forbidden = ('PearAbortObservation.h', 'PearPhaseSelection.h')
    need(not any(Path(p.decode()).name in forbidden for p in tracked if p), 'private_or_generated_header')
    changed = git(root, 'diff', '--name-only', '-z', manifest['upstream']['commit'], '--').split(b'\0')
    allowed = set(names) | {'README.md'}
    need(all(p.decode() in allowed or p.startswith(b'pear/') for p in changed if p),
         'unaccounted_source_change')
    for module in manifest.get('submodules', []):
        mode, object_id, revision, name = git(root, 'ls-files', '--stage', '--', module['path']).decode().split()
        # ls-files --stage uses: mode object stage<TAB>path.
        need(mode == '160000' and object_id == module['commit'] and revision == '0'
             and name == module['path'], 'submodule_identity')
    checked_peers = []
    for binding in manifest.get('imported_headers', []):
        peer = (peers or {}).get(binding['provider'])
        if peer is not None:
            data = (Path(peer) / relative(binding['provider_path'])).read_bytes()
            need(digest(data) == binding['sha256'], 'provider_header_identity')
            checked_peers.append(binding['path'])
    return {'component': manifest['component'], 'selected_files_verified': len(rows),
            'upstream_ancestry': True, 'full_history': True,
            'peer_headers_checked': checked_peers, 'build_or_execution_performed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--peer', action='append', default=[], metavar='NAME=PATH')
    args = parser.parse_args()
    peers = dict(value.split('=', 1) for value in args.peer)
    try:
        print(json.dumps(verify(args.root, peers), sort_keys=True))
    except (SourceError, OSError, ValueError, KeyError) as error:
        raise SystemExit(str(error)) from error


if __name__ == '__main__':
    main()
