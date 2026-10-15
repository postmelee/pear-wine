# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read admitted canonical Wine source, never replay legacy editable patches."""
import json
from pathlib import Path, PurePosixPath
from pear.verify_source import relative, verify_entry, need

ROOT = Path(__file__).resolve().parents[2]


def materialize(name, *, root=ROOT):
    relative(name)
    root = Path(root)
    need(root.is_dir() and root.resolve(strict=True) == root, 'test_source_root_alias')
    manifest = json.loads((root/'pear/source-manifest.json').read_text())
    rows = [row for row in manifest['selected_files'] if row['path'] == name]
    need(len(rows) == 1, 'test_source_not_selected')
    verify_entry(root, rows[0])
    raw = (root/name).read_text()
    verify_entry(root, rows[0])
    return raw


def ordinary_file(root, relative):
    name = PurePosixPath(relative)
    if not isinstance(relative, str) or str(name) != relative or name.is_absolute() or any(
            value in ('', '.', '..') for value in name.parts) or '\\' in relative:
        raise ValueError('invalid relative source path')
    path = root
    for part in name.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('source or patch path is a symlink')
    if not path.is_file():
        raise ValueError('required ordinary source or patch file is missing')
    return path



def upstream_source(name, *, root=ROOT):
    relative(name)
    import subprocess
    manifest=json.loads((root/'pear/source-manifest.json').read_text())
    commit=manifest['upstream']['commit']
    need(commit=='4e819f054dd2d9ee855ee3f1e30d8c1bb8f80fcf','test_upstream_pin')
    result=subprocess.run(['git','-C',str(root),'show',commit+':'+name],
                          capture_output=True,timeout=30,check=True)
    need(len(result.stdout)<=8*1024**2,'test_upstream_size')
    return result.stdout.decode('utf-8')


def configured_headers():
    """Explicit hash-bound generated inputs plus the canonical source headers."""
    import hashlib, os, unittest
    declared = os.environ.get('PEAR_WINE_TEST_INPUTS')
    expected = os.environ.get('PEAR_WINE_TEST_INPUTS_SHA256')
    if not declared or not expected:
        raise unittest.SkipTest('explicit Wine generated-input manifest and SHA-256 required')
    path = Path(declared)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'test_header_manifest_alias')
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == expected, 'test_header_manifest_changed')
    value = json.loads(raw)
    rows = [row for row in value['inputs'] if row['path'].startswith('native/objects/include/')]
    need(rows and any(row['path'] == 'native/objects/include/config.h' for row in rows), 'test_header_input_set')
    for row in rows:
        source = ordinary_file(path.parent, row['path'])
        content = source.read_bytes()
        need(len(content) == row['size_bytes'] and hashlib.sha256(content).hexdigest() == row['sha256'],
             'test_header_input_changed')
    need((ROOT/'include/winnt.h').read_text() == upstream_source('include/winnt.h'), 'test_upstream_header_changed')
    return path.parent/'native/objects/include', ROOT/'include'


def historical_arena(name):
    """Hash-checked frozen negative input; never a production-source fallback."""
    import hashlib
    relative(name)
    value = json.loads((ROOT/'pear/arena-negative-inputs.json').read_text())
    rel = 'pear/tests/fixtures/pe_arena_pre_cookie/'+name
    rows = [row for row in value['files'] if row['path'] == rel]
    need(len(rows) == 1, 'test_negative_input_missing')
    raw = ordinary_file(ROOT, rel).read_bytes()
    need(len(raw) == rows[0]['size_bytes'] and hashlib.sha256(raw).hexdigest() == rows[0]['sha256'],
         'test_negative_input_changed')
    return raw.decode('utf-8')
