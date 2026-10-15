# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable source-admission controls; no compiler, runtime or game dependency."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('pear_source_verifier',
                                             Path(__file__).resolve().parents[1] / 'verify_source.py')
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)


class SourceAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pear-source-admission-')
        self.root = Path(self.temp.name)
        (self.root / 'unit.c').write_bytes(b'original source\n')
        (self.root / 'unit.c').chmod(0o644)
        self.entry = {'path': 'unit.c', 'mode': '100644', 'size_bytes': 16,
                      'sha256': source.digest(b'original source\n')}

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_source_is_admitted(self):
        source.verify_entry(self.root, self.entry)

    def test_changed_source_is_refused(self):
        (self.root / 'unit.c').write_bytes(b'changed source!\n')
        with self.assertRaisesRegex(source.SourceError, 'source_identity'):
            source.verify_entry(self.root, self.entry)

    def test_wrong_executable_mode_is_refused(self):
        (self.root / 'unit.c').chmod(0o755)
        with self.assertRaisesRegex(source.SourceError, 'source_mode'):
            source.verify_entry(self.root, self.entry)

    def test_missing_source_is_refused(self):
        (self.root / 'unit.c').unlink()
        with self.assertRaisesRegex(source.SourceError, 'missing_source'):
            source.verify_entry(self.root, self.entry)

    def test_symlink_cannot_impersonate_regular_source(self):
        (self.root / 'alias.c').symlink_to('unit.c')
        with self.assertRaisesRegex(source.SourceError, 'source_kind'):
            source.verify_entry(self.root, {**self.entry, 'path': 'alias.c'})

    def test_declared_symlink_preserves_link_bytes(self):
        (self.root / 'alias.c').symlink_to('unit.c')
        entry = {'path': 'alias.c', 'mode': '120000', 'size_bytes': 6,
                 'sha256': source.digest(b'unit.c')}
        source.verify_entry(self.root, entry)

    def test_aliased_parent_is_refused(self):
        (self.root / 'alias').symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(source.SourceError, 'aliased_parent'):
            source.verify_entry(self.root, {**self.entry, 'path': 'alias/unit.c'})

    def test_escape_and_absolute_paths_are_refused(self):
        for path in ('../unit.c', '/unit.c', 'dir/../unit.c', 'dir//unit.c'):
            with self.subTest(path=path), self.assertRaisesRegex(source.SourceError, 'unsafe_path'):
                source.verify_entry(self.root, {**self.entry, 'path': path})

    def test_malformed_digest_is_refused(self):
        with self.assertRaisesRegex(source.SourceError, 'manifest_digest'):
            source.verify_entry(self.root, {**self.entry, 'sha256': 'a' * 65})


if __name__ == '__main__':
    unittest.main()
