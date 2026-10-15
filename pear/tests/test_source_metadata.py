# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact task metadata can coexist with a closed imported-source range."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('pear_metadata_verifier',
                                             Path(__file__).resolve().parents[1] / 'verify_source.py')
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)

APPROVED_METADATA = (
    '.github/source-notice-exceptions.json',
    'mydocs/working/task_m1_56_stage4.md',
    'mydocs/working/task_m1_56_stage4.json',
    'mydocs/working/task_m1_56_stage5.2.md',
    'mydocs/working/task_m1_56_stage5.2.json',
    'mydocs/working/task_m1_56_stage6.md',
    'mydocs/working/task_m1_56_stage6.json',
)
UNAPPROVED_METADATA = (
    'mydocs/working/task_m1_56_stage4.1.md',
    'mydocs/working/task_m1_56_stage5.1.json',
)


class MetadataAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pear-source-metadata-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'pear').mkdir()
        (self.root / 'unit.c').write_bytes(b'original source\n')
        (self.root / 'unit.c').chmod(0o644)
        self.manifest = {'schema_version': 1, 'component': 'pear-wine',
                         'upstream': {'commit': 'a' * 40},
                         'selected_files': [{'path': 'unit.c', 'mode': '100644',
                                             'size_bytes': 16, 'sha256': source.digest(b'original source\n')}]}
        self.changed = ['unit.c']
        self.tracked = ['unit.c', 'pear/source-manifest.json']
        self.shallow = False
        self.ancestor = True

    def git(self, root, *args):
        self.assertEqual(root, self.root.resolve())
        if args == ('rev-parse', '--is-shallow-repository'):
            return b'true\n' if self.shallow else b'false\n'
        if args == ('merge-base', '--is-ancestor', 'a' * 40, 'HEAD'):
            if not self.ancestor:
                raise source.SourceError('git_identity')
            return b''
        if args == ('ls-files', '-z'):
            return b'\0'.join(path.encode() for path in self.tracked) + b'\0'
        if args == ('diff', '--name-only', '-z', 'a' * 40, '--'):
            return b'\0'.join(path.encode() for path in self.changed) + b'\0'
        raise AssertionError(('unexpected git operation', args))

    def verify(self, peers=None):
        (self.root / 'pear/source-manifest.json').write_text(json.dumps(self.manifest))
        with patch.object(source, 'git', self.git):
            return source.verify(self.root, peers)

    def test_each_approved_report_and_policy_path_is_admitted(self):
        for name in APPROVED_METADATA:
            with self.subTest(path=name):
                self.changed = ['unit.c', name]
                result = self.verify()
                self.assertEqual(result['selected_files_verified'], 1)
                self.assertFalse(result['build_or_execution_performed'])

    def test_all_approved_metadata_can_be_staged_together(self):
        self.changed = ['unit.c', 'README.md', 'pear/tests/test_source_metadata.py', *APPROVED_METADATA]
        self.assertEqual(self.verify()['selected_files_verified'], 1)

    def test_unrelated_source_change_is_refused(self):
        for name in ('dlls/unreviewed.c', 'src/unreviewed.c', 'include/unreviewed.h'):
            with self.subTest(path=name), self.assertRaisesRegex(source.SourceError, 'unaccounted_source_change'):
                self.changed = ['unit.c', *APPROVED_METADATA, name]
                self.verify()

    def test_unapproved_report_and_policy_paths_are_refused(self):
        for name in UNAPPROVED_METADATA:
            with self.subTest(path=name), self.assertRaisesRegex(source.SourceError, 'unaccounted_source_change'):
                self.changed = ['unit.c', name]
                self.verify()

    def test_near_miss_metadata_and_other_tasks_are_refused(self):
        names = ('.github/source-notice-exceptions.json.py', '.github/other.json',
                 'mydocs/working/task_m1_57_stage6.md', 'mydocs/working/task_m1_56_stage5.3.json',
                 'mydocs/working/task_m1_56_stage6.py', 'mydocs/working/task_m1_56_stage6.md/extra.c',
                 'mydocs/working/task_m1_56_stage6.md.bak', 'mydocs/working/task_m1_56_report.md',
                 'mydocs/other/task_m1_56_stage6.md', 'mydocs/working/TASK_m1_56_stage6.md')
        for name in names:
            with self.subTest(path=name), self.assertRaisesRegex(source.SourceError, 'unaccounted_source_change'):
                self.changed = ['unit.c', name]
                self.verify()

    def test_metadata_does_not_hide_changed_selected_source(self):
        self.changed.extend(APPROVED_METADATA)
        (self.root / 'unit.c').write_bytes(b'changed source!\n')
        with self.assertRaisesRegex(source.SourceError, 'source_identity'):
            self.verify()

    def test_metadata_does_not_hide_wrong_source_mode(self):
        self.changed.extend(APPROVED_METADATA)
        (self.root / 'unit.c').chmod(0o755)
        with self.assertRaisesRegex(source.SourceError, 'source_mode'):
            self.verify()

    def test_private_or_generated_headers_remain_forbidden(self):
        self.changed.extend(APPROVED_METADATA)
        for name in ('pear/PearAbortObservation.h', 'pear/PearPhaseSelection.h'):
            with self.subTest(path=name), self.assertRaisesRegex(source.SourceError, 'private_or_generated_header'):
                self.tracked = ['unit.c', name]
                self.verify()

    def test_shallow_history_is_still_refused(self):
        self.changed.extend(APPROVED_METADATA)
        self.shallow = True
        with self.assertRaisesRegex(source.SourceError, 'shallow_history'):
            self.verify()

    def test_missing_upstream_ancestry_is_still_refused(self):
        self.changed.extend(APPROVED_METADATA)
        self.ancestor = False
        with self.assertRaisesRegex(source.SourceError, 'git_identity'):
            self.verify()

    def test_changed_peer_provider_is_still_refused(self):
        self.changed.extend(APPROVED_METADATA)
        peer = self.root / 'peer'
        peer.mkdir()
        (peer / 'provider.h').write_bytes(b'changed\n')
        self.manifest['imported_headers'] = [{'path': 'unit.c', 'provider': 'peer',
                                              'provider_path': 'provider.h',
                                              'sha256': source.digest(b'original\n')}]
        with self.assertRaisesRegex(source.SourceError, 'provider_header_identity'):
            self.verify({'peer': peer})


if __name__ == '__main__':
    unittest.main()
