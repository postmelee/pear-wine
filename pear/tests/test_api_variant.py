# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Injected real architecture-check C: exact current entries and old oracle."""
from pathlib import Path
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
import test_api_architecture as original

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_api_variant', ROOT/'native_api_variant.py')
variant = importlib.util.module_from_spec(spec)
spec.loader.exec_module(variant)


class VariantSourceTests(unittest.TestCase):
    def test_only_exact_selected_condition_changes(self):
        source = original.SOURCE.read_bytes()
        generated = variant.generate(source)
        self.assertEqual(generated.replace(variant.NEW, variant.OLD, 1), source)
        self.assertEqual(hashlib.sha256(generated).hexdigest(),
                         'e978253389db2360448d0e93945e6bc65398ba8f0b5a136a1d5d3123bd8a4e8c')
        self.assertEqual(variant.provenance(source)['replacement_count'], 1)
        self.assertNotEqual(source, generated)

    def test_changed_truncated_or_repeated_original_refused(self):
        source = original.SOURCE.read_bytes()
        for raw in (source[:-1], source+b' ', source+variant.OLD, source.replace(b'architecture_bytes', b'architecture_count', 1)):
            with self.subTest(length=len(raw)), self.assertRaisesRegex(ValueError, 'original_source_changed'):
                variant.generate(raw)


class CurrentEnumerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='pear-api-variant-')
        cls.root = Path(cls.directory.name)
        generated = variant.generate(original.SOURCE.read_bytes()).decode()
        # Reuse the original native harness and actual C function extraction.
        declarations = generated[generated.index('typedef LONG (NTAPI *query_architectures_fn)'):
                                 generated.index('static const WCHAR arg_space[]')]
        errors = generated[generated.index('static int fail_code('):generated.index('static uint64_t hash_bytes(')]
        formatter = generated[generated.index('static char output[512]'):generated.index('static int report(int child)')]
        functions = generated[generated.index('static int architecture_check(void)'):generated.index('void WINAPI mainCRTStartup(void)')]
        harness = original.HARNESS.replace('words[0] = 0x7AA64u; words[1] = 0; *returned = 8;',
                 'words[0] = 0x7AA64u; words[1] = 0x12014cu; words[2] = 0; *returned = 12;', 1)
        harness = harness.replace('case 9: words[1] = 0x13014cu; words[2] = 0; *returned = 12; break;',
                    'case 9: words[1] = 0x13014cu; break;', 1)
        harness = harness.replace('case 17: words[1] = 0x10000u; break;', '''case 17: words[1] = 0x10000u; break;
    case 20: words[1] = 0; *returned = 8; break;
    case 21: words[2] = 0x28664u; words[3] = 0; *returned = 16; break;
    case 22: words[0] = 0x12014cu; words[1] = 0x7AA64u; break;
    case 23: words[1] = 0x28664u; break;
    case 24: words[2] = 0x7AA64u; break;''', 1)
        source = cls.root/'query.c'; source.write_text(harness+declarations+errors+formatter+functions+original.MAIN)
        cls.binary = cls.root/'query'
        result = subprocess.run(['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1',
                                 '-fsanitize=undefined', '-fno-sanitize-recover=all', str(source), '-o', str(cls.binary)],
                                 capture_output=True, text=True, timeout=30)
        if result.returncode: raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_case(self, scenario):
        result = subprocess.run([str(self.binary), str(scenario)], capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual(result.stderr, '')
        return [json.loads(line) for line in result.stdout.splitlines()]

    def test_exact_source_supported_machine_words_pass(self):
        observation, row, report = self.run_case(0)
        self.assertEqual(observation, {'valid': 1, 'step': 0, 'code': 0, 'query_calls': 1, 'arguments_valid': 1})
        self.assertEqual(row, variant.expected_architecture())
        self.assertEqual(report, {'reported': 1, 'buffer_length': 0})

    def test_native_only_other_arch_extra_order_flags_lengths_and_terminator_refused(self):
        for scenario in (*range(5, 14), 15, 16, 17, 20, 21, 22, 23, 24):
            with self.subTest(scenario=scenario):
                observation, row, _ = self.run_case(scenario)
                self.assertEqual((observation['valid'], observation['step'], observation['code']), (0, 9, 13))
                self.assertEqual(observation['arguments_valid'], 1)

    def test_missing_exports_query_failure_and_prior_error_are_preserved(self):
        for scenario, step, code in ((1, 9, 126), (2, 9, 127), (3, 9, 127), (4, 9, 87), (14, 6, 31)):
            with self.subTest(scenario=scenario):
                observation = self.run_case(scenario)[0]
                self.assertEqual((observation['valid'], observation['step'], observation['code']), (0, step, code))

    def test_report_errors_remain_failures(self):
        for scenario in (18, 19):
            rows = self.run_case(scenario)
            self.assertEqual(rows[0]['valid'], 1)
            self.assertEqual(rows[-1], {'reported': 0, 'buffer_length': 0})


if __name__ == '__main__':
    unittest.main()
