# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic disassembly rejection tests; these never execute Wine or x18 code."""
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock

from pear_runtime.errors import Error
from pear import abi_review


def program():
    functions = {}
    for name, desired, base in [('_pear_x18_enter_host', 0, 0x100), ('_pear_x18_enter_guest', 1, 0x300)]:
        ops = [('sub', 'sp, sp, #0x2c0')]
        ops += [('stp', f'x{i}, x{i+1}, [sp, #{i*8}]') for i in range(0, 18, 2)]
        ops += [('stp', 'x19, x30, [sp, #144]'), ('mrs', 'x16, NZCV'), ('mrs', 'x17, FPCR'),
                ('stp', 'x16, x17, [sp, #160]'), ('mrs', 'x16, FPSR'), ('str', 'x16, [sp, #176]')]
        ops += [('stp', f'q{i}, q{i+1}, [sp, #{192+i*16}]') for i in range(0, 32, 2)]
        ops += [('mov', f'w19, #{desired}'), ('adrp', 'x16, 0x8000'), ('ldr', 'x16, [x16]'),
                ('cbz', 'x16, FAIL'), ('blr', 'x16'), ('and', 'w0, w0, #1'), ('cmp', 'w0, w19'), ('b.eq', 'FAIL'),
                ('adrp', 'x16, 0x8000'), ('ldr', 'x16, [x16, #8]'), ('cbz', 'x16, FAIL'),
                ('mov', 'w0, w19'), ('blr', 'x16'), ('adrp', 'x16, 0x8000'), ('ldr', 'x16, [x16]'),
                ('blr', 'x16'), ('and', 'w0, w0, #1'), ('cmp', 'w0, w19'), ('b.ne', 'FAIL')]
        ops += [('ldp', f'q{i}, q{i+1}, [sp, #{192+i*16}]') for i in range(0, 32, 2)]
        ops += [('ldp', 'x16, x17, [sp, #160]'), ('msr', 'NZCV, x16'), ('msr', 'FPCR, x17'),
                ('ldr', 'x16, [sp, #176]'), ('msr', 'FPSR, x16'), ('ldp', 'x19, x30, [sp, #144]')]
        ops += [('ldp', f'x{i}, x{i+1}, [sp, #{i*8}]') for i in range(0, 18, 2)]
        ops += [('add', 'sp, sp, #0x2c0'), ('ret', ''), ('brk', '#0x504')]
        fail = hex(base + (len(ops)-1) * 4)
        functions[name] = (base, [(op, args.replace('FAIL', fail)) for op, args in ops])
    functions.update({
        '___wine_syscall_dispatcher': (0x1000, [('ldr', 'x10, [x18, #0x378]'),
            ('stp', 'x18, x19, [x10, #0x90]'), ('bl', '0x100'), ('blr', 'x23'),
            ('bl', '0x300'), ('ldp', 'x18, x19, [sp, #0x90]'), ('ret', 'x16')]),
        '___wine_syscall_dispatcher_return': (0x1100, [('bl', '0x300'),
            ('ldp', 'x18, x19, [sp, #0x90]'), ('ret', 'x16')]),
        '___wine_unix_call_dispatcher': (0x1200, [('ldr', 'x10, [x18, #0x378]'),
            ('stp', 'x18, x19, [x10, #0x90]'), ('bl', '0x100'), ('blr', 'x16'),
            ('bl', '0x300'), ('ldp', 'x18, x19, [sp, #0x90]'), ('ret', 'x17')]),
        '_call_user_mode_callback': (0x1300, [('bl', '0x9000'), ('bl', '0x300'),
            ('mov', 'x18, x19'), ('br', 'x3')]),
        '_user_mode_callback_return': (0x1400, [('bl', '0x9100'), ('ret', '')]),
        '_signal_start_thread': (0x1500, [('bl', '0x9200'), ('b', '0x1100')]),
        '_trace_usercall': (0x9000, [('ret', '')]),
        '_trace_userret': (0x9100, [('ret', '')]),
        '_init_syscall_frame': (0x9200, [('ret', '')]),
    })
    return functions


def text(functions):
    lines = ['fixture: file format mach-o arm64', 'Disassembly of section __TEXT,__text:']
    for name, (address, ops) in sorted(functions.items(), key=lambda row: row[1][0]):
        lines.append(f'{address:016x} <{name}>:')
        for index, (op, args) in enumerate(ops):
            # Words are placeholders in synthetic analysis tests. No binary or
            # real-reader qualification is claimed by analyze().
            lines.append(f'{address + index*4:x}: d503201f\t{op}\t{args}')
    return '\n'.join(lines) + '\n'


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.functions = program()

    def rejects(self, code):
        with self.assertRaises(Error) as caught:
            abi_review.analyze(text(self.functions))
        self.assertEqual(caught.exception.code, code)

    def test_six_declared_contracts_pass_without_claiming_execution(self):
        result = abi_review.analyze(text(self.functions))
        self.assertTrue(result['analysis_passed'])
        self.assertFalse(result['runtime_execution'])
        self.assertEqual(result['binary_binding'], 'not_checked')
        self.assertEqual(len(result['entries']), 6)
        self.assertFalse(result['helpers'][0]['pointer_symbols_bound'])

    def test_missing_host_transition_rejects_real_native_call_path(self):
        self.functions['___wine_syscall_dispatcher'][1][2] = ('nop', '')
        self.rejects('abi_review_host_call_in_foreign_mode')

    def test_x18_restoration_before_foreign_enable_is_rejected(self):
        self.functions['___wine_unix_call_dispatcher'][1][4] = ('ldp', 'x18, x19, [sp, #0x90]')
        self.rejects('abi_review_x18_in_host_mode')

    def test_guest_value_must_be_saved_before_disabling_mode(self):
        self.functions['___wine_syscall_dispatcher'][1][1] = ('nop', '')
        self.rejects('abi_review_guest_x18_not_saved')

    def test_callback_enable_in_wrong_current_mode_is_rejected(self):
        self.functions['_call_user_mode_callback'][1][0] = ('bl', '0x100')
        self.rejects('abi_review_redundant_transition')

    def test_returning_to_guest_in_host_mode_is_rejected(self):
        self.functions['___wine_syscall_dispatcher_return'][1][:] = [('ret', 'x16')]
        self.rejects('abi_review_wrong_return_mode')

    def test_conditional_path_cannot_skip_host_transition(self):
        self.functions['___wine_syscall_dispatcher'][1][0] = ('cbz', 'x0, 0x100c')
        self.rejects('abi_review_host_call_in_foreign_mode')

    def test_unknown_branch_target_is_not_silently_uncovered(self):
        self.functions['_signal_start_thread'][1][1] = ('b', '0x9998')
        self.rejects('abi_review_uncovered_path')

    def test_missing_entry_and_truncated_fallthrough_fail(self):
        del self.functions['_signal_start_thread']
        self.rejects('abi_review_entry_missing')
        self.functions = program()
        self.functions['_signal_start_thread'][1].pop()
        self.rejects('abi_review_incomplete_fallthrough')

    def test_unrecognized_instruction_fails(self):
        self.functions['_signal_start_thread'][1][0] = ('udf', '#0')
        self.rejects('abi_review_unknown_operation')

    def test_helper_target_mode_must_match_contract(self):
        ops = self.functions['_pear_x18_enter_host'][1]
        index = ops.index(('mov', 'w19, #0'))
        ops[index] = ('mov', 'w19, #1')
        self.rejects('abi_review_helper_wrong_mode')

    def test_helper_x18_access_and_missing_spills_are_rejected(self):
        self.functions['_pear_x18_enter_host'][1][1] = ('mov', 'x18, x0')
        self.rejects('abi_review_helper_touches_x18')
        self.functions = program()
        ops = self.functions['_pear_x18_enter_guest'][1]
        ops[ops.index(('ldp', 'q8, q9, [sp, #320]'))] = ('nop', '')
        self.rejects('abi_review_helper_simd_preservation')

    def test_helper_must_check_getter_after_setter(self):
        ops = self.functions['_pear_x18_enter_guest'][1]
        index = next(i for i, value in enumerate(ops) if value[0] == 'b.ne')
        ops[index] = ('b.eq', ops[index][1])
        self.rejects('abi_review_helper_mode_verification')

    def test_api_pointer_symbols_are_bound_when_available(self):
        symbols = {name: row[0] for name, row in self.functions.items()}
        symbols.update(_pear_x18_getter=0x8000, _pear_x18_setter=0x8008)
        result = abi_review.analyze(text(self.functions), machine_symbols=symbols)
        self.assertTrue(all(row['pointer_symbols_bound'] for row in result['helpers']))
        symbols['_pear_x18_setter'] += 8
        with self.assertRaisesRegex(Error, 'abi_review_helper_api_identity'):
            abi_review.analyze(text(self.functions), machine_symbols=symbols)

    def test_helper_cannot_restore_volatile_state_before_its_calls(self):
        ops = self.functions['_pear_x18_enter_host'][1]
        restore = ops.index(('ldp', 'x0, x1, [sp, #0]'))
        ops[1], ops[restore] = ops[restore], ops[1]
        self.rejects('abi_review_helper_spill_order')

    def test_unrelated_static_symbols_may_repeat_but_required_entries_cannot(self):
        valid = text(self.functions)
        extra = 'a000 <_unrelated_local>:\na000: d503201f nop\na004 <_unrelated_local>:\na004: d503201f nop\n'
        self.assertTrue(abi_review.analyze(valid + extra)['analysis_passed'])
        with self.assertRaisesRegex(Error, 'abi_review_duplicate_symbol'):
            abi_review.analyze(valid + 'a100 <_signal_start_thread>:\na100: d503201f nop\n')

    def test_wrong_architecture_is_not_an_arm64_review(self):
        with self.assertRaisesRegex(Error, 'abi_review_reader_format'):
            abi_review.analyze(text(self.functions).replace('mach-o arm64', 'mach-o x86-64'))


class BindingTests(unittest.TestCase):
    def test_short_and_wrong_target_binaries_are_rejected(self):
        with self.assertRaisesRegex(Error, 'abi_review_binary_size'):
            abi_review.macho(b'not a binary')
        data = struct.pack('<8I', 0xfeedfacf, 0x1000007, 0, 6, 1, 8, 0, 0) + b'\0'*8
        with self.assertRaisesRegex(Error, 'abi_review_macho_header'):
            abi_review.macho(data)

    def test_overlapping_mapping_and_changed_word_are_rejected(self):
        fixture = text(program())
        symbols, instructions, _ = abi_review.parse(fixture)
        symbols.update(_pear_x18_getter=0x8000, _pear_x18_setter=0x8008)
        data = bytearray(0xa000)
        for address in instructions:
            data[address:address+4] = struct.pack('<I', 0xd503201f)
        with mock.patch.object(abi_review, 'macho', return_value=(symbols, [(0, len(data), 0, 5)])):
            # Only this test mocks Mach-O parsing. It does not count as actual
            # binary, tool, signing or runtime qualification.
            result = abi_review.validate_actual(bytes(data), fixture)
            self.assertEqual(result['instruction_bytes_checked'], len(instructions))
            data[0x1000] ^= 1
            with self.assertRaisesRegex(Error, 'abi_review_instruction_bytes'):
                abi_review.validate_actual(bytes(data), fixture)
        with mock.patch.object(abi_review, 'macho', return_value=(symbols, [(0, len(data), 0, 5)]*2)):
            with self.assertRaisesRegex(Error, 'abi_review_instruction_mapping'):
                abi_review.validate_actual(bytes(data), fixture)


if __name__ == '__main__':
    unittest.main()
