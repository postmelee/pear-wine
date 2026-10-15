# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Original finite binary-bound ARM64 Wine transition analyzer.

Explicit binary/disassembly inputs replace the legacy build-root discovery CLI.
This analysis does not execute Wine or authorize a native transition.
"""
import argparse,hashlib,os,re,signal,struct,subprocess,time
from pathlib import Path
from pear_runtime.errors import Error,need


MAX_BINARY = 64 * 1024 * 1024

MAX_TEXT = 64 * 1024 * 1024

ENTRIES = {
    '___wine_syscall_dispatcher': (1, 1),
    '___wine_syscall_dispatcher_return': (0, 1),
    '___wine_unix_call_dispatcher': (1, 1),
    '_call_user_mode_callback': (0, 1),
    '_user_mode_callback_return': (0, 0),
    '_signal_start_thread': (0, 1),
}

HELPERS = {'_pear_x18_enter_host': 0, '_pear_x18_enter_guest': 1}

POINTERS = ('_pear_x18_getter', '_pear_x18_setter')

HOST_CALLS = {'_trace_usercall', '_trace_userret', '_init_syscall_frame',
              '_syscall_dispatcher_return_slowpath', '_trace_syscall', '_trace_sysret'}

CONDITIONAL = {'b.eq', 'b.ne', 'b.hs', 'b.cs', 'b.lo', 'b.cc', 'b.ls', 'b.hi',
               'b.ge', 'b.gt', 'b.le', 'b.lt', 'b.mi', 'b.pl', 'b.vs', 'b.vc',
               'cbz', 'cbnz', 'tbz', 'tbnz'}

ORDINARY = {'hint', 'bti', 'nop', 'ldr', 'ldrb', 'str', 'stp', 'ldp', 'mov', 'movk',
            'mrs', 'msr', 'and', 'ubfx', 'add', 'sub', 'subs', 'cmp', 'ccmp', 'bfxil',
            'bfi', 'lsr'}

def parse(text):
    """Read the pinned LLVM's linked ARM64 disassembly format, failing closed."""
    need(isinstance(text, str) and 0 < len(text.encode()) <= MAX_TEXT, 'abi_review_text_size')
    need('file format mach-o arm64' in text, 'abi_review_reader_format')
    symbols, instructions, owners = {}, {}, {}
    owner = None
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]+) <([^<>]+)>:', line)
        if match:
            address, owner = int(match[1], 16), match[2]
            if owner in symbols:
                need(owner not in set(ENTRIES) | set(HELPERS) | HOST_CALLS, 'abi_review_duplicate_symbol')
                symbols[owner] = None  # Repeated unrelated translation-unit locals.
            else:
                symbols[owner] = address
            continue
        match = re.match(r'\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{8})\s+(\S+)\s*(.*)', line)
        if match:
            address, word = int(match[1], 16), int(match[2], 16)
            need(owner is not None and address not in instructions and address % 4 == 0,
                 'abi_review_instruction_identity')
            instructions[address] = (word, match[3], match[4].strip())
            owners[address] = owner
        elif re.match(r'\s*[0-9a-fA-F]+:', line):
            raise Error('abi_review_unknown_instruction_format')
    need(instructions and len(instructions) <= MAX_TEXT // 16, 'abi_review_instruction_count')
    return symbols, instructions, owners

def clean(operands):
    return operands.split(';', 1)[0].strip()

def branch_target(operands):
    operand = clean(operands).split(',')[-1].strip()
    match = re.fullmatch(r'0x([0-9a-fA-F]+)(?: <[^<>]+>)?', operand)
    need(match is not None, 'abi_review_unknown_branch')
    return int(match[1], 16)

def canonical(operands):
    value = clean(operands)
    value = re.sub(r'#0x([0-9a-f]+)', lambda m: '#' + str(int(m[1], 16)), value)
    return value.replace(', #0]', ']').replace(' ', '')

def helper_review(name, desired, symbols, instructions, owners):
    rows = [(a, *v) for a, v in sorted(instructions.items()) if owners[a] == name]
    need(rows and rows[0][0] == symbols[name], 'abi_review_helper_missing')
    need(all(not re.search(r'\b[wx]18\b', args) for _, _, _, args in rows), 'abi_review_helper_touches_x18')
    need(all(op in ORDINARY | {'adrp', 'blr', 'ret', 'brk'} | CONDITIONAL for _, _, op, _ in rows),
         'abi_review_helper_unknown_operation')
    need([(op, canonical(args)) for _, _, op, args in rows].count(('mov', 'w19,#' + str(desired))) == 1,
         'abi_review_helper_wrong_mode')
    pairs = {(op, canonical(args)) for _, _, op, args in rows}
    need(('sub', 'sp,sp,#704') in pairs and ('add', 'sp,sp,#704') in pairs,
         'abi_review_helper_stack')
    for register in range(0, 18, 2):
        args = canonical(f'x{register}, x{register + 1}, [sp, #{register * 8}]')
        need(('stp', args) in pairs and ('ldp', args) in pairs, 'abi_review_helper_gpr_preservation')
    for register in range(0, 32, 2):
        args = canonical(f'q{register}, q{register + 1}, [sp, #{192 + register * 16}]')
        need(('stp', args) in pairs and ('ldp', args) in pairs, 'abi_review_helper_simd_preservation')
    args = canonical('x19, x30, [sp, #144]')
    need(('stp', args) in pairs and ('ldp', args) in pairs, 'abi_review_helper_callee_preservation')
    for op, args in [('mrs', 'x16,NZCV'), ('mrs', 'x17,FPCR'), ('stp', 'x16,x17,[sp,#160]'),
                     ('mrs', 'x16,FPSR'), ('str', 'x16,[sp,#176]'), ('ldp', 'x16,x17,[sp,#160]'),
                     ('msr', 'NZCV,x16'), ('msr', 'FPCR,x17'), ('ldr', 'x16,[sp,#176]'), ('msr', 'FPSR,x16')]:
        need((op, args) in pairs, 'abi_review_helper_status_preservation')
    call_indices = [i for i, row in enumerate(rows) if row[2] == 'blr']
    need(len(call_indices) == 3, 'abi_review_helper_api_sequence')
    first_call, last_call = call_indices[0], call_indices[-1]
    for index, (_, _, op, args) in enumerate(rows):
        operands = canonical(args)
        if op in ('stp', 'str') and '[sp' in operands:
            need(index < first_call, 'abi_review_helper_spill_order')
        if op in ('ldp', 'ldr') and '[sp' in operands:
            need(index > last_call, 'abi_review_helper_spill_order')
    calls, page, pointer = [], None, None
    for index, (address, _, op, args) in enumerate(rows):
        if op == 'adrp':
            match = re.fullmatch(r'x16, (0x[0-9a-fA-F]+)(?: <[^<>]+>)?', clean(args))
            need(match is not None, 'abi_review_helper_pointer_page')
            page = int(match[1], 16)
        elif op == 'ldr' and clean(args).startswith('x16, [x16'):
            match = re.fullmatch(r'x16, \[x16(?:, #(0x[0-9a-fA-F]+|[0-9]+))?\]', clean(args))
            need(match is not None and page is not None, 'abi_review_helper_pointer_load')
            pointer = page + (int(match[1], 0) if match[1] else 0)
        elif op == 'blr':
            need(clean(args) == 'x16' and pointer is not None, 'abi_review_helper_call_target')
            calls.append(pointer)
            after = [(x[2], canonical(x[3])) for x in rows[index + 1:index + 4]]
            if len(calls) in (1, 3):
                need(len(after) == 3 and after[:2] == [('and', 'w0,w0,#1'), ('cmp', 'w0,w19')]
                     and after[2][0] == ('b.eq' if len(calls) == 1 else 'b.ne'),
                     'abi_review_helper_mode_verification')
            else:
                need(rows[index - 1][2] == 'mov' and canonical(rows[index - 1][3]) == 'w0,w19',
                     'abi_review_helper_setter_argument')
        if op in CONDITIONAL:
            target = branch_target(args)
            need(target in instructions and instructions[target][1] == 'brk'
                 and owners[target] == name, 'abi_review_helper_failure_path')
    need(len(calls) == 3 and calls[0] == calls[2] and calls[0] != calls[1],
         'abi_review_helper_api_sequence')
    pointer_identity = all(symbol in symbols for symbol in POINTERS)
    if pointer_identity:
        need(calls == [symbols[POINTERS[0]], symbols[POINTERS[1]], symbols[POINTERS[0]]],
             'abi_review_helper_api_identity')
    return {'entry': name, 'requested_mode': desired, 'instruction_count': len(rows),
            'api_sequence': ['getter', 'setter', 'getter'], 'pointer_symbols_bound': pointer_identity,
            'register_spills_checked': True, 'ordinary_calls': 0}

def analyze(text, *, machine_symbols=None):
    """Analyze declared entry contracts; this function alone proves no binary or run."""
    symbols, instructions, owners = parse(text)
    if machine_symbols is not None:
        for name in (*ENTRIES, *HELPERS):
            need(name in machine_symbols and name in symbols and symbols[name] == machine_symbols[name],
                 'abi_review_symbol_mismatch')
        for name in POINTERS:
            need(name in machine_symbols, 'abi_review_pointer_symbol_missing')
            symbols[name] = machine_symbols[name]
    need(all(name in symbols for name in (*ENTRIES, *HELPERS)), 'abi_review_entry_missing')
    helper_results = [helper_review(name, mode, symbols, instructions, owners) for name, mode in HELPERS.items()]
    helper_addresses = {symbols[name]: mode for name, mode in HELPERS.items()}
    checks = []
    for name, (initial, terminal) in ENTRIES.items():
        pending, seen, exits = [(symbols[name], initial, initial == 0)], set(), 0
        while pending:
            address, mode, guest_saved = pending.pop()
            if (address, mode, guest_saved) in seen:
                continue
            seen.add((address, mode, guest_saved))
            need(len(seen) <= 4096 and address in instructions and owners[address] in ENTRIES,
                 'abi_review_uncovered_path')
            _, op, args = instructions[address]
            need(op in ORDINARY | CONDITIONAL | {'bl', 'blr', 'br', 'ret', 'b'},
                 'abi_review_unknown_operation')
            if re.search(r'\b[wx]18\b', args):
                need(mode == 1, 'abi_review_x18_in_host_mode')
            if op == 'stp' and canonical(args) == 'x18,x19,[x10,#144]':
                guest_saved = True
            if op == 'bl':
                target = branch_target(args)
                if target in helper_addresses:
                    desired = helper_addresses[target]
                    need(mode != desired, 'abi_review_redundant_transition')
                    if desired == 0:
                        need(guest_saved, 'abi_review_guest_x18_not_saved')
                    mode = desired
                else:
                    need(mode == 0, 'abi_review_host_call_in_foreign_mode')
                    need(any(symbols.get(allowed) == target for allowed in HOST_CALLS),
                         'abi_review_unknown_host_call')
            elif op == 'blr':
                need(mode == 0, 'abi_review_host_call_in_foreign_mode')
                expected = {'___wine_syscall_dispatcher': 'x23', '___wine_unix_call_dispatcher': 'x16'}
                need(owners[address] in expected and clean(args) == expected[owners[address]],
                     'abi_review_unknown_indirect_call')
            if op in ('ret', 'br'):
                need(mode == terminal, 'abi_review_wrong_return_mode')
                if op == 'br':
                    need(owners[address] == '_call_user_mode_callback' and clean(args) == 'x3',
                         'abi_review_unknown_indirect_branch')
                exits += 1
                continue
            if op == 'b' or op in CONDITIONAL:
                pending.append((branch_target(args), mode, guest_saved))
                if op == 'b':
                    continue
            need(address + 4 in instructions, 'abi_review_incomplete_fallthrough')
            pending.append((address + 4, mode, guest_saved))
        need(exits > 0, 'abi_review_missing_return')
        checks.append({'entry': name, 'required_entry_mode': initial, 'required_return_mode': terminal,
                       'reachable_instruction_states': len(seen), 'terminal_paths': exits,
                       'x18_only_foreign': True, 'ordinary_calls_only_host': True})
    return {'schema_version': 1, 'record_kind': 'wine_abi_assembly_review',
            'scope': 'six_declared_wine_assembly_entries_and_two_mode_helpers',
            'analysis_passed': True, 'binary_binding': 'not_checked', 'runtime_execution': False,
            'entries': checks, 'helpers': helper_results,
            'unqualified': ['arbitrary_native_callbacks', 'signal_context_semantics', 'unwinding',
                            'all_wine_control_flow', 'guest_execution', 'performance']}

def macho(data, *, extra_symbols=()):
    """Bounded ARM64 Mach-O segment/symbol facts used to bind reader output."""
    need(isinstance(data, bytes) and 32 <= len(data) <= MAX_BINARY, 'abi_review_binary_size')
    def take(offset, size):
        need(0 <= offset <= len(data) and 0 <= size <= len(data) - offset, 'abi_review_macho_bounds')
        return data[offset:offset + size]
    def unpack(fmt, offset):
        return struct.unpack('<' + fmt, take(offset, struct.calcsize('<' + fmt)))
    magic, cpu, _, filetype, ncmds, sizeofcmds, _, _ = unpack('8I', 0)
    need(magic == 0xfeedfacf and cpu == 0x100000c and filetype in (6, 8)
         and 0 < ncmds < 4096 and sizeofcmds <= len(data) - 32, 'abi_review_macho_header')
    at, segments, symtab = 32, [], None
    for _ in range(ncmds):
        cmd, size = unpack('II', at)
        need(size >= 8 and size % 8 == 0 and at + size <= 32 + sizeofcmds, 'abi_review_macho_command')
        if cmd == 0x19:
            need(size >= 72, 'abi_review_macho_segment')
            vmaddr, vmsize, fileoff, filesize, _, initprot = unpack('QQQQII', at + 24)
            need(filesize <= vmsize and fileoff + filesize <= len(data), 'abi_review_macho_segment_bounds')
            segments.append((vmaddr, filesize, fileoff, initprot))
        elif cmd == 2:
            need(size == 24 and symtab is None, 'abi_review_macho_symtab')
            symtab = unpack('4I', at + 8)
        at += size
    need(at == 32 + sizeofcmds and symtab is not None, 'abi_review_macho_commands')
    offset, count, strings_at, strings_size = symtab
    need(count <= 1000000 and count * 16 <= len(data), 'abi_review_macho_symbol_count')
    strings = take(strings_at, strings_size)
    need(isinstance(extra_symbols, (tuple, list)) and len(extra_symbols) <= 32 and
         all(isinstance(name, str) and re.fullmatch(r'_[A-Za-z0-9_]{1,128}', name) for name in extra_symbols),
         'abi_review_extra_symbols')
    wanted = set(ENTRIES) | set(HELPERS) | set(POINTERS) | HOST_CALLS | set(extra_symbols)
    symbols = {}
    for index in range(count):
        name_at, kind, _, _, value = unpack('IBBHQ', offset + index * 16)
        if kind & 0xe0 or kind & 0x0e != 0x0e:
            continue
        need(name_at < len(strings), 'abi_review_macho_symbol_string')
        end = strings.find(b'\0', name_at, min(name_at + 4096, len(strings)))
        need(end != -1, 'abi_review_macho_symbol_string')
        try:
            name = strings[name_at:end].decode('utf-8')
        except UnicodeError:
            raise Error('abi_review_macho_symbol_encoding') from None
        if name in wanted:
            need(name not in symbols or symbols[name] == value, 'abi_review_macho_ambiguous_symbol')
            symbols[name] = value
    return symbols, segments

def validate_actual(binary, disassembly):
    """Bind parsed words/symbols to binary bytes. Caller must verify reader provenance."""
    symbols, segments = macho(binary)
    text_symbols, instructions, _ = parse(disassembly)
    for name, address in text_symbols.items():
        if name in symbols:
            need(address == symbols[name], 'abi_review_symbol_mismatch')
    for address, (word, _, _) in instructions.items():
        matches = [offset + address - base for base, size, offset, protection in segments
                   if protection & 4 and base <= address and address + 4 <= base + size]
        need(len(matches) == 1, 'abi_review_instruction_mapping')
        need(binary[matches[0]:matches[0] + 4] == struct.pack('<I', word), 'abi_review_instruction_bytes')
    result = analyze(disassembly, machine_symbols=symbols)
    result.update(binary_binding='verified', binary_sha256=hashlib.sha256(binary).hexdigest(),
                  disassembly_sha256=hashlib.sha256(disassembly.encode()).hexdigest(),
                  instruction_bytes_checked=len(instructions), trusted_reader_required=True)
    return result

def reproduce_reader(command, expected, env=None):
    """Rerun only the already verified native disassembler, with bounded output."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(command['argv'], cwd=command['cwd'], stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, start_new_session=True, env=env)
        deadline = time.monotonic() + 30
        try:
            while process.poll() is None:
                need(time.monotonic() < deadline and os.fstat(out.fileno()).st_size <= MAX_TEXT
                     and os.fstat(err.fileno()).st_size <= 65536, 'abi_review_reader_bounds')
                time.sleep(.02)
            need(process.returncode == 0, 'abi_review_reader_failed')
            out.seek(0)
            err.seek(0)
            need(out.read(MAX_TEXT + 1) == expected and not err.read(65537), 'abi_review_reader_output_changed')
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--disassembly',type=Path,required=True)
    args=parser.parse_args(argv)
    from pear_runtime.assembly._common import read_relative
    import json
    binary=read_relative(args.binary.parent,args.binary.name,MAX_BINARY)
    text=read_relative(args.disassembly.parent,args.disassembly.name,MAX_TEXT).decode('utf-8')
    result=validate_actual(binary,text)
    result['runtime_execution_performed']=False
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0


if __name__=='__main__':raise SystemExit(main())
