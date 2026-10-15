# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Generate one exact API fixture for the selected ARM64EC Wine enumeration.

The canonical original fixture and native-only oracle remain unchanged. Only
its fixed class-181 expected entry count/words differ. Generated C belongs in a
retained build directory; this generator is the single editable variant owner.
"""
from pathlib import Path
import argparse
import hashlib
import json

ORIGINAL_SHA256 = '00ce66bba9690a0c23f945ca447465639794ccca2e2e418777b2809ecd41e1d8'
ORIGINAL_SIZE = 12610
VARIANT = 'arm64ec-class181-arm64-i386-v1'
OLD = b'''    if (status != 0 || architecture_bytes != 8 || architecture_count != 1 ||
        architecture_words[0] != (0xAA64u | (7u << 16)) || architecture_terminator != 0)
'''
NEW = b'''    if (status != 0 || architecture_bytes != 12 || architecture_count != 2 ||
        architecture_words[0] != (0xAA64u | (7u << 16)) ||
        architecture_words[1] != (0x014Cu | (18u << 16)) || architecture_terminator != 0)
'''


def generate(original):
    if (type(original) is not bytes or len(original) != ORIGINAL_SIZE or
            hashlib.sha256(original).hexdigest() != ORIGINAL_SHA256 or original.count(OLD) != 1):
        raise ValueError('native_api_original_source_changed')
    return original.replace(OLD, NEW, 1)


def expected_architecture():
    return {'version': 1, 'record_kind': 'pear_architecture_result', 'status': 0,
            'returned_bytes': 12, 'machines': [43620, 332], 'flags': [7, 18], 'terminator': 0}


def provenance(original):
    generated = generate(original)
    return {'schema_version': 1, 'scope': 'exact_native_api_fixture_variant', 'variant': VARIANT,
            'original_sha256': ORIGINAL_SHA256, 'original_size_bytes': ORIGINAL_SIZE,
            'generated_sha256': hashlib.sha256(generated).hexdigest(), 'generated_size_bytes': len(generated),
            'expected_architecture': expected_architecture(), 'replacement_count': 1,
            'runtime_modified': False, 'original_native_only_fixture_modified': False,
            'claim': 'Selected class-181 enumeration only; no i386 execution or cold-prefix support claim.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path)
    parser.add_argument('--bindings', type=Path)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.recipe is not None:
        if args.bindings is None or args.source is not None:
            raise ValueError('native_api_build_arguments')
        build(args.recipe, args.bindings, args.output)
        return
    if args.source is None or args.bindings is not None:
        raise ValueError('native_api_generation_arguments')
    source = args.source
    if not source.is_absolute() or source.resolve(strict=True) != source or source.is_symlink():
        raise ValueError('native_api_source_alias')
    output = args.output
    if not output.is_absolute() or output.parent.resolve(strict=True) != output.parent:
        raise ValueError('native_api_output_parent')
    raw = source.read_bytes()
    generated = generate(raw)
    output.mkdir(mode=0o700)
    (output/'api-arm64ec.c').write_bytes(generated)
    (output/'generation.json').write_text(json.dumps(provenance(raw), indent=2, sort_keys=True)+'\n')


def tool_input_rows(manifest):
    """Exact installed tool/header/library input set; no live directory discovery."""
    selected = []
    required = {'bin/clang', 'bin/clang-23', 'bin/ld.lld', 'bin/lld',
                'lib/libLLVM.23.1.dylib', 'lib/libclang-cpp.23.1.dylib',
                'aarch64-w64-mingw32/lib/libkernel32.a',
                'bin/aarch64-w64-windows-gnu.cfg', 'bin/mingw32-common.cfg'}
    rows = manifest['files']; seen = {row['path'] for row in rows}
    if not required <= seen: raise ValueError('native_api_tool_manifest_missing')
    for row in rows:
        name = row['path']
        if not (name in required or name.startswith(('generic-w64-mingw32/include/', 'lib/clang/23/include/'))):
            continue
        value = {'root': 'tools', 'path': 'llvm-mingw/'+name}
        if 'symlink' in row:
            value.update(kind='symlink', target=row['symlink'])
        else:
            value.update(sha256=row['sha256'], size_bytes=row['size_bytes'])
        selected.append(value)
        if name.startswith('generic-w64-mingw32/include/'):
            selected.append({**value, 'path': 'llvm-mingw/aarch64-w64-mingw32/include/'+name.split('/include/',1)[1]})
    return sorted(selected, key=lambda row: row['path'])


def verify_tool_inputs(recipe, context, original):
    from pear_runtime.build import load, fact
    from pear_runtime.errors import need
    prepared_path = context.input('tools', 'prepared.json', original['tool_prepared_sha256'])
    prepared = load(prepared_path)
    tool = next(row for row in prepared['artifacts'] if row['id'] == 'llvm-mingw')
    manifest = context.input('tools', 'llvm-mingw-files.json', tool['files_manifest']['sha256'])
    expected = tool_input_rows(load(manifest))
    actual = sorted([row for row in recipe['inputs'] if row['root']=='tools' and
                     row['path'].startswith('llvm-mingw/')], key=lambda row: row['path'])
    need(actual == expected, 'native_api_tool_input_set')
    directory = context.root('tools')/'llvm-mingw/aarch64-w64-mingw32/include'
    need(directory.is_symlink() and str(directory.readlink()) == '../generic-w64-mingw32/include',
         'native_api_include_alias')
    return {'prepared_ref': fact(prepared_path), 'manifest_ref': fact(manifest),
            'directory_link': {'path': str(directory), 'target': '../generic-w64-mingw32/include'}}


def build(recipe_path, bindings_path, output):
    """Compile the exact generated fixture using the common bounded builder.

    The caller reviews and pins the private recipe/bindings. Every implicit
    toolchain input is admitted by its original installed-files manifest.
    This operation produces a PE and never loads or executes it.
    """
    from pear_runtime import build as common
    from pear_runtime.assembly import core
    from pear_runtime.errors import need
    recipe_ref, bindings_ref = common.fact(recipe_path), common.fact(bindings_path)
    recipe, bindings = common.load(recipe_path), common.load(bindings_path)
    need(recipe.get('name') == 'native-api-arm64ec-v1' and
         set(recipe['roots']) == {'wine','runtime','tools','baseline','configuration','host'}, 'native_api_build_recipe')
    with common.Context(recipe_path, bindings_path, output) as context:
        source = context.input('wine', 'pear/tests/fixtures/api_pe.c', ORIGINAL_SHA256)
        generator = context.input('wine', 'pear/native_api_variant.py')
        need(generator == Path(__file__).resolve() and common.fact(generator)['sha256'] == recipe['generator_sha256'],
             'native_api_generator')
        original = common.load(context.input('baseline','build.json'))
        need(original['passed'] is True and original['fixture_hashes']['api_pe.c'] == ORIGINAL_SHA256,
             'native_api_original_build')
        commands = [row for row in original['commands'] if row['id'] == 'fixture-api-arm64']
        need(len(commands) == 1 and commands[0]['exit_code'] == 0, 'native_api_original_recipe')
        tool_evidence = verify_tool_inputs(recipe, context, original)
        old = commands[0]['argv']
        expected = [str(context.root('host')/'arch'), '-arm64',
                    str(context.root('tools')/'llvm-mingw/bin/clang'),
                    '--target=aarch64-w64-windows-gnu', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-O1', '-fno-builtin', '-nostdlib', '-Wl,-e,mainCRTStartup']
        need(old[:12] == expected and old[13:15] == ['-lkernel32','-o'] and
             Path(old[12]).name == 'api_pe.c' and len(old) == 16, 'native_api_original_argv')
        generated = context.path('api-arm64ec.c'); generated.write_bytes(generate(source.read_bytes()))
        context.record_output('api-arm64ec.c')
        generation = context.path('generation.json'); common.write_json(generation, provenance(source.read_bytes()))
        context.record_output('generation.json')
        target = context.path('api-arm64ec.exe'); depfile = context.path('api-arm64ec.d')
        argv = [*expected, str(generated), '-lkernel32', '-o', str(target), '-MD', '-MF', str(depfile), '-v']
        context.run('fixture-api-arm64ec', argv, cwd=context.output, timeout=60, max_output_bytes=1024**2)
        context.record_output('api-arm64ec.exe'); context.record_output('api-arm64ec.d')
        deps = context.audit_depfile(depfile)
        need(any(row['path'] == str(generated) for row in deps), 'native_api_source_dependency')
        # A plain native ARM64 executable is required, not a hybrid or x64 DLL.
        import struct
        raw = target.read_bytes(); need(len(raw) >= 256 and raw[:2] == b'MZ', 'native_api_pe')
        pe = struct.unpack_from('<I',raw,60)[0]
        need(pe+26 <= len(raw) and raw[pe:pe+4] == b'PE\0\0' and
             struct.unpack_from('<H',raw,pe+4)[0] == 0xaa64 and
             struct.unpack_from('<H',raw,pe+24)[0] == 0x20b and
             not struct.unpack_from('<H',raw,pe+22)[0] & 0x2000, 'native_api_pe')
        need(common.fact(recipe_path) == recipe_ref and common.fact(bindings_path) == bindings_ref,
             'native_api_build_inputs_changed')
        need(verify_tool_inputs(recipe, context, original) == tool_evidence, 'native_api_tools_changed')
        return context.finish('passed', extra={'variant': VARIANT, 'recipe_ref': recipe_ref,
            'bindings_ref': bindings_ref, 'generator_ref': common.fact(generator),
            'source_ref': common.fact(source), 'generation_ref': common.fact(generation),
            'original_build_ref': common.fact(context.root('baseline')/'build.json'),
            'tool_evidence': tool_evidence, 'artifacts': {'native_api_pe': common.fact(target)}, 'expected_architecture': expected_architecture(),
            'claim': 'Synthetic native API fixture; runtime and original fixture unchanged.'})


if __name__ == '__main__':
    main()
