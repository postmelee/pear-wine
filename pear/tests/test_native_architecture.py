# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Execute exact configure and server architecture decisions from the patch.

The extracted Wine code is LGPL-2.1-or-later. Synthetic prefix types and host
capabilities exercise ordinary native code; these tests do not execute Wine,
Windows code, a translator, signing, or restricted host operations.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from source_inputs import materialize, upstream_source


def patch_sources():
    return {name:(upstream_source(name),materialize(name)) for name in
            ('configure','configure.ac','server/Makefile.in','server/registry.c')}


def function(text, marker):
    if text.count(marker) != 1:
        raise ValueError('expected exactly one complete source function')
    start = text.index(marker)
    return text[start:text.index('\n}\n', start) + 3]


def configure_policy(text, autoconf=False):
    declaration = ('AC_SUBST(PEAR_NATIVE_ONLY_ARCH_CFLAGS,"")' if autoconf else
                   'PEAR_NATIVE_ONLY_ARCH_CFLAGS=""')
    if text.count(declaration) != 1 or text.count('pear_native_only_archs=\n') != 1:
        raise ValueError('missing native-only configure policy')
    start = text.index('pear_native_only_archs=\n')
    block = text[start:text.index('\nesac\n', start) + len('\nesac\n')]
    return 'PEAR_NATIVE_ONLY_ARCH_CFLAGS=""\n' + block


class ConfigurePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = patch_sources()
        cls.policy = configure_policy(cls.sources['configure'][1])

    def selection(self, host, system, architectures):
        script = self.policy + '\nprintf "%s\\n" "$PEAR_NATIVE_ONLY_ARCH_CFLAGS"\n'
        result = subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True,
                                timeout=5, env={'PATH': '/usr/bin:/bin', 'HOST_ARCH': host,
                                              'host_os': system, 'PE_ARCHS': architectures})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return result.stdout.strip()

    def test_generated_and_authored_configuration_run_identical_policy(self):
        self.assertEqual(configure_policy(self.sources['configure.ac'][1], True), self.policy)

    def test_only_native_darwin_arm64_target_enables_policy(self):
        for architectures in ('aarch64', ' aarch64', '  aarch64 \t\n'):
            with self.subTest(architectures=architectures):
                self.assertEqual(self.selection('aarch64', 'darwin25.5.0', architectures),
                                 '-DPEAR_NATIVE_ONLY_ARCH=1')

    def test_companion_empty_and_non_native_targets_preserve_upstream_selection(self):
        for architectures in ('', 'none', 'aarch64 arm64ec', ' aarch64 x86_64',
                              'i386 aarch64', 'aarch64 arm', 'arm64ec', 'aarch64 aarch64'):
            with self.subTest(architectures=architectures):
                self.assertEqual(self.selection('aarch64', 'darwin25.5.0', architectures), '')

    def test_other_hosts_and_platforms_do_not_enable_policy(self):
        for host, system in (('x86_64', 'darwin25'), ('i386', 'darwin25'), ('arm', 'darwin25'),
                             ('aarch64', 'linux-gnu'), ('aarch64', 'freebsd14'), ('aarch64', 'mingw32')):
            with self.subTest(host=host, system=system):
                self.assertEqual(self.selection(host, system, 'aarch64'), '')

    def test_selected_flag_reaches_server_make_recipe(self):
        make = shutil.which('make')
        if not make:
            self.skipTest('make unavailable')
        server = self.sources['server/Makefile.in'][1].split('SOURCES =', 1)[0]
        # Use the actual Makefile definitions with the configure-selected value.
        for architectures, expected in (('aarch64', '-DPEAR_NATIVE_ONLY_ARCH=1'),
                                         ('aarch64 arm64ec', '')):
            flag = self.selection('aarch64', 'darwin25', architectures)
            recipe = ('PEAR_NATIVE_ONLY_ARCH_CFLAGS = ' + flag + '\n' + server +
                      '\nall:\n\t@printf "%s\\n" "$(EXTRADEFS)"\n')
            result = subprocess.run([make, '-f', '-'], input=recipe, capture_output=True,
                                    text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), expected)
        generated = self.sources['configure'][1]
        self.assertIn('\nPEAR_NATIVE_ONLY_ARCH_CFLAGS\n', generated)
        self.assertIn('PEAR_NATIVE_ONLY_ARCH_CFLAGS = $PEAR_NATIVE_ONLY_ARCH_CFLAGS\n', generated)


PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PREFIX_32BIT 32
#define PREFIX_64BIT 64
#define IMAGE_FILE_MACHINE_I386 0x014c
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_ARMNT 0x01c4
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
static int prefix_type, can_arm32, probes;
static unsigned int supported_machines_count;
static unsigned short supported_machines[8], native_machine;
static int supports_aarch32(void) { ++probes; return can_arm32; }
'''


class ServerArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        clang = shutil.which('clang')
        if not clang:
            raise unittest.SkipTest('native C compiler unavailable')
        cls.temp = tempfile.TemporaryDirectory(prefix='pear-native-architecture-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        before, after = patch_sources()['server/registry.c']
        marker = 'static void init_supported_machines(void)\n'
        bodies = {'before': function(before, marker), 'plain': function(after, marker),
                  'pear': function(after, marker), 'nonapple': function(after, marker)}
        text, names = PREAMBLE, []
        for arch in ('aarch64', 'x86_64', 'i386', 'arm'):
            for variant, body in bodies.items():
                name = variant + '_' + arch
                names.append(name)
                text += '\n' + ''.join('#undef __' + item + '__\n' for item in
                                        ('aarch64', 'x86_64', 'i386', 'arm', 'APPLE'))
                text += '#undef PEAR_NATIVE_ONLY_ARCH\n#define __' + arch + '__ 1\n'
                if variant != 'nonapple':
                    text += '#define __APPLE__ 1\n'
                if variant in ('pear', 'nonapple'):
                    text += '#define PEAR_NATIVE_ONLY_ARCH 1\n'
                text += body.replace('init_supported_machines', name)
        text += '\nstatic void (*decisions[])(void) = {' + ','.join(names) + '};\n'
        text += r'''
int main(int argc, char **argv)
{
    if (argc != 4) return 64;
    unsigned int variant = (unsigned int)atoi(argv[1]);
    if (variant >= sizeof(decisions) / sizeof(decisions[0])) return 65;
    prefix_type = atoi(argv[2]);
    can_arm32 = atoi(argv[3]);
    decisions[variant]();
    printf("%u %04x %d", supported_machines_count, native_machine, probes);
    for (unsigned int i = 0; i < supported_machines_count; ++i)
        printf(" %04x", supported_machines[i]);
    putchar('\n');
    return 0;
}
'''
        source = cls.folder / 'decisions.c'
        source.write_text(text)
        cls.binary = cls.folder / 'decisions'
        result = subprocess.run([clang, '-std=c11', '-Wall', '-Wextra', '-Werror',
                                 '-fsanitize=undefined', '-fno-sanitize-recover=all', str(source),
                                 '-o', str(cls.binary)], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)
        cls.names = names

    def observe(self, arch='aarch64', variant='pear', prefix=64, aarch32=False):
        result = subprocess.run([str(self.binary), str(self.names.index(variant + '_' + arch)),
                                 str(prefix), str(int(aarch32))], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        fields = result.stdout.split()
        count, native, probes = int(fields[0]), int(fields[1], 16), int(fields[2])
        machines = [int(value, 16) for value in fields[3:]]
        self.assertEqual(count, len(machines))
        return native, probes, machines

    def test_native_only_advertises_exact_arm64_without_companion_probe(self):
        for available in (False, True):
            self.assertEqual(self.observe(aarch32=available), (0xaa64, 0, [0xaa64]))

    def test_original_arm64_companions_remain_when_policy_is_disabled(self):
        for available in (False, True):
            expected = [0xaa64, 0x014c] + ([0x01c4] if available else []) + [0x8664]
            for variant in ('before', 'plain', 'nonapple'):
                self.assertEqual(self.observe(variant=variant, aarch32=available), (0xaa64, 1, expected))

    def test_32bit_arm64_prefix_still_has_no_supported_machine(self):
        for variant in ('before', 'plain', 'pear', 'nonapple'):
            self.assertEqual(self.observe(variant=variant, prefix=32), (0, 0, []))

    def test_other_host_architectures_preserve_original_lists(self):
        for arch in ('x86_64', 'i386', 'arm'):
            for prefix in (32, 64):
                expected = self.observe(arch, 'before', prefix)
                for variant in ('plain', 'pear', 'nonapple'):
                    with self.subTest(arch=arch, prefix=prefix, variant=variant):
                        self.assertEqual(self.observe(arch, variant, prefix), expected)


if __name__ == '__main__':
    unittest.main()
