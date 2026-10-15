# Native fixture source notices

The sources listed in [fixture-source-manifest.json](../fixture-source-manifest.json)
are exact imports from the selected Pear checkpoint. They retain all existing
MIT and LGPL notices. Unmarked original Pear files retain GPL-3.0-or-later adoption,
with [license text](../COPYING). Adjacent attribution preserves the admitted bytes;
it does not claim all historical files have modern inline SPDX headers.

The Cocoa upstream baseline is copyright Ken Thomases / CodeWeavers and
LGPL-2.1-or-later; its exact COPYING.LIB and source notice are retained in
`fixtures/cocoa_startup/`. Mock and harness files retain their own terms.
These are redistributable synthetic tests, not game files or runtime qualification.
The canonical native ABI implementation is `dlls/ntdll/unix/pear_abi_fixture.c`;
there is no second editable `abi_native.c` copy in this test directory.
