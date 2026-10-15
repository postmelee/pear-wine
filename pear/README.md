# Pear Wine source handoff

This repository owns Wine host/PE source, native memory owner, loader/CHPE integration and Wine-side graphics provider. The exact imported source range is recorded in [source-manifest.json](source-manifest.json), including the unchanged upstream pin/tree, ordered original patch identities, source modes, and original Pear commit correspondence. Accepted baseline and selected checkpoint are separate commits. Original upstream history and notices are preserved.

The pinned upstream commit is `4e819f054dd2d9ee855ee3f1e30d8c1bb8f80fcf`. The selected range contains 58 changed source units. A merged source view is not a claim that every retained compiled object used that same view. Build recipes must preserve their per-artifact source/configuration correspondence. Wine 11/CodeWeavers Preview is a separate lineage.

## Source checks available now

From this repository root, using Python 3 and Git:

```sh
python3 -B pear/verify_source.py
python3 -B -m unittest discover -s pear/tests -p 'test_*.py' -v
python3 -B pear/verify_source.py --peer pear-dxmt=../pear-dxmt
```

These commands check selected source identities, modes, ancestry, closed source changes, forbidden generated/private headers and optional peer-header identity. They do not compile or execute the runtime. Upstream tests remain retained; the [test ownership map](test-ownership.json) names each selected original component/integration test, exact identity, single destination and remaining adaptation/execution work. New source-admission tests do not substitute for the original ABI, memory, loader or graphics failure oracles.

## Build and verification owner

[pear-runtime](https://github.com/postmelee/pear-runtime) owns portable build/assembly, immutable input locks, generated diagnostic schemas, signing/admission and paired integration tests. Its Stage 3 recipe implementation is pending at this source-import checkpoint; no unimplemented build command is claimed here. The bounded first reconstruction may reuse explicitly declared immutable lower-layer objects and admitted tools. It must compile current selected units from these forks into isolated outputs and verify all implicit headers, helpers and libraries.

Wine requires the admitted LLVM-MinGW/Bison toolchain and Apple SDK/native tools. Graphics additionally requires admitted native LLVM 15, CMake/Ninja/Meson/Python and Metal tooling. Preserve the exact recorded target/flags and generated shader inputs; a new tool version requires re-admission. Game files, authenticated prefixes, owned image/spec inputs and signing material are never source dependencies in this repository.

## Shared source authority

`pear-runtime/include/PearAbortObservation.h` is a generated build input owned by the common runtime. This fork intentionally does not track another copy. Wine exports `include/wine/pear_fex_memory.h` and the v1/v2 typed graphics provider headers. DXMT owns its upstream `winemetal.h` and `winemetal_thunks.h`; the Wine copies are pinned consumer mirrors.

Canonical provider paths and exact digests are in the manifest. Frozen historical patches are provenance, not a second editable implementation. Final source authority cutover is pending owner acceptance; this import alone does not activate a runtime.

## Licensing and contributions

Upstream Wine/DXMT LGPL terms and existing MIT or other per-file notices remain unchanged. Copied/adapted inputs retain their original attribution and version-specific component notices. New original scripts/tests under `pear/` carry GPL-3.0-or-later SPDX notices; [COPYING](COPYING) supplies that license text and does not relicense the imported component.

DXMT's upstream contribution policy rejects AI-generated/co-authored contributions. This private downstream work does not authorize an upstream submission, rewrite upstream authorship or claim upstream acceptance. Preserve the original contribution policy.

## Related repositories and limits

- [pear-wine](https://github.com/postmelee/pear-wine): Wine host/PE implementation and ABI providers.
- [pear-fex](https://github.com/postmelee/pear-fex): translator/frontend implementation.
- [pear-dxmt](https://github.com/postmelee/pear-dxmt): renderer and Metal consumer.
- [pear-runtime](https://github.com/postmelee/pear-runtime): compatible composition, build, verification and recovery.
- [Pear](https://github.com/postmelee/pear): app/Steam/game policy and development selection.

These repositories currently require collaborator access. Source validation, compilation, synthetic runtime tests, game qualification and public distribution are separate claims. No newly reconstructed runtime, Megabonk success, general no-Rosetta coverage or public distribution qualification is established at this import checkpoint. Preserve the previous environment and recovery inputs until the new handoff is verified.
