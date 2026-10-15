# Pear Wine source handoff

This repository owns Wine host/PE source, native memory owner, loader/CHPE integration and Wine-side graphics provider. The exact imported source range is recorded in [source-manifest.json](source-manifest.json), including the unchanged upstream pin/tree, ordered original patch identities, source modes, and original Pear commit correspondence. Accepted baseline and selected checkpoint are separate commits. Original upstream history and notices are preserved.

The pinned upstream commit is `4e819f054dd2d9ee855ee3f1e30d8c1bb8f80fcf`. The selected range contains 58 changed source units. A merged source view is not a claim that every retained compiled object used that same view. Build recipes must preserve their per-artifact source/configuration correspondence. Wine 11/CodeWeavers Preview is a separate lineage.

The selected reconstruction uses fork commit `1b76db6902345388c589ba3909b22badf751dfd5` with runtime builder
`c8887f9edaba57dffe7772cc26fd19aa9571d451`. Later source/test commits are development inputs only when a new
reviewed recipe names them. Preserve this lock and its original receipts; do not
substitute a current branch tip or a dirty test checkout for the historical pin.
The later Stage 4 fixture/test checkpoint is `d31a50d7385b3385ab278e0fe7687b9d1267de94`;
[its report](../mydocs/working/task_m1_56_stage4.md) is published with that
private checkpoint; collaborator access is required.

## Source checks available now

From this repository root, using Python 3 and Git:

```sh
python3 -B pear/verify_source.py
python3 -B -m unittest discover -s pear/tests -p 'test_*.py' -v
python3 -B pear/verify_source.py --peer pear-dxmt=../pear-dxmt
```

These commands check selected source identities, modes, ancestry, closed source changes, forbidden generated/private headers and optional peer-header identity. They do not compile or execute the runtime. Upstream tests remain retained; the [test ownership map](test-ownership.json) names each selected original component/integration test, exact identity, single destination and remaining adaptation/execution work. New source-admission tests do not substitute for the original ABI, memory, loader or graphics failure oracles.

## Build and verification owner

[pear-runtime](https://github.com/postmelee/pear-runtime) owns build/assembly, immutable input locks, generated
diagnostic schemas, signing/admission and paired integration tests. Its
[selected wine recipe](https://github.com/postmelee/pear-runtime/blob/c8887f9edaba57dffe7772cc26fd19aa9571d451/recipes/wine/README.md)
was exercised in the Stage 3 reconstruction. It rebuilds the selected units,
relinks explicitly retained lower layers and records actual headers, tools and
libraries. It is a bounded reconstruction, not a clean rebuild of every upstream
target. Run the recipe from its pinned runtime checkout; private local bindings
and the exact immutable input pack remain required.

```sh
python3 -B -m pear_runtime.recipes.wine \
  --recipe recipes/wine/selected-v1.json \
  --bindings "$WINE_BINDINGS" \
  --output "$FRESH_WINE_OUTPUT"
```

This command runs from `pear-runtime`, after all named variables have been bound
to reviewed canonical paths and the storage/input gates pass. The
[development guide](https://github.com/postmelee/pear-runtime/blob/codex/task56/docs/development.md) distinguishes the historical build pins from later
test/tool revisions and provides the fixture and bounded recovery commands.

The exercised development selector uses the separate runtime tool commit
`6f0202b457f0e585c5c7621a63d203e77d07386d` and the exact
[Pear development lock](https://github.com/postmelee/pear/blob/2bfcc9dff80212ba40b841a2fe6c32033ca0e801/tools/development/locks/task56-development-v1.json).
This later tool revision does not replace the compilation pins above.
The retained candidate also binds canonical builder-source paths: a checkout
with equal bytes at another path is not automatically an admitted replacement.

The bounded Wine recipe requires Python 3, Git, the exact LLVM-MinGW install,
Apple native tools/SDK, the common diagnostic header and the immutable
object/configuration/tool/resource pack, including `winegcc`, `winebuild`
and locale bytes. It invokes neither configure nor make. The paired graphics
recipe separately declares its native LLVM 15 archives, generated shader
inputs and Apple compiler/SDK closure. Public source history alone cannot
recover these retained compiled/generated inputs. Preserve the recorded
target flags and admit changed tools explicitly. Game files, authenticated
prefixes, owned image/spec inputs and signing material are not stored here.

## Shared source authority

`pear-runtime/include/PearAbortObservation.h` is a generated build input owned by the common runtime. This fork intentionally does not track another copy. Wine exports `include/wine/pear_fex_memory.h` and the v1/v2 typed graphics provider headers. DXMT owns its upstream `winemetal.h` and `winemetal_thunks.h`; the Wine copies are pinned consumer mirrors.

Canonical provider paths and exact digests are in the manifest. The existing owners accepted this fork as the single future editable authority for its selected range; frozen historical patches remain provenance. The [canonical cutover record](https://github.com/postmelee/pear-runtime/blob/codex/task56/provenance/source-cutover-task56.json) binds the exact reviewed commits and ownership scope. This local acceptance does not activate a runtime, renew historical build pins or release retained inputs. Final private publication refs are recorded separately in the Pear Task #56 handoff.

## Licensing and contributions

Upstream Wine/DXMT LGPL terms and existing MIT or other per-file notices remain unchanged. Copied/adapted inputs retain their original attribution and version-specific component notices. New original scripts/tests under `pear/` carry GPL-3.0-or-later SPDX notices; [COPYING](COPYING) supplies that license text and does not relicense the imported component.

DXMT's upstream contribution policy rejects AI-generated/co-authored contributions. This private downstream work does not authorize an upstream submission, rewrite upstream authorship or claim upstream acceptance. Preserve the original contribution policy.

## Related repositories and limits

- [pear-wine](https://github.com/postmelee/pear-wine): Wine host/PE implementation and ABI providers.
- [pear-fex](https://github.com/postmelee/pear-fex): translator/frontend implementation.
- [pear-dxmt](https://github.com/postmelee/pear-dxmt): renderer and Metal consumer.
- [pear-runtime](https://github.com/postmelee/pear-runtime): compatible composition, build, verification and recovery.
- [Pear](https://github.com/postmelee/pear): app/Steam/game policy and development selection.

These component repositories require collaborator access. Source validation,
compilation, synthetic runtime tests, game qualification and public distribution
remain separate claims. The selected reconstruction and candidate3's four native
controls, three bootstrap controls, seven-fixture batch and eighteen-frame
observation passed within their recorded scopes and independent-release checks.
Retained candidate2 evidence is reused only under the reviewed unchanged-input
boundary. The [accepted method map](https://github.com/postmelee/pear-runtime/blob/codex/task56/provenance/paired-memory-methods.json)
does not turn selected-input semantics into generic future enforcement.

Pear development prepare/select/inspect and selection-metadata recovery passed.
The seven v5 synthetic fixtures passed through the actual Pear selector, and new
independent resource checks covered those seven and the eight retained native,
bootstrap and frame operations. Read-only game inspection admitted the exact
private inputs and captured sources; game copying and execution were unperformed.
Recovery switched the isolated selection from game to retained fixture and back;
it was not a full runtime/toolchain/private-state restoration. See the
[development entry and limits](https://github.com/postmelee/pear/blob/2bfcc9dff80212ba40b841a2fe6c32033ca0e801/docs/development/rosetta-free.md#split-native-development-components).

Preserve the previous environment and exact recovery inputs. The accepted source
cutover is limited to the recorded implementation, tests and development handoff;
D37 and separate observation research retain their previous owners and status.
This does not establish gameplay, complete Rosetta-independence coverage or
public distribution, or authorize activation or artifact deletion.

The linked Pear documents are pinned to the accepted Stage 5.2 checkpoint. Their public reachability awaits authorized publication of Pear ancestry; the local reviewed checkout contains those exact files.
