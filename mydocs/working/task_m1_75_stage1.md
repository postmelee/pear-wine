# Task #75 Stage 1 — wine documentation baseline

GitHub Issue: [#75](https://github.com/postmelee/pear/issues/75)
Implementation plan: Pear `mydocs/plans/task_m1_75_impl.md`, reviewed SHA-256
`556d07f2cf7f5d55721cf6b2211573d3cae4da32e84c298650eef91ab6e8d82d`.
Stage: 1

## Stage Purpose

Correct the current component guide's stale claim that the accepted Pear ancestry
is awaiting public publication. The published component base is
`007291b81de386fd8886770c33b5d385c078635d`. Pear PR #58 has merged; the guide now distinguishes its corrected
selector/manual-confirmation source from the preserved historical component pins.

Context used: the approved Task #75 Stage 1 scope, existing component guide and
applicable repository instructions; Pear's central stage report template
(SHA-256 `f614f948fa1438435c9a40ddabf57adb657a89921fb98ef051443ac1aba46525`),
`task-stage-report` procedure and artifact retention guide. These are downstream
documentation changes, with no generated upstream implementation or license change.

## Artifacts

| File | Change Summary |
|---|---|
| `pear/README.md` | Replace one stale paragraph with the merged PR, corrected source and current official guide references. |
| `mydocs/working/task_m1_75_stage1.md` | Record this component's bounded documentation checks and retention handoff. |

## Body Change Scope / Lossless Preservation

Only the existing `pear/README.md` paragraph and this new report change. All
previous Markdown targets and commit literals remain; the two added targets are
[Pear PR #58](https://github.com/postmelee/pear/pull/58) and the
[current development guide](https://github.com/postmelee/pear/blob/master/docs/development/rosetta-free.md).
PR #58 merged at `26927fa2cc4e5d606ac02f2c1c1eceb54e83f60e`; corrected Pear
source is `400da1145b20ff787ad30b251ea5c810ed291c29`. The accepted Stage 5.2
checkpoint links remain historical evidence, not the current instructions.

The README SHA-256 is `cadafc28f554a18602bff364c46cfde88a3ef67397424b0f4d42ecba58b9c427`. Its mode remains `100644`.
No upstream README body, implementation, test, recipe, license, notice, provenance,
lock or selected artifact is changed. Existing original checkouts remain intact;
this work occurs only in the separate Task #75 component worktree.

## Verification Results

Execution context: macOS Darwin arm64, Git 2.53.0 and Python 3.14.4. These are
Git/text checks and read-only GitHub metadata queries, not compilation or runtime,
fixture, native or game execution. No prose-mirroring tests were added.

Evidence reuse: the existing historical source/build/tool references retain their
previous identities and scope. No prior runtime pass is presented as a new test or
current execution authority. Pear's integrated document/governance suite is owned
by the central Task #75 Stage 1 report and is not a component test execution here.

Commands run from this component checkout, with `BASE` set to the full base above:

```sh
git status --short
git diff --check
git diff --name-only "$BASE"
git diff --exit-code "$BASE" -- . ':(exclude)pear/README.md' ':(exclude)mydocs/working/task_m1_75_stage1.md'
```

Read-only remote checks:

```sh
gh api repos/postmelee/pear/pulls/58
gh api repos/postmelee/pear/commits/400da1145b20ff787ad30b251ea5c810ed291c29
gh api 'repos/postmelee/pear/contents/docs/development/rosetta-free.md?ref=master'
```

- The diff and preservation checks passed. The staged scope is exactly the two
  Markdown files above; no incremental source-header change exists.
- GitHub confirmed PR #58 closed and merged at the stated merge commit, the
  corrected source commit, and the current guide target. The observed guide Git
  blob was `b21784aafd998cbb4d4f6a06d5a5b2191a76bde7` (23,701 bytes); `master`
  is intentionally a current-guidance link and can later advance.
- Local Git ancestry checks confirmed the corrected source and retained
  `2bfcc9dff80212ba40b841a2fe6c32033ca0e801` document checkpoint belong to
  the merged ancestry. Old links/pins, file modes and original guide bytes were
  independently compared.
- Private verification receipt: SHA-256
  `6136c949435591437f81d335c3254456e2402d23b1d803a2a35e6147a0c55254`.
  It records the two guide edits and live remote checks; the bundled-commit
  receipt records the final report and commit identity separately.
- Compilation, native controls, game execution, publication visibility changes
  and a full historical privacy/license audit were unperformed in this Stage 1
  slice. No changed source or runtime behavior requires those checks here.

## Artifact Disposition

| Artifact/root | Actual state and outcome | Remaining owner/consumer | Identity/recovery reference | Retain reason / release condition |
|---|---|---|---|---|
| Guide and this report | Git-backed text, retained together in the stage commit | Component maintainers and Task #75 | Full base and guide digest above; resulting commit in central handoff | Current guidance and stage review history |
| Private diff/link/commit receipts | Retained local evidence; no payload export | Task #75 reviewer | Receipt digest above and bundled-commit receipt | Final stage/publication review |
| Existing selected sources, tools, inputs, candidates and private state | Unmodified retained dependencies | Existing Task #56/debug consumers | Their original manifests and path bindings remain authoritative | No release condition was discharged by a documentation correction |

Storage observations: Not applicable for material output/peak-space planning:
this slice adds small Markdown/evidence files only. No runtime copy, archive,
restore, deletion or claimed physical space recovery occurs. Existing worktree
and private-input retention decisions remain unchanged.

## Residual Risks

- A corrected link/status paragraph is not a complete source-publication or
  license clearance. Stage 2 reviews exact refs and exposed remote surfaces.
- The selected runtime still has its previously recorded retained-input and
  qualification limits; this documentation change does not resolve WGI or game
  behavior.

## Impact on Next Stage

Carry the new component stage commit into Stage 2's downstream-object inventory.
Preserve the base audit and append the narrow new documentation/report delta;
no history rewriting or visibility change is authorized by this report.

## Approval Request

The requester approved continuous progression through Task #75's three stages
within its recorded scope. This verified component bundle completes its Stage 1
slice; the main Task #75 report coordinates the stage boundary. Public visibility,
game execution and deletion remain excluded.
