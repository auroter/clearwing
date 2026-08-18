# SourceHunt optimization campaign

This campaign optimizes Clearwing for small local models while keeping every
candidate prompt solution-independent. The original task model was
`dsv4-flash-nvfp4` at:

```text
http://tinybox.taile6728b.ts.net:30000/v1
```

The vLLM server must enable native tools, for example with
`--enable-auto-tool-choice --tool-call-parser deepseek_v3`. Both automatic and
required tool selection have been verified against this endpoint.

The ranks 781–804 continuation used the same frozen treatment with
`DeepSeek-v4-Flash-0731` through a replacement OpenAI-compatible endpoint.
Endpoint credentials are runtime configuration and are not committed.

## Experiment variables

Prompt, scaffold, and context policy are independent variables:

- `legacy-v1`: existing behavior, retained for compatibility.
- `generic-security-v1`: generic discovery loop with solution heuristics and
  historical CVE context disabled.
- `native-v1`: the existing Clearwing tool surface.
- `minimal-linear-v1`: Read/Grep/Trace/Submit only.
- `candidate-ledger-v1`: minimal tools plus typed, persistent hypothesis state.
- `candidate-ledger-closure-v1`: the candidate ledger unchanged until the final
  three model calls, when a short generic countdown forces submit/reject/finish
  closure on the strongest candidate.
- `candidate-ledger-source-retry-v1`: candidate ledger plus one runtime repair
  turn when the first response invokes no source tool. A second text-only
  response stops as `no_source_action`; the retry is absent from the standing
  prompt.
- `candidate-ledger-source-retry-active-v1`: source retry plus a generic
  submission invariant: `record_finding` must cite a pending, investigating, or
  validated ledger candidate. This blocks findings after every hypothesis was
  rejected without requiring the stronger proof scaffold.
- `window-ledger-v1`: candidate ledger plus generic static source-window ranking.
- `guided-window-ledger-v1`: opaque ranked-window reads with mandatory initial
  coverage, removing line-plan translation from the model.
- `state-interaction-ledger-v1`: expands the strongest read anchor into a compact,
  target-blind packet of declarations, initialization, writes, comparisons, and
  one-hop state producers before candidate commitment.
- `proof-refinement-ledger-v1`: keeps the state-interaction packet unchanged and
  exposes one bounded, obligation-specific source packet only after a failed
  structured domain proof.
- `legacy-context-v1`: existing growing transcript, retained as a control.
- `compact-small-model-v1`: shorter static instructions/tool schemas, 3.5k-char
  tool-result clipping, and deterministic compaction near 12k estimated request
  tokens. It keeps a small complete assistant/tool tail plus durable active and
  rejected candidates, counterevidence, next checks, and trace evidence. Raw
  source windows remain disposable because they can be reread.

Select them with `--prompt-bundle`, `--scaffold-profile`, and
`--context-profile`. Ablation IDs and baseline groups include all three values,
so results from different treatments cannot be mixed accidentally.

## Leakage boundary

Optimization candidates are rejected if they contain benchmark CVEs, commits,
target files, distinctive symbols, expected CWEs, known mechanism labels, or
ground-truth phrases. Reflection traces are redacted by the same manifest-derived
policy before reaching the reflection model.

The generic bundle also disables the legacy FFmpeg-specific memory-safety hints
and CVE seed context. Do not use `--seed-cves`, case-specific campaign hints, or
the specialist prompt when collecting optimization data.

## LAIR offline supervision

LAIR's `training/cve_data_extraction` goldens are useful outside the hunter
boundary. They contain source-verified `discovery -> investigation -> challenge`
chains, but they also contain answer-bearing commits, changed files, citations,
symbols, root-cause prose, and fix behavior. Never attach a LAIR task, golden, or
retrieved excerpt to a blind hunter request.

`clearwing.eval.sourcehunt_lair` validates the upstream `GoldenChain` contract and
converts each causal trace into abstract next-action rows. A row contains only:

- completed trace kinds and completed generic proof obligations;
- the next generic proof obligation;
- one bounded context category to request next.

It never copies a CVE, repository, commit, path, symbol, citation, claim, CWE,
fix fact, vulnerability description, case key, or repository key. Before output, a leakage audit compares
every emitted string with case identifiers, paths, source excerpts, and
source-level identifiers. Splits are deterministic by repository, so two CVEs
from the same codebase cannot cross train/development/test. `ffmpeg` is reserved
and excluded by default even if a future corpus contains it.

After LAIR has generated and audited its collected `goldens/CVE-*.json` files,
build SourceHunt routing supervision with:

```bash
uv run python evaluations/build_sourcehunt_lair_dataset.py \
  --goldens /data/lair-cve-training-data \
  --output-dir /data/sourcehunt-lair-router-v1
```

The output contains `router/{train,development,test}.jsonl` and `manifest.json`.
The manifest records corpus and split digests without retaining reversible case
metadata. Treat the development fold as permanently opened once it participates
in scaffold or prompt selection. Keep the test fold sealed until the router and
validator policies are frozen.

The first intended consumer is a small deterministic or learned router choosing
the next on-demand context category. It is not a source-text generator and must
not lengthen the standing hunter prompt. A second consumer can score validator
decisions against LAIR challenge outcomes and exact citations, but this must run
offline; only the blind finding and source-derived trace enter production
validation.

### Differential validator replay

`evaluations/run_sourcehunt_lair_validator.py` measures the existing validator
on LAIR goldens without exposing a snapshot label. It builds one alleged finding
from the vulnerable golden, selects bounded source windows from that trace, and
submits the identical finding twice. Only the source text at the pinned revision
changes. A correct pair advances the vulnerable snapshot and rejects the fixed
snapshot.

```bash
uv run python evaluations/run_sourcehunt_lair_validator.py \
  --campaign-root /data/lair-cve-training-data \
  --base-url http://tinybox.taile6728b.ts.net:30000/v1 \
  --model dsv4-flash-nvfp4 \
  --prompt-profile legacy-v1 \
  --temperature 0 \
  --max-output-tokens 16384 \
  --output results/sourcehunt-optimization/lair-validator-pilot.json
```

The replay reports vulnerable recall, fixed rejection rate, pair accuracy,
per-axis pass counts, model errors, false negatives, and fixed false positives.
Use the same completed golden set for every validator treatment. Do not optimize
on the replay test fold or use fix citations to choose the source windows.

The replay uses `balanced-anchor-v1` context. It derives all paths, coordinates,
and anchors from the vulnerable trace, allocates the character budget fairly
across causal paths, and selects fixed-width line slots nearest those anchors.
Both revisions therefore receive exactly the same line coordinates; only source
text changes. This prevents early alphabetical paths from consuming the context
budget and hiding the authoritative operation or guard in a later path.

Always set an explicit output cap for small reasoning models. An uncapped pilot
request generated roughly 568,000 tokens without reaching the constrained JSON.
The replay now defaults to 8,192 output tokens, retries invalid output once under
the same cap, records the cap and temperature in its v2 result, and never scores
a model-error rejection as a correct fixed negative.

### LAIR development pilot (2026-08-12)

The opened pilot contains 12 completed source-verified C/C++ chains from 12
repositories. The leakage-safe routing adapter emitted 107 development rows:

- trace targets: 12 attack sources, 12 entry points, 20 propagations, 13 state
  transitions, 14 guard failures, 12 vulnerable operations, 12 security effects,
  and 12 challenge actions;
- context targets: 24 input/caller, 20 dataflow, 13 state/representation, 14
  guard/control-flow, 24 operation/effect, and 12 counterevidence requests;
- serialized vocabulary: 22 fixed ontology strings, with no CVE, repository,
  commit, path, symbol, excerpt, vulnerability prose, or FFmpeg text.

The original legacy diagnostic, before balanced selection and explicit sampling,
scored 83.3% vulnerable recall, 75.0% fixed rejection, and 58.3% pair accuracy
with no model errors. Its three fixed false positives all omitted a decisive late
path from the capped context, so it is useful failure evidence but not the final
controlled baseline.

The controlled temperature-zero comparison used identical `balanced-anchor-v1`
context and a 16,384-token cap:

| Validator prompt | Vulnerable recall | Fixed rejection | Pair accuracy | Errors |
|---|---:|---:|---:|---:|
| `legacy-v1` | 91.7% | 58.3% | 50.0% | 0 |
| `source-first-compact-v2` | 91.7% | 58.3% | 58.3% | 0 |

The compact prompt aligned one additional pair, but 1/12 on an opened development
fold is not enough to promote it. Keep `legacy-v1` as the production default and
treat `source-first-compact-v2` as the leading optimization candidate. A longer
`source-first-high-recall-v1` ablation overcorrected: at an 8,192-token cap it
scored 33.3% vulnerable recall, 91.7% fixed rejection, 25.0% pair accuracy, and
two model errors. Do not promote it.

Five temperature-zero replicates per arm then showed that the one-pass advantage
was not promotion evidence:

| Validator prompt | Vulnerable recall | Fixed rejection | Pair accuracy | Errors |
|---|---:|---:|---:|---:|
| `legacy-v1` | 86.7% (52/60) | 58.3% (35/60) | 46.7% (28/60) | 0/120 |
| `source-first-compact-v2` | 88.3% (53/60) | 56.7% (34/60) | 51.7% (31/60) | 1/120 |

The compact arm gained three paired decisions but regressed fixed rejection and
produced one capped structured-output failure. Wilson 95% intervals overlap
broadly. The aggregate, exact input digests, opaque per-case stability, and seed
provenance are recorded in
`results/sourcehunt-optimization/lair-validator-replicates/summary.json` (SHA256
`efbbbd14a936192e1b546844aef48d0f19a0699b5151c43dc6e7abf0917e5468`).

The replication runner alternates arm order, checkpoints each complete arm,
resumes without repeating finished work, fails on configuration/case/coordinate
drift, and uses pooled Wilson intervals. Promotion requires all of the following:

- vulnerable recall at least the replicated legacy control;
- fixed rejection at least the replicated legacy control;
- mean pair accuracy above the control with stable per-case behavior;
- zero model errors at the 16,384-token cap.

### Leakage-safe validator GEPA result

Core GEPA ran directly over a deterministic 6/6 split of the same opened 12-case
development fold. Each case scored 35% vulnerable correctness, 35% fixed
correctness, and a 30% same-case bonus; any model error scored zero. GEPA saw only
opaque case handles. Reflection saw only a generic natural-language lesson—never
golden prose, source, identifiers, coordinates, axes, metric keys, or arm labels.
Candidates were limited to 2,000 characters and rejected if they contained any
answer-bearing term or evaluation-protocol wording.

This boundary caught two optimizer shortcuts before promotion: one candidate
mentioned paired snapshots, and another copied an internal metric-field name.
Those diagnostic runs are preserved under explicitly rejected result directories.
The hardened run used 48 of a hard 60-call budget, evaluated four candidates, and
kept the 725-character `source-first-compact-v2` seed as best. Its stochastic seed
score was 0.892; every accepted mutation scored 0.783 on the six-case validation
half. Result: no GEPA mutation advances to replicated replay, and `legacy-v1`
remains the production default. Do not reopen FFmpeg or consume a sealed test fold
for this validator treatment.

## Evaluation design

Never optimize on positives alone. Use `include_fixed_negative_cases()` to add
every pinned patched snapshot as a negative control. The current manifest yields
an FFmpeg vulnerable/fixed pair; add more fixed pairs and clean repositories before
trusting transfer results.

Legacy scoring requires all of the following:

- correct target file and CWE;
- evidence stronger than suspicion;
- a multi-step trace linked to the target;
- at least two mechanism-bearing target symbols;
- a non-empty root-cause description.

File+CWE-only reports are false positives.

## GEPA

Install the optional integration:

```bash
uv sync --extra dev --extra optimization
```

`clearwing.eval.sourcehunt_gepa.SourceHuntGEPAAdapter` runs the unchanged
SourceHunt system, scores each observation, and returns redacted actionable side
information. Core GEPA is used directly; SourceHunt is not rewritten as DSPy
ReAct, which keeps the runtime/sandbox constant during prompt experiments.

Use `optimize_sourcehunt_prompt()` with train/validation
`SourceHuntOptimizationExample` lists. The adapter fails closed unless the
manifest contains both confirmed positives and disproven fixed/clean controls.
For a no-charge local endpoint, set both token-price fields to `0.0`; action,
model-call, and scaffold limits still bound execution independently of cost.
These run-scoped prices propagate through the spend ledger, HunterPool, and
each native hunter. This is required: otherwise the global fallback price for
an unknown model can prematurely stop file dispatch even while the authoritative
local-endpoint ledger correctly records zero dollars.
Set `max_hunt_files` to cap repository-wide fan-out after generic ranking; the
selection uses priority descending with a stable path tie-break.
Use `max_hunter_steps`, `max_parallel`, `starting_band`, and
`redundancy_override` to hold per-file work constant across scaffold arms.
Use standard depth for scaffold optimization: it retains deep sandboxed hunters
but excludes the separate deep-depth harness generator from the comparison.
For small models, use bounded ranker chunks (currently 25 files, one chunk in
flight, one retry) so structured rankings fit comfortably in one response.
DeepSeek V4 Flash still returned truncated/empty ranker JSON at that size, so
the scaffold comparison disables LLM reranking and holds Clearwing's generic
deterministic static ranking constant across every arm.
The deterministic ranker scans production C/C++/Rust source with the same
repository-independent signal categories exposed by `rank_source_windows`.
Category counts saturate, signal diversity is rewarded, and only eight strong
line-local anchors contribute; this prevents large files or repeated memory
operations from monopolizing a bounded campaign. Test, documentation, example,
benchmark, and fuzz paths are excluded generically. The score and per-category
counts are retained on each file target for auditability.
Examples also fail closed unless they use blind repository-level ablations with
no assisted hint packet; target-file and later ablations are diagnostics only.
The current prompt/scaffold seam belongs to the legacy hunter, so GEPA examples
also reject the proof flow instead of silently scoring a prompt it does not use.
The reflection model may be a GEPA/LiteLLM model or `ClearwingReflectionLM` around
an existing native Clearwing client.

Optimization order:

1. Compare scaffolds with the fixed seed prompt.
2. Freeze the winning scaffold and optimize discovery instructions.
3. Freeze discovery and optimize investigation/challenge instructions.
4. Re-evaluate all candidates on held-out projects and fixed controls.
5. Run the winning generic configuration blindly across FFmpeg, then independently
   validate and deduplicate every finding.

## Local DeepSeek diagnostics (2026-08-11)

The endpoint emitted valid native tools through both raw OpenAI-compatible calls
and Clearwing's `AsyncLLMClient`. On the small heap-overflow fixture:

| Scaffold | Tokens | Result |
|---|---:|---|
| `minimal-linear-v1` | 13,420 | Correct overflow, suspicion evidence |
| `native-v1` | 20,926 | Correct overflow, suspicion evidence |

On the pinned vulnerable FFmpeg target-file ablation, 12-14-step static runs did
not find the labeled issue. Linear mode swept source windows; the enforced ledger
created explicit hypotheses but selected other mechanisms. This is a diagnostic
failure, not a prompt hint: retain it as negative optimization feedback.

Full proof-flow evaluation is not available on a host without Docker and Bear.
Do not treat static target-file diagnostics as the final FFmpeg campaign baseline.

Docker and Bear are now available through the local Colima Docker socket. The
pinned vulnerable and fixed FFmpeg checkouts each have a 2,174-entry compile
database, so repository-level proof-flow baselines are the authoritative results
below.

### Compact repository baselines

Both treatments used the same blind 24-file target set, 40 steps per hunter,
parallelism 4, standard depth, fast band, redundancy 1, deterministic static file
ranking, and zero local token prices.

| Scaffold | Vulnerable | Fixed | Vuln input | Fixed input | Result |
|---|---:|---:|---:|---:|---|
| `window-ledger-v1` | 0.175 | 1.0 | 9,039,148 | 8,359,653 | no findings |
| `guided-window-ledger-v1` | 0.175 | 1.0 | 9,310,919 | 9,440,150 | no findings |

Both vulnerable arms failed first at `true_candidate_generated`; both fixed arms
remained free of false reports. Guided ranked reads correctly forced W1/W2/W3 and
reduced the vulnerable target file from 389,660 to 358,643 input tokens, but the
model still isolated familiar memory operations, rejected two sound bounds
hypotheses, then repeated the first one. Navigation improved; semantic state
interaction did not.

The next scaffold therefore keeps the prompt short and moves generic context
assembly into a deterministic tool. For each anchor it extracts the dominant
mutable state and a compact role-labeled packet: representation, reserved-state
initialization, writers, comparisons, the stored producer, and that producer's
upstream state and guards. It derives every line from the current checkout and
uses no case manifest, patch, CVE, known filename, symbol, value, or mechanism.
On the pinned pair, the same generic algorithm includes the relevant state chain
in the vulnerable packet and independently includes the terminating producer
guard only in the fixed packet. No patch or answer-derived term participates in
packet construction.

### Proof-gated state interaction result

The state-interaction treatment initially found the right value-domain candidate
but spent its remaining turns rereading source and rewriting the candidate. A
generic checkpoint now activates after two source actions for a tracked,
unresolved domain. It blocks further source reads and candidate rewrites until
the hunter calls `record_domain_proof` with four explicit obligations:

1. attacker input reaches the producer;
2. the producer can reach the distinguished stored value;
3. the changed consumer branch reaches the extracted effect; and
4. the boundary effect lacks a dominating guard.

A false answer narrows the candidate's next check to the unresolved obligation.
Four true answers validate the candidate, record
`security_effect_possible`, seed exact source/transfer/condition/effect trace
steps, and permit a `static_corroboration` report. This small amount of enforced
control flow eliminated the model's executive loop without lengthening the
standing prompt.

The 40-step target-pair diagnostic at
`domain-proof-gated-40-diagnostics/summary.json` separated the snapshots:

- vulnerable: one validated finding with a four-step exact source trace;
- fixed: zero findings, with the extracted terminating guard correctly proving
  the producer and distinguished domains disjoint.

The blind repository run at
`domain-proof-gated-v1/state-interaction-ledger-v1--compact-small-model-v1.json`
used the same 24-file target set on each snapshot. It submitted exactly one
finding on the vulnerable target and none across the fixed files. Vulnerable and
fixed input totals were 8,546,607 and 8,468,558 tokens respectively. The recorded
scores were 0.125 and 1.0 because independent validation suppressed the positive,
not because discovery missed it.

The original validator call returned an empty response, so structured parsing
rejected the report. Validation now retries invalid or empty structured output
once with a short generic instruction, 8,192 output tokens, and the hunter's
exact vulnerability trace. A manual retry produced structured output but still
rejected the candidate on an incorrect practical-reachability claim. Treat that
as a validator false negative: the discovery and fixed-side differential remain
the useful scaffold signal, while validator reachability reasoning needs its own
bounded refinement.

### Context expansion ablation

Two subsequent target-pair ablations front-loaded additional, correctly
source-derived context about repeated-input reachability, dispatch, allocation
extent, and boundary addressing. Both regressed vulnerable discovery from one
finding to zero:

- `reachability-proof-gated-40-diagnostics`;
- `reachability-allocation-proof-40-diagnostics`.

The failure is important: correct context is not automatically useful context
for this model. Keep the winning initial packet compact. The next experiment
now exposes `read_domain_proof_refinement` only after a particular domain-proof
obligation remains false. Its schema is absent from earlier model requests, it
accepts only a recorded unresolved obligation, returns a bounded source-derived
packet for that obligation, and can be called only once before another structured
proof is required. The initial state-interaction packet is unchanged. Measure
this on-demand treatment against the same vulnerable/fixed controls before
beginning GEPA prompt search.

The first 40-step paired run of this treatment,
`on-demand-refinement-40-diagnostics`, produced zero findings on both snapshots.
The vulnerable hunter used three refinements but processed independent false
obligations in an inefficient order and temporarily treated a non-terminating
comparison as a producer cap. It corrected that interpretation only on its final
turn. The refinement loop now exposes one prerequisite at a time and labels
comparison context as terminating or non-terminating based on nearby control-flow
effects. This revision requires another paired diagnostic; do not promote it to a
repository run on the first result.

The revised run, `on-demand-refinement-ordered-40-diagnostics`, restored clean
separation. The vulnerable hunter submitted one validated finding after 23 model
calls and 230,190 input tokens; its seeded source/state-sink/condition/effect-sink
trace matched the compact winning run. The fixed hunter submitted zero findings
after 40 calls and 398,625 input tokens, correctly treating the extracted
terminating producer guard as proof that the domains are disjoint. Peak estimated
contexts were 11,389 and 11,621 tokens. This passes the target-pair promotion gate;
the next meaningful test was a blind repository run, not another target-file
replicate.

That blind 24-file run completed at
`proof-refinement-ledger-v1/proof-refinement-ledger-v1--compact-small-model-v1.json`.
It retained one vulnerable finding, zero fixed findings, and the same `[0.125,
1.0]` scores as the unchanged `state-interaction-ledger-v1` control. Independent
validation again suppressed the vulnerable positive, so correctness did not
improve. The refinement treatment used 8,425,157 vulnerable and 8,123,672 fixed
input tokens with 890 and 864 model calls. Relative to control, that is 121,450
and 344,886 fewer input tokens (about 1.4% and 4.1%) and 37 and 36 fewer calls.
Keep it as an efficiency candidate, not a promoted correctness winner. Do not
begin GEPA prompt search on this result; use the LAIR development fold to improve
generic routing and validator evaluation first.

## Blind FFmpeg discovery campaign (2026-08-13)

DeepSeek V4 Flash has meaningfully examined all 180 attempted deterministic
FFmpeg rank slots. Ranks 1–24 came from the earlier
repository baseline. Ranks 25–96 used the proof-refinement scaffold: 72 files,
24,751,510 tokens, 563 raw candidate updates, and no submitted findings. Ranks
97–108 were then
replayed as a controlled scaffold comparison using the same 12 files, 24 steps,
temperature 0, and a 4,096-token output cap:

| Scaffold | Tokens | Candidate calls | Step-cap hunters | Findings |
|---|---:|---:|---:|---:|
| `minimal-linear-v1` | 2,345,124 | 0 | 9/12 | 0 |
| `candidate-ledger-v1` | 2,455,745 | 74 | 10/12 | 0 |
| `proof-refinement-ledger-v1` | 2,577,673 | 64 | 12/12 | 0 |

Use `candidate-ledger-v1` as the discovery baseline. Its 4.7% token overhead
over minimal-linear retains a reviewable hypothesis funnel. Proof refinement
cost 5.0% more than candidate ledger without improving submission yield. These
results do not establish a correctness winner because every arm submitted zero
findings. The exact inputs, campaign hashes, token components, call counts, and
decision are recorded in
`results/sourcehunt-optimization/ffmpeg-blind-campaign/matched-scaffold-ranks-0097-0108.json`.

Most hunters reached the hard step cap, so end-of-budget behavior is now an
independent scaffold variable. `candidate-ledger-closure-v1` preserves the
candidate-ledger standing prompt and tools, then supplies a generic remaining-call
count only for the final three calls. It tells the hunter to resolve, submit, or
reject its strongest candidate and forbids new broad exploration. Keep this as a
separate treatment so prior `candidate-ledger-v1` artifacts remain reproducible;
promote it only after a matched replay.

The matched closure replay did not pass that promotion gate. It used 2,306,771
tokens (6.1% fewer than candidate ledger) and retained 76 candidate calls, but
still submitted zero findings and left 10/12 hunters at the step cap. In the
final three steps the hunters made 28 source actions and 11 candidate updates,
but no trace or finding calls. The small model did not reliably obey the textual
closure request. Retain `candidate-ledger-v1` for unseen coverage; if closure is
revisited, make it a bounded runtime phase rather than adding more standing
prompt text.

Offline source tracing independently supports two deduplicated root causes:

- H.264 slice ownership stores an unbounded slice counter in a 16-bit table where
  slice 65,535 aliases the unavailable-entry sentinel. The fixed control adds the
  missing counter cap, and the production validator advanced the vulnerable report
  at high severity.
- Vulkan HEVC RPS construction may write more than the public Khronos array
  capacity of eight because the write loop uses FFmpeg's larger `nb_refs` without
  a destination-capacity guard. The production validator advanced the report at
  medium severity; no executable Vulkan trigger has yet established more than
  eight live current references.

At that checkpoint, neither issue had a crash-confirmed reproducer. Survivor details remain offline in
`evaluations/sourcehunt_ffmpeg_survivors.json`; never include that file or its
derived hypotheses in hunter context.

### Blind continuation and first crash-confirmed discovery

Candidate-ledger continuation attempted ranks 109–180. Source-action audit—not
the runner's historical `files_hunted` counter—confirms that all 24 files at
ranks 109–132, 19/24 at ranks 133–156, and 9/24 at ranks 157–180 actually ran a
source-bearing tool. Together with ranks 1–108, that is 160 meaningfully examined
files and 20 false completion slots. The failures were DeepSeek responses that
printed DSML/XML-like calls as ordinary text; the provider returned no native
tool call, and the old loop treated that as a clean finish. The unusually cheap
last waves are therefore parser/tool-call failures, not efficiency gains.

The missed ranks were 138, 146, 153, 154, 156, 158, 161, 162, 164, 167–169,
172, and 174–180. `candidate-ledger-source-retry-v1` repairs this generically at
runtime. A first sparse-offset replay exposed deterministic-ranker drift: current
offsets no longer resolved to all historical files after ranking code changed.
The final replay therefore used a sealed exact-path manifest and failed closed
if any requested file was absent. The first pinned attempt source-confirmed
15/20 files; bounded replays recovered the remaining 5, including one path that
needed three attempts. The recovery runs used 3,688,534 tokens and 111 candidate
calls in total. Coverage accounting records `files_examined` and
`source_action_files`; selected or dispatched files alone are never counted as
examined.

The pinned replay's only hunter-submitted report, in `hdsenc.c`, was rejected
offline. `parse_header` bounds every tag, returns `AVERROR_INVALIDDATA` whenever
metadata is absent, and processes header output produced by the nested FLV muxer.
No NULL-metadata manifest path or attacker-controlled memory violation survives.
The hunter had already marked both relevant candidates rejected before filing;
`candidate-ledger-source-retry-active-v1` now prevents that control-flow error at
runtime without adding standing prompt text.

The completed continuation consumed 9,025,918 tokens and 261 raw candidate calls
through rank 156, with no hunter-submitted findings. Offline source triage rejected
the usual incomplete hypotheses but recovered one complete new root cause from
the candidate funnel:

- `af_arnndn.c` accepts `denoise_output->nb_neurons` from 0 through 128 while
  validating only the separate VAD output shape. During non-silent inference,
  `compute_dense` writes that many floats into `g[NB_BANDS]`, a 22-float stack
  array. A syntactically valid model declaring 23 outputs deterministically causes
  an ASan stack-buffer-overflow in `compute_dense`; the ASan object report names
  `g` as the overwritten buffer. The production validator independently advanced
  the source report at high severity.

Build and run the target-blind reproducer with:

```bash
uv run python evaluations/run_ffmpeg_arnndn_reproducer.py \
  --ffmpeg .reference/ffmpeg/ffmpeg \
  --model-output /tmp/clearwing-arnndn-23.model \
  --output results/sourcehunt-optimization/ffmpeg-dynamic-validation/arnndn-denoise-output-stack-overflow.json
```

The structured crash artifact is
`results/sourcehunt-optimization/ffmpeg-dynamic-validation/arnndn-denoise-output-stack-overflow.json`.
The vulnerable and fixed-control `af_arnndn.c` files are byte-identical, so the
issue persists in both checked snapshots.

The three-case validator replay advanced Vulkan at medium and arnndn at high, but
rejected H.264 after incorrectly treating `top_borders[-1]` as a previous-row
element. The upstream H.264 fix commit documents that `top_borders` has only
`mb_width` elements and the access underflows its allocation by 96 bytes (with
writes at negative offsets). Keep H.264 as source-confirmed and record this replay
as a validator false negative. Current honest totals are three confirmed root
causes, one dynamically crash-confirmed.

### Exact-path wave 181–204 and three blind dynamic discoveries

The next sealed manifest selected 24 previously unseen production files by exact
path. Thirteen targets performed successful source-bearing actions on the first
attempt. Exact-path replays recovered seven, then two, then the final two; the
full wave is therefore 24/24 source-confirmed. The three recovery passes used
2,336,138 tokens and 66 raw candidate calls. As in the earlier recovery,
`files_hunted` was not accepted as coverage evidence.

This wave produced three source-supported issues, all found without CVE, patch,
fixed-checkout, historical-location, or survivor context and all independently
reproduced under ASan:

- RTP/QDM2 accepts a packet-controlled `block_size` smaller than its mandatory
  reconstructed header. A one-byte block yields `negative-size-param (size=-1)`
  in `qdm2_parse_packet`. Linking the later upstream minimum-size check ahead of
  the sealed static library makes the identical harness return invalid data with
  no sanitizer report. The later upstream commit describes the same invariant as
  an out-of-array access.
- `ahistogram` signed-logarithmic binning maps a valid positive full-scale sample
  to `bin == width` for even widths. A constant `+1.0` source with
  `ascale=log:hmode=sign` produces an eight-byte heap-buffer-overflow exactly one
  element past the histogram allocation. The issue is present in both sealed
  snapshots.
- XPSNR's downsampled high-pass stencil steps by two over odd active boundary
  dimensions but reads through `x + 3` and `y + 3`. Two valid 2049x1153 YUV444
  frames produce a two-byte heap-buffer-overflow read beyond the tightly allocated
  temporal source plane. The issue is present in both sealed snapshots.

Structured artifacts live under
`results/sourcehunt-optimization/ffmpeg-dynamic-validation/`, and the generic
reproducer entry points are `run_ffmpeg_qdm2_reproducer.py`,
`run_ffmpeg_ahistogram_reproducer.py`, and `run_ffmpeg_xpsnr_reproducer.py` in
`evaluations/`. The vulnerable-source-only survivor file now contains six cases.
Repeated validator calls show meaningful variance on the H.264 and Vulkan impact
axes even while source reality/triggerability remain supported, so no single
validator vote should be used as the prompt-optimization objective. Keep upstream
fix evidence, dynamic evidence, and independent source-only validation as separate
signals.

Current honest totals are 204 distinct source-confirmed files, six confirmed root
causes, and four dynamically crash-confirmed issues. H.264 and Vulkan still need
their older dynamic proofs; broad FFmpeg coverage beyond rank 204 remains open.

### Blind wave 205–228

The next sealed exact-path wave completed 24/24 source-confirmed on its first pass,
using 5,028,744 tokens and 147 candidate calls. It made no formal submissions, but
offline terminal-ledger triage recovered one complete denial-of-service root cause:

- `ff_rdt_parse_header` accepts a zero-length RDT status packet because it checks
  only `pkt_len > len`. The loop then advances `buf`, `len`, and `consumed` by zero
  and sees the identical status header forever. A 16-byte direct harness times out
  deterministically on both sealed snapshots. This is a remotely supplied CPU
  denial rather than memory corruption.

The candidate-ledger remains useful even when the small model does not complete a
formal report: XPSNR and RDT were both recovered from source-grounded terminal
hypotheses. Current totals are 228 distinct source-confirmed files, seven confirmed
root causes, and five dynamically reproduced issues.

### Blind waves 229–276 and four additional dynamic confirmations

Two more sealed exact-path waves completed with the unchanged
`candidate-ledger-source-retry-active-v1` scaffold, the
`compact-small-model-v1` context, 24 hunter steps, a 4,096-token output cap,
temperature zero, and no answer-bearing inputs. Ranks 229–252 were 24/24
source-confirmed, used 4,952,368 tokens, and produced 155 candidate calls.
Ranks 253–276 were also 24/24 source-confirmed, used 4,563,131 tokens, and
produced 158 candidate calls plus one formal finding.

Offline triage and production-code reproducer work confirmed four new root
causes:

- RDT's AAC cache path can copy a 9,212-byte unconsumed record tail into an
  8,256-byte `PayloadContext.buffer`. RTSP admits and forwards substantially
  larger interleaved records. A direct production-parser harness reports the
  heap-buffer-overflow on both sealed snapshots.
- A zero-sized `tfra` atom for an unknown track makes `ismindex` seek to the
  same position and repeat `read_tfra` forever. Both snapshot harnesses time
  out. This is a real but low-impact issue in a local indexing tool.
- The `entropy` filter allocates `1 << depth` histogram entries and indexes
  them with an unmasked stored 16-bit sample. A gray10le sample of 1,024
  accesses the first eight bytes beyond its 1,024-entry allocation. The formal
  blind hunter report was reproduced through the production ffmpeg filter graph
  under ASan on both snapshots.
- CAF's variable-packet seek callback fails to handle the documented negative
  result from `av_index_search_timestamp`. A forward seek beyond the final
  packet dereferences `index_entries[-1]`. A 107-byte syntactically parsed CAF
  followed by public `av_seek_frame` produces an eight-byte ASan heap-buffer-
  overflow read in `read_seek` on both snapshots.

The CAF case is especially useful scaffold evidence: the small model recorded
and validated the exact negative-index candidate in its terminal ledger but did
not submit it before the step cap. As with XPSNR and RDT, terminal candidate
state therefore remains valuable even when formal finding yield understates
discovery quality.

The ten-case vulnerable-source-only survivor replay (before adding CAF) advanced
8/10 reports. Entropy passed all four axes at high confidence. H.264 remained a
validator false negative, and the validator correctly identified the `ismindex`
loop as real and triggerable while rejecting it on security impact. This again
supports keeping source proof, dynamic reproduction, and validator votes as
separate signals instead of optimizing toward one validator decision.

At this checkpoint, ranks 1–276 are source-confirmed. The honest totals are
eleven confirmed root causes, nine dynamically reproduced issues, and two
source-only issues awaiting older dynamic proofs. The next manifest excludes
every prior bounded target found across all instrumentation ledgers and seals
the deterministic ranks 277–300 by exact path.

### Blind waves 277–324 and three more confirmed root causes

The unchanged frozen treatment completed two further exact-path waves:

| Ranks | Source-confirmed | Tokens | Candidate calls | Formal findings |
|---|---:|---:|---:|---:|
| 277–300 | 24/24 | 4,589,393 | 165 | 0 |
| 301–324 | 24/24 | 4,344,701 | 129 | 0 |

Before selecting ranks 301–324, the deterministic selector was audited by
excluding every bounded target recorded in all campaign instrumentation
ledgers. It reproduced the already sealed 277–300 manifest exactly, then
selected the next 24 paths. This is now the required procedure for future
waves; rank offsets and historical `files_hunted` counters are not coverage
evidence.

Terminal-ledger triage and independent production-code validation confirmed
three additional root causes:

- The Dolby Vision RPU parser accepts long signed fixed-point coefficients, but
  the generator passes their integer components to a signed Golomb writer whose
  documented domain is only 16 bits. The generator also reserves a constant 177
  bytes for an MMR piece despite coefficient-dependent Golomb lengths. A
  parser-to-metadata-to-generator harness produces undefined bit-writer shifts
  followed by the always-on `flush_put_bits` assertion on both snapshots. Treat
  this conservatively as denial of service, not demonstrated heap corruption.
- `showfreqs=data=delay` starts its group-delay loop at frequency bin zero while
  reading `fft_data[ch][f-1]`. A normal production filter invocation produces a
  four-byte ASan heap-buffer-overflow read eight bytes before the FFT allocation
  on both snapshots. This is an unambiguous memory-safety defect but has limited
  security impact because the value affects only visualization output.
- HLS SAMPLE-AES accepts the 13-bit ADTS frame length without checking it against
  the remaining packet. That length directly determines the in-place AES block
  count. A 64-byte packet declaring an 8,191-byte frame produces an ASan heap-
  buffer-overflow in the production AES decryption routine on both sealed
  snapshots. Although later repository history contains a validating change,
  neither history nor later source was exposed to the hunter.

The corresponding generic recorders are
`run_ffmpeg_dovi_rpu_reproducer.py`,
`run_ffmpeg_showfreqs_reproducer.py`, and
`run_ffmpeg_hls_sample_aes_reproducer.py` under `evaluations/`. Structured
artifacts are retained under
`results/sourcehunt-optimization/ffmpeg-dynamic-validation/`.

The complete vulnerable-source-only `v11` survivor replay evaluated all 14
cases. It advanced 10/14: HLS SAMPLE-AES advanced at high severity, while
`showfreqs`, `ismindex`, XPSNR, and Dolby Vision were rejected on impact or
general reachability rather than source reality. These votes are useful triage,
not ground truth. The replay artifact is
`results/sourcehunt-optimization/ffmpeg-survivor-validation/deepseek-v4-flash-0731-vulnerable-v11.json`.

Current honest totals are 324 distinct source-confirmed files, 14 confirmed root
causes, and 12 dynamically reproduced issues. H.264 and Vulkan HEVC remain the
two source-only cases. Open-ended FFmpeg exhaustion is not close: this is strong
bounded progress, not a claim that the remaining production source has been
comprehensively audited.

### Blind wave 325–348 and Musepack SV7 confirmation

The audited selector excluded 324 unique bounded paths from every campaign
instrumentation ledger, then reproduced the sealed 301–324 manifest exactly
when that set was withheld from the exclusion. Only after that replay passed did
it seal ranks 325–348. The unchanged treatment completed all 24 targets with
source-bearing actions, using 4,352,353 tokens and 129 candidate/finding calls.

This wave produced one successful formal report and dynamic confirmation:

- Musepack SV7 stores an 11-bit `lastframelen` from file extradata without
  constraining it to `MPC_FRAME_SIZE` (1,152). The decoder allocates planar S16
  storage for 1,152 samples, synthesizes that fixed amount, and then publishes
  as many as 2,047 samples when the packet marks itself as the last frame. A
  public `avcodec_send_packet`/`avcodec_receive_frame` harness receives
  `nb_samples=2047`; a normal consumer loop immediately produces a two-byte
  ASan heap-buffer-overflow read at the end of each 2,304-byte channel plane on
  both snapshots.

The reproducer and recorder are
`evaluations/ffmpeg_mpc7_lastframelen_reproducer.c` and
`evaluations/run_ffmpeg_mpc7_lastframelen_reproducer.py`. Current honest totals
are 348 distinct source-confirmed files, 15 confirmed root causes, and 13
dynamically reproduced issues. H.264 and Vulkan HEVC remain source-only.

The complete vulnerable-source-only `v12` survivor replay evaluated all 15
cases and advanced 14/15. Musepack advanced at medium severity. `showfreqs` was
the only rejection, failing the general and impactful axes while passing real
and triggerable. XPSNR, `ismindex`, and Dolby Vision advanced in this replay
after being rejected in `v11`, reinforcing that validator votes are variable
triage signals rather than ground truth. The replay artifact is
`results/sourcehunt-optimization/ffmpeg-survivor-validation/deepseek-v4-flash-0731-vulnerable-v12.json`.

### Blind wave 349–372

The audited selector found 348 unique bounded paths across all campaign
instrumentation ledgers. With the 325–348 set withheld, it reproduced that
sealed manifest exactly before selecting the next 24 deterministic unseen
paths. The unchanged frozen treatment completed 24/24 targets with
source-bearing actions, using 4,334,219 tokens and 132 candidate calls. It
produced no formal findings, and focused source triage did not establish a new
root cause. All 24 target files are byte-identical in the independent control
snapshot, so that comparison provides no differential evidence. Current honest
totals are 372 distinct source-confirmed files, 15 confirmed root causes, and
13 dynamically reproduced issues.

### Blind wave 373–396

The selector audit collected 396 unique bounded paths from every SourceHunt
optimization instrumentation ledger. With the 373–396 set withheld, the current
deterministic ranker reproduced the sealed manifest exactly. The same audit also
reproduced the 325–348 and 349–372 manifests when each was withheld, so the
selection state is internally consistent across the last three waves.

The unchanged frozen treatment completed all 24 targets with successful
source-bearing actions. It used 4,335,583 tokens, made 137 candidate calls, and
submitted no formal findings. Focused review rejected the strongest terminal
leads: image-dimension validation prevents the suspected BMP stride overflow;
AFIR's exponential partition growth keeps its segment count below 1,024;
signature category counts sum exactly to the fixed 380/348 capacities; x264's
SEI callback owns and frees the transferred payloads; and Pixlet's scratch copies
are byte counts covered by its 16-element margin. The FFV1 Vulkan encoder would
benefit from defensive CPU-side validation of GPU-returned slice lengths, but no
attacker-controlled route to an overlarge length or concrete violated allocation
invariant was established, so it is not promoted.

All 24 wave files are byte-identical in the independent control snapshot. No new
root cause was established. Current honest totals are 396 distinct
source-confirmed files, 15 confirmed root causes, and 13 dynamically reproduced
issues. Relative to the 4,995-file deterministic ranked corpus, bounded coverage
is 7.9%, with 4,599 ranked files remaining.

### Blind wave 397–420 and LCL/ZLIB disclosure confirmation

The unchanged frozen treatment completed all 24 exact-path targets with
source-bearing actions. It used 4,453,854 tokens, made 135 candidate calls, and
submitted no formal finding. The all-ledger audit found exactly 420 bounded
paths, and withholding this wave reproduced its sealed manifest exactly (as did
withholding each earlier exact-path wave from ranks 205–396). All 24 files are
byte-identical in the independent control snapshot.

Offline terminal-ledger triage confirmed one additional root cause:

- LCL/ZLIB's multithread decoder accepts valid zlib streams whose actual outputs
  are shorter than the packet's claimed half-frame size. `zlib_decomp` returns
  the short positive count, both call sites discard it, and the decoder then
  marks the entire decompression allocation as valid image data. A public
  16x16 RGB24 decoder harness supplies two three-byte streams; FFmpeg returns a
  768-byte frame containing the six supplied bytes plus all 762 bytes of the
  otherwise uninitialized allocation. ASan's deterministic malloc-fill marker
  confirms the complete disclosure on both sealed snapshots.

The generic reproducer and recorder are
`evaluations/ffmpeg_lcl_multithread_reproducer.c` and
`evaluations/run_ffmpeg_lcl_multithread_reproducer.py`; structured artifacts
are under `results/sourcehunt-optimization/reproducers/`. The case is retained
as dynamically reproduced even though no sanitizer crash is expected: the
security effect is exposure of initialized allocator contents through a public
decoded-frame contract.

The other terminal leads were rejected after source proof. PAF motion blocks
have explicit source-page end checks; bounded bytestream access prevents GDV LZ
copies from leaving its frame allocation; HEVC intra-prediction callers provide
the required doubled top/left border arrays; swscale swizzles are internally
constructed from component indices zero through three; and the reviewed VVC,
RTSP, Vulkan FFV1, RALF, median, MJPEG Huffman, H.264 CAVLC, and V4L2 candidates
are covered by the producer bounds described in the campaign triage record.

Current honest totals are 420 distinct source-confirmed files, 16 confirmed root
causes, and 14 dynamically reproduced issues. H.264 and Vulkan HEVC remain the
two source-only cases. Relative to the 4,995-file deterministic corpus, bounded
coverage is 8.4%, with 4,575 files remaining. The audited next exact-path
manifest seals ranks 421–444 without changing prompts, scaffold, or context.

### Blind wave 421–444

The unchanged treatment completed 24/24 targets with successful source-bearing
actions, using 4,601,980 tokens and 140 candidate calls with no formal findings.
Peak estimated context remained 11,956 tokens; the largest individual input was
16,049 tokens. All 24 source files are byte-identical in the control snapshot.

Focused terminal-ledger review did not establish another root cause. The AAC
encoder's largest scale-factor band is exactly the 96-entry quantization scratch
capacity, and short-window grouping keeps its `w * 16 + g` metadata within 128
entries. TrueMotion2 checks Huffman literal counts and token bounds, constrains
motion blocks to the picture, and allocates explicit luma/chroma edge padding.
DV stops at `pos >= 64` before indexing the coefficient block. D3D12 decode's
32-entry barrier stack cannot overflow under any registered codec because each
sets `max_num_ref` to 17 or less, leaving room for its two leading output
barriers. E-AC-3's copy span and extension span are multiples of 12 bins, keeping
the maximum copy-section count below `SPX_MAX_BANDS` (17). TIFF's LZW encoder
checks its remaining output bound and propagates failure. Android MediaCodec's
input/output capacity observations depend on the platform codec violating its
own buffer contract and are not attacker-media routes in this encoder path.

The all-ledger selector audit now finds exactly 444 unique bounded paths, none
outside the deterministic corpus. Withholding each sealed exact-path wave from
ranks 205–444 reproduces it exactly. Current totals remain 16 confirmed root
causes and 14 dynamically reproduced issues. Coverage is 444/4,995 (8.9%), with
4,551 ranked files remaining. The next sealed manifest contains ranks 445–468.

### Blind wave 445–468

The first pass completed successful source-bearing actions for 19/24 targets.
Two exact-path recovery passes covered the remaining five and then two paths,
so the merged wave is 24/24 source-confirmed. Across all three passes it used
3,563,833 tokens, made 103 candidate calls, and submitted no formal findings.
All 24 target files are byte-identical in the independent control snapshot.

Focused terminal-ledger review did not establish another root cause. VC-1's
bitplanes are allocated for `mb_stride * FFALIGN(mb_height, 2)`, covering the
decoder's `mb_stride * mb_height` writes. MS Video 1 visits only complete 4x4
blocks and its bottom-up row arithmetic stays inside those blocks. Rawvideo's
sub-16-bit expansion writes either at most the copied packet size or exactly
`width * height` 16-bit samples into an allocation at least as large as the
computed frame. The audio equalizer validates channel indices and its four
section-history accesses match the four-element arrays. DTS-to-PTS creates a
fresh null tree-node holder on every removal iteration, so the suspected reuse
of a non-null removal node does not occur. HQX dispatches exactly 16 slice jobs
for its 16-element slice state, ZMBV's previous-frame allocation includes its
configured motion-search margins, and ClearVideo's copy helpers reject source
or destination rectangles outside the coded frame.

The all-ledger selector audit now finds exactly 468 unique bounded paths, none
outside the 4,995-file deterministic corpus. Withholding every sealed
exact-path wave from ranks 205–468 regenerates it exactly. Totals remain 16
confirmed root causes and 14 dynamically reproduced issues. Coverage is
468/4,995 (9.4%), with 4,527 ranked files remaining. The unchanged next exact-
path manifest seals ranks 469–492.

### Blind wave 469–492

The first pass completed successful source-bearing actions for 11/24 targets.
Several other hunters incorrectly claimed that source tools were unavailable
despite receiving their schemas, then reasoned from model memory and mentioned
historical CVEs. Those trajectories are not coverage or vulnerability evidence.
An exact-path replay recovered all 13 misses, making the merged wave 24/24
source-confirmed. The two passes used 4,102,069 tokens and made 132 candidate
calls, with no formal findings. All 24 target files are byte-identical in the
independent control snapshot.

Focused terminal-ledger review did not establish another root cause. HEVC's
unguarded center collocated-MV lookup remains inside the picture: SPS parsing
requires width and height to be multiples of the minimum coding block, boundary
quadtrees must split until their leaves fit, and every prediction partition is
contained by such a leaf. AAC rejects `max_sfb > num_swb`, selects matching
short- or long-window offset tables, and bounds the flattened group arrays to
128 entries. H.261 constrains each motion estimate to -15 through 15, so the
successive-vector difference stays within the 64-entry VLC table. PP7 allocates
its temporary surface for aligned luma geometry, which dominates every chroma
stride and height used by the same buffer. Spectrumsynth allocates a two-window
overlap buffer. Unsharp allocates `width + 2 * steps_x` columns and per-thread
row state matching its inclusive loop ranges and dispatch count. DXVA2 copies
slices into driver buffers only after checking each slice plus start code
against the remaining capacity.

RTMP-over-HTTP's signed capacity arithmetic deserves hardening but did not
survive the promotion gate. The normal RTMPT write path flushes after ten FLV
packets by default; even with a caller-selected larger flush interval, the
capacity-doubling expression reaches signed overflow while the requested total
is still below `INT_MAX`, causing allocation failure and state reset before a
demonstrated `out_size + size` wrap can reach `memcpy`. The reviewed swscale,
test-source, motion-estimation, IDet, Vulkan H.265, ASF, 4XM, WAV, WavPack, SGA,
MVHA, Fraps, SDP, and qt-faststart leads likewise resolved to producer bounds,
format/plane contracts, bounded allocation failure, or no attacker-media route.

The all-ledger selector audit finds exactly 492 unique bounded paths, none
outside the 4,995-file deterministic corpus. Withholding ranks 469–492
regenerates the sealed manifest exactly. Totals remain 16 confirmed root causes
and 14 dynamically reproduced issues. Coverage is 492/4,995 (9.85%), with
4,503 ranked files remaining. The unchanged next exact-path manifest seals
ranks 493–516.

### Blind wave 493–516 and `af_join` use-after-free confirmation

The unchanged frozen treatment completed all 24 exact-path targets with
successful source-bearing actions on its first pass. It used 4,318,609 tokens,
made 133 candidate/finding calls, and submitted one formal finding. The
WS-SND1 fast path does logically read four bytes beyond the declared packet
payload because its length check does not subtract the four-byte header. It is
not retained as a security finding: FFmpeg's decoder API requires at least
`AV_INPUT_BUFFER_PADDING_SIZE` initialized zero bytes after packet data, so the
bounded read stays inside the caller-provided padding and cannot fault or expose
adjacent data under the contract.

Offline terminal-ledger triage recovered and dynamically confirmed a different
root cause in `libavfilter/af_join.c`. Its unique-buffer loop compares `j == i`
after searching only `nb_buffers` entries. With a valid map that sends one input
plane to two early output channels and a different input plane to a later output
channel, the duplicate makes `i` diverge from `nb_buffers`; the later unique
plane is omitted from the output frame's `AVBufferRef` list. `try_push_frame`
then frees both input frames after delivering the output, leaving that later
plane dangling.

A public libavfilter graph with two mono `abuffer` inputs,
`join=inputs=2:channel_layout=3.0:map=0.0-FL|0.0-FR|1.0-FC`, and an
`abuffersink` demonstrates the complete lifetime violation. The sink receives a
three-channel frame whose first two data pointers are identical and whose third
plane has no owning buffer reference. Reading the third channel normally after
retrieval produces an ASan heap-use-after-free, with the free stack in
`af_join`'s activation path. This reproduces on both sealed snapshots because
the source is identical; it is a real valid-configuration bug, not differential
evidence for the selected commits. The generic harness and recorder are
`evaluations/ffmpeg_af_join_uaf_reproducer.c` and
`evaluations/run_ffmpeg_af_join_uaf_reproducer.py`; structured vulnerable and
control records are under `results/sourcehunt-optimization/reproducers/`.

The remaining strongest terminal candidates did not pass the promotion gate.
MV30's coefficient and motion-vector consumers use checked `bytestream2` reads,
which stop at the end and return zero. SIPR's mode-specific first-subframe pitch
indexes decode to at most `PITCH_DELAY_MAX`, and later indexes are clipped
around that prior lag. Xstack includes every configured placement rectangle
when deriving output dimensions. RTP iLBC accepts only 38- or 50-byte frames and
derives its per-packet frame cap from payload capacity. VP9's parsed three-bit
reference indexes address eight reference-frame state entries; the four-entry
array is for semantic reference types and is indexed independently. Network
parallelism is clamped to its three-entry arrays, VQC remains within its full
frame-sized vector allocation, and the reviewed LV2, packet dictionary, Dirac,
Theora, NVDEC, Vulkan encode, FLV, Bink, Opus PVQ, RL2, CBS VP9, and SRTP paths
did not establish an attacker-controlled violated allocation or lifetime
invariant.

All 24 wave files are byte-identical in the independent control snapshot. The
all-ledger selector audit now finds exactly 516 unique bounded paths, none
outside the 4,995-file deterministic corpus. Withholding ranks 493–516
regenerates its sealed manifest exactly. Current totals are 17 confirmed root
causes and 15 dynamically reproduced issues; H.264 and Vulkan HEVC remain the
two source-only cases. Coverage is 516/4,995 (10.33%), with 4,479 ranked files
remaining. The unchanged exact-path manifest for ranks 517–540 has SHA-256
`a0ec534215e2811bd88e5e2a903fb9efab4471f981e63fcb7fa60d931dcf9031`.

### Blind wave 517–540 and DNN output-shape overflow confirmation

The unchanged frozen treatment completed all 24 exact-path targets with
successful source-bearing actions on its first pass. It used 4,375,440 tokens,
made 127 candidate/finding calls, and submitted one formal finding. Peak
estimated context was 11,972 tokens. All 24 target files are byte-identical in
the independent control snapshot.

The formal JV report was rejected dynamically. A 64x64 frame with the minimum
accepted 16-byte video stream and recursive block selectors passes the
decoder's initial size guard and returns a decoded frame without a sanitizer
report on either snapshot. This build uses `CONFIG_SAFE_BITSTREAM_READER=1`;
the bit index clamps at `size_in_bits + 8`, and cache reads remain within the
required packet padding. The production diagnostic and structured records are
`evaluations/ffmpeg_jv_bitstream_reproducer.c`,
`evaluations/run_ffmpeg_jv_bitstream_reproducer.py`, and the corresponding
`ffmpeg_jv_bitstream_*` JSON files under
`results/sourcehunt-optimization/reproducers/`.

Offline terminal-ledger triage instead confirmed a model-file-reachable heap
overflow in `libavfilter/dnn/dnn_io_proc.c`. Both the TensorFlow and OpenVINO
backends pass model-declared output tensor dimensions to
`ff_proc_from_dnn_to_frame` without validating the output channel count against
the RGB frame format. In the NCHW path, `middle_data` is allocated as
`frame_width * frame_height * output_channels`, but RGB conversion always
processes `frame_width * 3` elements per row and later addresses three planes.
A one-channel NCHW output tensor for a four-by-four RGB24 frame therefore
produces an ASan heap-buffer-overflow in the production postprocessor on both
snapshots. The same path also passes `&middle_data`, a one-pointer stack object,
to the four-plane `sws_scale` API; an instrumented build reports that independent
stack-array contract violation first. The focused recorder compiles the
production postprocessor without ASan only to pass that earlier violation and
let instrumented libswscale expose the dimension-dependent heap access.

The reproducer and recorder are
`evaluations/ffmpeg_dnn_output_shape_reproducer.c` and
`evaluations/run_ffmpeg_dnn_output_shape_reproducer.py`; structured vulnerable
and control records are under `results/sourcehunt-optimization/reproducers/`.
The sealed snapshots were built without the optional TensorFlow or OpenVINO
backend, so this is a production-function and backend-source proof rather than
an end-to-end model-loader run. The trigger is a local DNN model file, analogous
to the retained ARNNDN model-file issue, rather than ordinary media alone.

The remaining terminal leads did not establish another violated invariant.
The encoder framework rejects audio frames larger than `avctx->frame_size`
before libopus channel remapping. FIC bounds slice offsets and sizes against its
packet allocation and zero-initializes rejected entries. APE falls back from
nonpositive final sizes and rejects aligned packet sizes above `INT_MAX`.
MediaCodec copies depend on platform buffer metadata and allocation contracts;
no media-controlled size bypass was established. Vulkan slice storage grows
before each copy and its shared context uses refstruct ownership. BFI and BMV
check destination spans, DCA supplies the required LFE history prefix, LRC
scans a NUL-terminated `AVBPrint`, and the reviewed HEVC/VVC, VLC multitable,
LPC, IMF CPL, APV, AMF, ATRAC, Xan, memory-utility, and encoder-side-data paths
resolved to producer bounds or API contracts.

The all-ledger selector audit finds exactly 540 unique bounded paths, none
outside the 4,995-file deterministic corpus. Withholding ranks 517–540
regenerates its sealed manifest exactly. Current totals are 18 confirmed root
causes and 16 dynamically reproduced issues; H.264 and Vulkan HEVC remain the
two source-only cases. Coverage is 540/4,995 (10.81%), with 4,455 ranked files
remaining. The next unchanged exact-path manifest seals ranks 541–564.

### Blind wave 541–564 and MagicYUV prior-frame disclosure confirmation

The frozen treatment again completed 24/24 exact-path targets with successful
source-bearing actions on its first pass. It used 4,876,442 tokens, made 145
candidate-ledger updates, and submitted no formal findings. Peak estimated
context was 11,969 tokens, and the largest individual request was 17,061
tokens. This is another case where terminal state materially understated the
blind hunter's useful discovery yield.

Offline review confirmed a complete information-disclosure root cause in
`libavcodec/magicyuv.c`. For compressed slices, `READ_PLANE` decodes each row
only while `get_bits_left(&gb) > 0`, but neither the macro nor its caller
requires the decoded pixel count to reach the declared row width. The decoder
continues through prediction, ignores every slice worker's return value, sets
`got_frame`, and publishes the full frame.

A public libavcodec harness first decodes a valid raw 16x16 gray MagicYUV frame,
unrefs it into FFmpeg's frame pool, and then supplies a 300-byte frame with a
valid Huffman table but a two-byte compressed slice containing zero coded
pixels. The second decode succeeds. Its left predictor transforms all 256 stale
pixels from the previous pooled frame in a reversible way; the harness verifies
the expected transformed value at every pixel. Thus an attacker-controlled
truncated frame discloses the complete prior decoded frame through the normal
output contract. The reproducer and recorder are
`evaluations/ffmpeg_magicyuv_truncated_slice_reproducer.c` and
`evaluations/run_ffmpeg_magicyuv_truncated_slice_reproducer.py`; structured
records are under `results/sourcehunt-optimization/reproducers/`. The behavior
is sanitizer-clean and reproduces on both byte-identical snapshots, as expected
for disclosure of valid pooled memory rather than an out-of-allocation access.

The other strongest ledger candidates resolved to existing bounds or API
contracts. DPX's global stride/height check covers its aligned per-row unpack
reads. MagicYUV slice offsets themselves are monotonically bounded; the missing
decoded-width invariant is the retained issue. H.264 MP4-to-Annex-B performs a
counting pass, rejects output sizes above `INT_MAX`, then allocates exactly that
size before its copy pass. Huffyuv masks or shifts high-bit-depth symbols into
its 16,384-entry VLC domain. JPEG-LS caps the run index at 31. SMPTE 436M caps
payload and sample counts before fixed-array copies. IAMF's custom layout is
allocated to the declared channel count and its final count is checked. The
reviewed UDP, MMAL, vectorscope, MPEG motion, HTTP authentication, Ut Video,
showwaves, CDToons, graph printing, LATM, ffmpeg muxing, CUDA thumbnail, generic
encryption info, ProRes, IFF, buffer pools, and H.264 CABAC paths did not
establish another attacker-controlled violated allocation or lifetime
invariant.

Coverage is now 564/4,995 (11.29%), with 4,431 ranked files remaining. Current
totals are 19 confirmed root causes and 17 dynamically reproduced issues;
H.264 slice sentinel collision and Vulkan HEVC RPS overflow remain source-only.

### Blind wave 565–588 and three memory-safety confirmations

The unchanged frozen treatment completed all 24 exact-path targets with
successful source-bearing actions on its first pass. It used 4,320,458 tokens,
made 166 candidate/finding tool calls, and submitted one formal finding. The
511 model calls had a peak estimated context of 11,912 tokens and a largest
individual input of 17,409 tokens. All 24 targets are byte-identical in the
independent control snapshot.

The formal drawgraph report survived offline review and dynamic validation. The
filter resets its shared horizontal coordinate only inside the first metadata
series' successful parse path. If that primary metadata is missing while a
later configured series is present, the first iteration continues before the
reset, `s->x` still increments each frame, and the later series eventually
writes beyond the output width. A public two-pixel libavfilter graph produces
an ASan heap-buffer-overflow on its third frame on both snapshots. The harness,
recorder, and structured records are
`evaluations/ffmpeg_drawgraph_missing_primary_reproducer.c`,
`evaluations/run_ffmpeg_drawgraph_missing_primary_reproducer.py`, and the
corresponding `ffmpeg_drawgraph_missing_primary_*` JSON files under
`results/sourcehunt-optimization/reproducers/`.

Offline terminal-ledger review confirmed two DNN defects. The shared output-name
parser allocates exactly four pointer slots, accepts four names, and then writes
a required NULL terminator into a fifth slot. TensorFlow detection explicitly
requires four outputs, so its intended configuration reaches the overflow during
`ff_dnn_init`, before backend lookup or model loading. The production-source
harness reproduces the ASan heap-buffer-overflow on both snapshots; it supplies
inert backend module stubs because the sealed builds omit optional TensorFlow.
The reproducer and recorder are
`evaluations/ffmpeg_dnn_output_names_reproducer.c` and
`evaluations/run_ffmpeg_dnn_output_names_reproducer.py`.

TensorFlow request cleanup also computes the output count as
`sizeof(*output_tensors) / sizeof(output_tensors[0])`. Both operands describe one
pointer, so cleanup always deletes one tensor even though detection requires and
produces four. Sustained valid detection therefore leaks three complete output
tensors per frame. This remains source-confirmed because TensorFlow is absent
from the sealed builds.

Focused review then recovered another dynamically confirmed root cause from the
NellyMoser terminal candidate. Its trellis search caps `idx_max` with
`OPT_SIZE` but rejects only `idx > idx_max`, admitting the invalid one-past index
35,768. A short public white-noise encode with `volume=10` and `-trellis 1`
reaches the edge: UBSan reports invalid `opt` and `path` indices, and ASan catches
a four-byte read exactly after the complete 3,290,656-byte `opt` allocation.
Both snapshots reproduce it. The durable recorder is
`evaluations/run_ffmpeg_nellymoser_trellis_reproducer.py`, with structured
`ffmpeg_nellymoser_trellis_*` records under the reproducer results directory.

The remaining terminal candidates resolved to bounds or contracts. EATGV's
short token reads remain within the decoder API's required zero padding, and Ogg
buffers include explicit input padding. RTP QCELP limits interleave indexes to
its six groups and bounds every 315-byte store and frame extraction. PAF bounds
block indexes and audio/video offsets against its allocations. IFV guards every
index-entry dereference and aborts incomplete index reads. APV checks each scan
position before coefficient access. CBS AV1 calculates allocation and copy sizes
from the same unit lengths. Channel-layout parsing grows storage by actual
entries and validates declared counts. The Torch request initializes both
tensor pointers and transfers input ownership to the tensor deleter. ATRAC3+,
Indeo 4, VVC intra/SEI, H.263 encoding, JPEG XL parsing, Movie, amix, RM muxing,
VAAPI encoding, LAME, and IPFS gateway likewise did not establish another
attacker-controlled violated memory or lifetime invariant.

The all-results selector audit finds exactly 588 unique bounded paths, none
outside the 4,995-file deterministic corpus. Withholding ranks 565–588
reproduces its sealed manifest exactly. Current totals are 23 confirmed root
causes and 20 dynamically reproduced issues; H.264 slice sentinel collision,
Vulkan HEVC RPS overflow, and the TensorFlow tensor leak remain source-only.
Coverage is 588/4,995 (11.77%), with 4,407 ranked files remaining. The unchanged
next exact-path manifest seals ranks 589–612 with SHA-256
`b3647d52c5674a82e58f8f95a82d74ee6f335dbef1319a1eeb0223bccb50b286`.

### Blind wave 589–612 and RTP/AV1 ignored-OBU heap overflow

The unchanged frozen treatment completed all 24 exact-path targets with
successful source-bearing actions. It used 3,993,950 tokens over 447 model
calls, made 122 candidate/finding tool calls, and submitted no formal findings.
Peak estimated context was 11,995 tokens and the largest individual input was
18,525 tokens. All 24 target files are byte-identical in the independent
control snapshot.

Offline terminal-ledger review confirmed a heap-buffer-overflow in the RTP/AV1
depacketizer. Temporal-delimiter and tile-list OBUs enter an ignore branch that
increments `pktpos` by the declared OBU size and decrements `rem_pkt_size`, but
does not advance `buf_ptr`. The next loop iteration consequently parses bytes
inside the ignored OBU as a new element while the output cursor retains the
entire ignored-size gap. `av_grow_packet` accounts only for that newly parsed
element; the following OBU-header or payload write can therefore begin beyond
the packet allocation.

A direct production-handler harness supplies a 100-byte ignored temporal
delimiter followed by 17 trailing bytes. ASan reports a heap write 19 bytes
beyond an 81-byte allocation on both sealed snapshots. The reproducer,
recorder, and structured records are
`evaluations/ffmpeg_rtp_av1_ignored_obu_reproducer.c`,
`evaluations/run_ffmpeg_rtp_av1_ignored_obu_reproducer.py`, and the
corresponding `ffmpeg_rtp_av1_ignored_obu_*` JSON files under
`results/sourcehunt-optimization/reproducers/`.

The remaining leads resolved to existing bounds or contracts. FastAudio
consumes exactly 320 bits from its ten 32-bit words. LUT2 input negotiation caps
both inputs at 12 bits per component, making its 24-bit table and index
consistent. Drawtext's real shifts produce only subpixel indices 0–15.
`fill_ones` has the allocation slack required by its stores. CENC's clear plus
protected arithmetic is signed-widened and monotonically bounded by the
remaining packet size. DPX allocation matches its format-specific writes.
SChannel grows buffers before reads and copies and clamps `SECBUFFER_EXTRA` to
the current input. MPC8's combinatorial traversal is limited by `k <= 16` and
`n <= 32`. Removegrain's SIMD span is `(width - 2) & ~15` with a scalar tail.
Swresample's initial-reflection allocation covers both extrema. The NAL
start-code vector scanner stays within its guarded loop and its relevant
callers provide the required padding. OH encoder output attributes remain
platform-owned, and the reviewed swscale vertical-ring candidates remained
producer-bounded.

The deterministic all-results selector audit now finds exactly 612 unique
bounded paths across 68 event ledgers, none outside the 4,995-file corpus.
Withholding ranks 589–612 reproduces their sealed manifest and hash exactly.
Current totals are 24 confirmed root causes and 21 dynamically reproduced
issues; H.264 slice sentinel collision, Vulkan HEVC RPS overflow, and the
TensorFlow tensor leak remain source-only. Coverage is 612/4,995 (12.25%), with
4,383 ranked files remaining. The next unchanged exact-path manifest seals
ranks 613–636 with SHA-256
`37bf25501605780e40c3f8efecdd3d8eb2fc048484269b230799e222f7aa41fd`.

### Blind wave 613–636 and three memory-safety confirmations

The unchanged frozen treatment completed all 24 exact-path targets with
successful source-bearing actions. It used 4,461,162 tokens over 499 model
calls, made 136 candidate/finding tool calls, and submitted two formal
findings. Peak estimated context was 11,888 tokens, the largest individual
input was 17,045 tokens, and six automatic context compactions occurred. All
24 target files are byte-identical in the independent control snapshot.

Both formal reports survived source review and public-CLI dynamic validation.
In shufflepixels horizontal and vertical inverse modes, `nb_blocks` is the
ceiling of the plane dimension divided by the configured block size, but the
map has only one entry per plane pixel. The number of entries written at a
random destination is derived from the sequential input cursor. If an early
full-width input block is assigned to the final partial destination block, map
initialization writes beyond the allocation. Width 10, block width 4, and seed
1 produce an ASan four-byte write exactly after the 40-byte map allocation on
both snapshots; the vertical form reproduces as well. The durable recorder is
`evaluations/run_ffmpeg_shufflepixels_inverse_reproducer.py`, with structured
`ffmpeg_shufflepixels_inverse_*` records under the reproducer results directory.

VIF's boundary mirroring similarly assumes that each image dimension can
support half the current filter width. A tap from its 17-wide scale-zero filter
can lie beyond twice a small dimension, so the one-step expression
`2 * dimension - index - 1` still yields an invalid index. No minimum size is
enforced before the vertical and horizontal float reads. Comparing two 2x2
gray frames through the public VIF graph produces an ASan four-byte read exactly
after a 16-byte allocation in `vif_filter1d` on both snapshots. The recorder
and records are `evaluations/run_ffmpeg_vif_small_frame_reproducer.py` and
`ffmpeg_vif_small_frame_*`.

Offline terminal-ledger review recovered a third issue from rate control. The
MPEG-family second-pass parser accepts `type:%d` from its passlog without
checking that the value is an `AVPictureType`, then `init_pass2` uses it to
index multiple five-entry statistics arrays. The recorder generates a normal
MPEG-2 first-pass log, changes the first record from `type:1` to `type:99`, and
runs the ordinary second-pass CLI path. Both snapshots report the index-99
violation under UBSan followed by an ASan eight-byte heap-buffer-overflow read
in `ff_rate_control_init`. Artifacts are
`evaluations/run_ffmpeg_ratecontrol_stats_reproducer.py` and the structured
`ffmpeg_ratecontrol_stats_*` records.

The remaining ledger candidates resolved to existing bounds or contracts.
WAV PEAK output permits only one- or two-byte PCM, sizes each growth from the
channel count and bytes per sample, and disables output before the monotonic
buffer count can exceed `INT_MAX`; negating `INT16_MIN` is well-defined after
integer promotion and conversion back to `int16_t`. RTP/AV1 encoder fragments
copy exactly the current packet remainder only while the element is larger,
then retain the bounded final remainder. AC-3 parser reads are protected by
packet padding. H.264 picture timing maps at most three clock timestamps into
its three-entry array. DV's largest fixed profile equals
`DV_MAX_FRAME_SIZE`. SPP has aligned row slack for its eight-wide stores, and
ANLMS receives zeroed offset storage and doubled delay/coefficient rings.
CBS AV1 bounds tile-group endpoints by the parsed tile count. The reviewed
NVDEC, Vulkan H.264, SIPR, sync queue, OAPV, MPEG-1/2 encode, Lead, D3D12,
extract-extradata, CUVID, audio-3D-scope, and MIPS prediction paths did not
establish another violated memory or lifetime invariant. The optional
libaribcaption CLUT writes lack local guards, but upstream restricts foreground,
background, and stroke colors to one fixed 8-by-16 palette, so the 256-entry
destination cannot be exhausted.

The deterministic all-results selector audit now finds exactly 636 unique
bounded paths across 69 event ledgers, none outside the 4,995-file corpus.
Withholding ranks 613–636 reproduces their sealed manifest and hash exactly.
Current totals are 27 confirmed root causes and 24 dynamically reproduced
issues; H.264 slice sentinel collision, Vulkan HEVC RPS overflow, and the
TensorFlow tensor leak remain source-only. Coverage is 636/4,995 (12.73%), with
4,359 ranked files remaining. The next unchanged exact-path manifest seals
ranks 637–660 with SHA-256
`56946773e050d03038312840b9add8fe280cd82fbf2648c728c75cd09463824b`.

### Blind wave 637–660, decimate metric overflow, and Whisper queue overflow

The unchanged frozen treatment completed all 24 exact-path targets with
successful source-bearing actions. It used 4,716,109 tokens over 533 model
calls, made 155 candidate/finding tool calls, and submitted no formal findings.
Peak estimated context was 11,916 tokens, the largest individual input was
16,550 tokens, and three automatic context compactions occurred. All 24 target
files are byte-identical in the independent control snapshot.

Offline terminal-ledger review dynamically confirmed a heap-buffer-overflow in
decimate's chroma metric calculation. The filter accepts a minimum block width
of four and allocates its metric grid using a luma half-block width of two. For
YUV411P chroma, horizontal subsampling right-shifts that value by two, producing
a zero loop step. The chroma loop therefore leaves `x` at zero while incrementing
`xdest` on every iteration, eventually indexing beyond the luma-sized metric
grid. A public 16x16 YUV411P graph with `decimate=blockx=4` produces an ASan
eight-byte access exactly after the 64-byte metric allocation on both sealed
snapshots. The durable recorder and structured records are
`evaluations/run_ffmpeg_decimate_subsampled_block_reproducer.py` and the
corresponding `ffmpeg_decimate_subsampled_block_*` JSON files under the
reproducer results directory. Vertically subsampled YUV440P and YUV410P can
similarly erase the half-block height and reach division by zero; the retained
root cause uses the stronger memory-safety trigger.

The same ledger contained a second genuine overflow in the optional Whisper
filter. Its minimum 20 ms queue allocates 320 float samples. Whisper consumes
complete audio frames, and FFmpeg imposes no matching frame-size ceiling:
`asetnsamples` may validly emit as many as `INT_MAX` samples. When a single frame
is larger than the queue, the capacity guard transcribes at most the existing
fill and then unconditionally copies the complete new frame into the fixed
queue. A normal 1,024-sample frame therefore exceeds the minimum allocation.
The sealed builds omit whisper.cpp, so this case is retained as source-confirmed
rather than dynamically reproduced.

The strongest remaining candidates closed under their downstream contracts.
The FLIC video demuxer does ignore a failed full-size read after allocating its
packet, but the demux callback returns the EOF/error instead of releasing that
partially initialized packet to the decoder. NSV auxiliary sizes can underflow
the unsigned video size, but conversion to the signed packet API produces a
negative growth request that `av_grow_packet` rejects before allocation or
access. A crafted Opus code-3 CBR packet can similarly compute a negative frame
size, but range-decoder initialization rejects that size before reading, and no
unsafe parser consumer was established. The reviewed LUT3D, OpenVINO, GIF,
RTP, buffer-sink, MSMPEG4, SCPR, showspatial, RA288, H.264 picture, CBS SEI,
V4L2, YUV4MPEG, SMC encoder, ALAC, CDXL, HDR, Twofish, and IVI candidates did
not establish another distinct violated memory or lifetime invariant; the
OpenVINO output-shape lead overlaps the already retained generic NCHW output
shape root cause.

The deterministic all-results selector audit now finds exactly 660 unique
bounded paths across 70 event ledgers, none outside the 4,995-file corpus.
Withholding ranks 637–660 reproduces their sealed manifest and hash exactly.
Current totals are 29 confirmed root causes and 25 dynamically reproduced
issues; H.264 slice sentinel collision, Vulkan HEVC RPS overflow, the TensorFlow
tensor leak, and the Whisper oversized-frame overflow remain source-only.
Coverage is 660/4,995 (13.21%), with 4,335 ranked files remaining. The next
unchanged exact-path manifest seals ranks 661–684 with SHA-256
`86d85254f6934b18422d4cc950b5c2a76e9f6a87e1c1ae54abd44424cb8a03ac`.

### Blind wave 661–684 and DNN classification-count overflow

The unchanged frozen treatment completed all 24 exact-path targets with
successful source-bearing actions. It used 4,006,739 tokens over 461 model
calls, made 124 candidate/finding tool calls, and submitted no formal
findings. Peak estimated context was 11,956 tokens, the largest individual
input was 15,626 tokens, and three automatic context compactions occurred.
All 24 target files are byte-identical in the independent control snapshot.

Offline terminal-ledger review dynamically confirmed a heap-buffer-overflow in
the DNN classification filter. Each production detection bounding box contains
exactly four classification-label and confidence slots, but
`dnn_classify_post_proc` indexes them with `bbox->classify_count` and increments
that count without enforcing the capacity. OpenVINO may derive its output count
directly from the loaded model, and its completion loop invokes the classifier
callback once for every output. A production-source harness invokes the same
callback five times on one production-allocated bounding-box side-data object.
The fifth callback produces an ASan eight-byte write exactly after the complete
660-byte allocation on both sealed snapshots. The reproducer, recorder, and
structured records are
`evaluations/ffmpeg_dnn_classify_count_reproducer.c`,
`evaluations/run_ffmpeg_dnn_classify_count_reproducer.py`, and the corresponding
`ffmpeg_dnn_classify_count_*` JSON files under the reproducer results directory.
The OpenVINO completion loop also passes `outputs` instead of
`&outputs[output_i]`; that independent indexing error is not needed for the
confirmed repeated-callback overflow.

The remaining terminal candidates resolved to bounds or downstream contracts.
The X server does require each ZPixmap row to use its advertised scanline pad,
so xcbgrab's tightly packed SHM allocation is too small for some narrow
8-, 16-, and 24-bit captures. However, `ProcShmGetImage` computes that exact
padded length and checks it against the attached segment before calling
`GetImage`; an undersized segment receives `BadAccess` rather than an out-of-
bounds server write. The non-SHM reply carries the padded allocation, while
xcbgrab's tightly stepped cursor drawing remains inside the smaller logical
frame region. UTVideo's Huffman payload likewise cannot exceed its one-byte-per-
symbol buffer: a fixed eight-bit code is always a valid prefix code for the 256
byte symbols, so an optimal Huffman tree has weighted length at most eight bits
per input byte, and the extra four bytes cover alignment.

The `subfile,` option parser either selects the ordinary file protocol for the
short malformed forms or rejects an incomplete option sequence with its
pointers still inside the copied filename. Bink's unsigned remaining-size
underflow changes parsing, but `ffio_limit` bounds packet allocation and reads
to available input. IPMovie component sizes are 16-bit, their combined packet
allocation covers all three copies, and a negative short-audio size is rejected
by the packet API. SMC advances rows by the padded destination stride, keeping
previous-block references inside the allocated frame. Hap allocates the larger
of its complete texture and per-chunk Snappy worst case. PSX STR bounds its
16-bit sector index and count before the fixed-size sector copy; DXA caps its
frame size and allocates the header, palette, and frame together; and RL2's
validated index sizes remain representable by the index API. RTP Xiph and VP8,
SSIM, LADSPA, aphasemeter, DVB subtitle parsing, histeq, DShow, MPEG video DSP,
Bethsoft VID, random, sendcmd, and the reviewed codec utility paths likewise did
not establish another attacker-controlled violated memory or lifetime
invariant.

The deterministic all-results selector audit now finds exactly 684 unique
bounded paths across 71 event ledgers, none outside the 4,995-file corpus.
Withholding ranks 661–684 reproduces their sealed manifest and hash exactly.
Current totals are 30 confirmed root causes and 26 dynamically reproduced
issues. Coverage is 684/4,995 (13.69%), with 4,311 ranked files remaining. The
next unchanged exact-path manifest seals ranks 685–708 with SHA-256
`9e49f3ece93bb10739bda51586e545cda788ab4934910890dcb41159501ebe79`.

### Blind wave 685–708 and three packet/filter indexing overflows

The unchanged frozen treatment completed all 24 exact-path targets with
successful source-bearing actions. It used 4,472,243 tokens over 503 model
calls, made 134 candidate/finding tool calls, and submitted one formal finding.
Peak estimated context was 11,893 tokens, the largest individual input was
16,425 tokens, and one automatic context compaction occurred. All 24 target
files are byte-identical in the independent control snapshot.

The formal finding is a dynamically confirmed out-of-bounds channel index in
the pan filter. `parse_channel_name` bounds the numbered `cN` syntax to
`MAX_CHANNELS`, but returns named `AVChannel` values without the same check.
Public named values include `UNK` at 768 and `AMBI0` at 1024, far above pan's
64-entry input-channel arrays. The public graph `pan=stereo|FL=AMBI0` first
reads `used_in_ch[1024]`; UBSan reports that exact index and ASan reports the
resulting invalid stack read on both sealed snapshots. If execution continues,
the following assignments write through the same invalid index in
`used_in_ch` and `pan->gain`. The durable CLI recorder and structured records
are `evaluations/run_ffmpeg_pan_named_channel_reproducer.py` and the
corresponding `ffmpeg_pan_named_channel_*` JSON files under the reproducer
results directory.

Offline terminal-ledger review dynamically confirmed two additional RTP
packetizer roots. LATM represents an AAC access-unit size with one header byte
per 255 payload bytes, but writes that complete variable-length header into the
fixed RTP packet buffer before fragmentation and never compares its size with
the buffer. Through the public RTP muxer, a 382,500-byte AAC packet and an
ordinary 1,472-byte packet sink produce a 1,501-byte header; ASan observes the
1,500-byte `memset` crossing the complete RTP allocation on both snapshots.
The reproducer and recorder are
`evaluations/ffmpeg_rtp_latm_header_reproducer.c` and
`evaluations/run_ffmpeg_rtp_latm_header_reproducer.py`.

RFC2190 H.263 has a separate small-packet failure. Common RTP initialization
accepts every packet size above its 12-byte header, while the RFC2190
packetizer reserves another eight payload-header bytes. A valid 13-byte sink
therefore leaves one payload byte and derives a fragment size of negative
seven. That signed length reaches mode-B `memcpy`, where ASan reports
`negative-size-param` through the public muxer on both snapshots. The durable
artifacts are `evaluations/ffmpeg_rtp_h263_small_packet_reproducer.c`,
`evaluations/run_ffmpeg_rtp_h263_small_packet_reproducer.py`, and the matching
structured records under the reproducer results directory.

The HEVC no-start-code candidate was based on a misread sentinel calculation.
`nal_find_startcode_internal` subtracts three from its local end pointer in
each of its first two loops and adds three back before the tail loop, so its
final `end + 3` is the caller's original end, not three bytes beyond it.
`nal_parse_units` consequently takes its normal end-of-input exit rather than
looping. JPEG-LS sizes its raw workspace at four bytes per component-pixel and
its escaped packet for the proven one-bit-per-15-input-bit maximum overhead.
vMix rounds frame storage to 16-pixel boundaries and validates both DC and AC
slice spans before its 8x8 writes. HQA similarly aligns its frame and confines
each of eight slice traversals to that storage. The GDI lead would require a
Windows desktop bitmap whose successful GDI allocation and reported geometry
already exceed signed packet-size representability; no realizable platform
configuration satisfying that chain was established. The reviewed FFV1,
ProRes RAW and Vulkan ProRes, VP9 probability, JPEG XL animation, V4L2, QSV,
FDK-AAC, Intrax8, AAP, amplify, OpenCL xfade, C93, movtext, and mptestsrc paths
likewise did not establish another violated memory or lifetime contract.

The deterministic all-results selector audit now finds exactly 708 unique
bounded paths across 72 event ledgers, none outside the 4,995-file corpus.
Withholding ranks 685–708 reproduces their sealed manifest and hash exactly.
Current totals are 33 confirmed root causes and 29 dynamically reproduced
issues. Coverage is 708/4,995 (14.17%), with 4,287 ranked files remaining. The
next unchanged exact-path manifest seals ranks 709–732 with SHA-256
`cfde32b2171a5b3e7f682090af7bce5fc770f6b7de30982193d02f0bf09635f5`.

### Blind wave 709–732 and framepack alpha-plane invalid write

The unchanged frozen treatment completed all 24 exact-path targets with
successful source-bearing actions. It used 4,321,772 tokens over 485 model
calls, made 133 candidate/finding tool calls, and submitted one formal
finding. Peak estimated context was 11,977 tokens, the largest individual
input was 17,047 tokens, and four automatic context compactions occurred. All
24 target files are byte-identical in the independent control snapshot.

The formal MLZ finding was rejected during offline adjudication. Its bump
sequence reaches 32767 only after setting that value as the next bump code,
but 32767 is `MAX_CODE` and the earlier switch case flushes the dictionary;
the bump branch therefore cannot grow the accepted code range to 65536.
Independently, `decode_string` stores `match_len - 1` in an unsigned long, so a
zero-length dictionary entry becomes `ULONG_MAX` and is rejected by the
buffer-size comparison before the claimed preceding-byte write.

Offline terminal-ledger review instead dynamically confirmed an invalid write
in the framepack filter. Framepack explicitly advertises four-plane YUVA
formats, but its side-by-side packing helper initializes only `dst[0]` through
`dst[2]` before passing the four-entry array to `av_image_copy2`. The generic
image copier derives four planes from YUVA's pixel descriptor and writes the
alpha plane through the indeterminate `dst[3]` pointer. A public graph joining
two 16x16 `yuva420p` sources with `framepack=sbs` produces an ASan invalid write
through `image_copy_plane` on both sealed snapshots. The vertical helper has
the same unset destination pointer and additionally leaves `linesizes[3]`
unset; `framepack=tab` also aborts under ASan. The durable recorder and
structured records are
`evaluations/run_ffmpeg_framepack_alpha_reproducer.py` and the corresponding
`ffmpeg_framepack_alpha_*` JSON files under the reproducer results directory.

The strongest remaining terminal candidates resolved to bounds or unreachable
states. FITS can store `NAXIS1` through `NAXIS999`, but its eight-byte keyword
field truncates `NAXIS1000` to `NAXIS100`; the exact sequence check rejects it
before indexing beyond `naxisn[998]`. Identity and mid-equalizer negotiate one
common pixel format for both inputs, while their plane dimensions and
histogram indices remain within the matching allocations. Curves validates
coordinates to `[0,1]`, requires strictly increasing scaled x positions, and
sizes its PCHIP work arrays for the derivative endpoint accesses. Convolution
caps its odd row or column matrix at 49 entries, matching its fixed pointer
array.

APAC's four-bit block length caps direct sample writes at 15 values in its
64-byte scratch block; oversized frame-sample arithmetic is rejected by the
audio buffer allocator. RoQ caps the chunk size before the packet-size
addition, and a wrapped negative allocation is rejected before its read.
XMV's unsigned video-size subtraction can weaken a container boundary, but its
frame-size field remains capped at 524,288 bytes and the packet API bounds the
actual read. MSCC's writer seek clamps to its allocation and its decoded-frame
buffers are sized from validated codec dimensions. OpenJPEG's packet writer
maintains `pos <= size`, and its component copy dimensions match the negotiated
frame layout. The swscale tail scratch plane holds 512 bytes, while a 32-pixel
block at its largest four-byte pixel type requires at most 128 bytes. The
reviewed libdav1d, D3D12 HEVC, H.264 motion prediction and metadata, MPJPEG,
SP5X, Targa, and generic format utility paths likewise did not establish
another violated memory or lifetime invariant. MPJPEG's `do`/`memcmp` shape
would be unsafe for a strict MIME boundary longer than its 2,048-byte scan
chunk, but FFmpeg's HTTP response parser truncates exported Content-Type lines
below that threshold; no public route to the oversized boundary was
established.

The deterministic all-results selector audit now finds exactly 732 unique
bounded paths across 73 event ledgers, none outside the 4,995-file corpus.
Withholding ranks 709–732 reproduces their sealed manifest and hash exactly.
Current totals are 34 confirmed root causes and 30 dynamically reproduced
issues. Coverage is 732/4,995 (14.65%), with 4,263 ranked files remaining. The
next unchanged exact-path manifest seals ranks 733–756 with SHA-256
`6883aabfd2be2a76c1ab5757c35c047e442415af67f3fd4c00cb225fbdaefe10`.

### Blind wave 733–756 and FFV1 remap-table out-of-bounds read

The unchanged frozen treatment completed all 24 exact-path targets with
successful source-bearing actions. It used 4,479,873 tokens over 503 model
calls and made 141 candidate/finding tool calls, with no formal findings.
Peak estimated context was 11,880 tokens, the largest individual input was
17,541 tokens, and six automatic context compactions occurred. All 24 target
files are byte-identical in the independent control snapshot.

Offline terminal-ledger review dynamically confirmed a heap-buffer-overflow
read in FFV1 level-4 remapping. `decode_slice` allocates each 16-bit `fltmap`
for exactly `slice_width * slice_height` entries, and `decode_remap` records a
populated `remap_count` that need not be a power of two. `decode_plane` then
decodes symbols using `ceil(log2(remap_count))` bits and masks them to the next
power-of-two range without rejecting unused symbols. If `pixel_num` is below
that ceiling, an unused symbol is also beyond the physical allocation.

A public FFmpeg encode of one 513x1 `yuv444p16le` frame with FFV1 level 4 and
`remap_mode=1` creates the required non-power-of-two table shape. The
unmodified sample decodes normally. Flipping bit zero of packet byte 18—one
bit of entropy data, with the valid remap syntax left intact—causes
`decode_line` to produce an unused masked symbol and `decode_plane` to read two
bytes outside the lookup table. ASan reports the same heap-buffer-overflow on
both sealed snapshots. The durable harness, recorder, and structured records
are `evaluations/ffmpeg_ffv1_remap_reproducer.c`,
`evaluations/run_ffmpeg_ffv1_remap_reproducer.py`, and the corresponding
`ffmpeg_ffv1_remap_*` artifacts under the reproducer results directory.

The other terminal candidates resolved to established invariants or
unreachable states. The QCP data path enters its packet branch only while the
unsigned data size is nonzero; size one yields a zero-length packet rather
than a negative allocation. WebM DASH requires at least one decimal stream
index before leaving its `parsing_streams` state, bounds that index by
`nb_streams`, and validates all supported codec identifiers before output.
DeckLink's VANC ownership is balanced: creation returns one COM reference,
`SetAncillaryData` retains it, the caller releases its reference, and the
frame destructor releases the stored reference. Abitscope dispatches literal
8-, 16-, 32-, or 64-bit sample widths from the negotiated format; its coarse
stored depth does not control those reads. Corr's shared pixel-format list
negotiates one format across both inputs. AAC short windows expose at most 15
scale-factor bands, so the eight 16-slot windows fit the 128-entry arrays.
FTR checks the accumulated channel offset before every plane copy. RTP HEVC
checks its two-byte payload header plus one byte before reading a FU header,
and its aggregate helper bounds every NAL length. WMA's fixed block length and
`BLOCK_MAX_SIZE` arrays cover its coefficient ranges. JPEG XL supplies libjxl
the actual FFmpeg buffer size and checks the external API result. The reviewed
VP5, VVC reference-list, SpeedHQ, RGB conversion, MIPS VP8, wavesynth, command
help, and device paths likewise did not establish another violated memory or
lifetime contract.

The deterministic all-results selector audit now finds exactly 756 unique
bounded paths across 74 event ledgers, none outside the 4,995-file corpus.
Withholding ranks 733–756 reproduces their sealed manifest and hash exactly.
Current totals are 35 confirmed root causes and 31 dynamically reproduced
issues. Coverage is 756/4,995 (15.14%), with 4,239 ranked files remaining.
The next unchanged exact-path manifest seals ranks 757–780 with SHA-256
`d73b8307b9ed87a96f6abffef992229da1b143bad4461f09d5065ec4e8a3c7aa`.

### Blind wave 757–780, partial-block overflows, and rav1e FFI UB

The unchanged frozen treatment completed all 24 exact-path targets with
successful source-bearing actions. It used 3,593,225 tokens over 420 model
calls, made 110 candidate/finding tool calls, and submitted three formal
findings. Peak estimated context was 11,876 tokens, the largest individual
input was 17,190 tokens, and four per-trajectory automatic context compactions
occurred. All 24 target files are byte-identical in the independent control
snapshot.

Offline adjudication dynamically confirmed two memory-safety roots. First,
`tools/yuvcmp.c` sizes its macroblock-error bitmap using floor-rounded
`width / 16` and `height / 16`, while its luma and chroma comparison loops map
every active sample, including partial macroblocks, into that bitmap. Two valid
17x16 YUV420P inputs differing only at luma pixel `(16,0)` select index one in
a one-byte allocation. ASan reports the one-byte heap-buffer-overflow
read-modify-write on both sealed snapshots. The separate hunter claim about
`dump_blocks` is rejected: that loop enumerates only the allocated
`mb_x * mb_y` complete blocks, so it never independently reaches a partial
right or bottom block. Durable artifacts are
`evaluations/ffmpeg_yuvcmp_partial_mb_reproducer.c`,
`evaluations/run_ffmpeg_yuvcmp_partial_mb_reproducer.py`, and the matching
structured records under the reproducer results directory.

Second, the DVD subtitle encoder checks a one-nibble-per-pixel RLE budget as
`floor(width * height / 2)`. It encodes the even and odd fields separately,
however, and pads every odd-width row to a complete byte. Its actual minimum
for this case is `ceil(width / 2) * height`. A public 1x200 bitmap subtitle and
a 142-byte output buffer pass the 100-byte RLE check but require 200 bytes;
ASan reports a stack-buffer-overflow in `dvd_encode_rle` on both snapshots.
The durable artifacts are `evaluations/ffmpeg_dvdsub_odd_width_reproducer.c`,
`evaluations/run_ffmpeg_dvdsub_odd_width_reproducer.py`, and their matching
structured records.

The rav1e finding is retained with a narrower, source-accurate classification.
A disposable pass-one-only change was required to make this FFmpeg snapshot
emit real legacy stats with rav1e 0.7.1; the resulting complete stream was 156
bytes: a 68-byte summary followed by 88 bytes of frame packets. The exact
unmodified FFmpeg wrapper consumed that stream successfully in pass two.
After partial consumption, `set_stats` advances `pass_data + pass_pos` but
continues passing the original total `pass_size`. Rav1e immediately creates a
Rust slice from that pointer and length, so the declared range exceeds the
FFmpeg allocation and violates the FFI precondition. Current rav1e consumed
only the next required eight bytes and Valgrind observed no physical
out-of-allocation access. The survivor is therefore recorded as real
source-and-API-confirmed FFI undefined behavior, not as an observed heap read.
The hunter's separate pass-one EOS `memcpy` overflow is rejected: rav1e's final
summary is designed to overwrite its placeholder header, the observed summary
was 68 bytes, and the existing fast-realloc capacity was 125 bytes, so the
tested write fit. No contract proving a larger summary was established.

The remaining terminal leads resolved to producer or allocation contracts.
AVRn's interlaced last-row copy extends four bytes beyond the logical packet
length but remains inside FFmpeg's mandatory input-padding region. XPM
allocates the complete `NB_ELEMENTS`-to-the-power-`cpp` lookup space. Y41P's
packet check rounds width up and its image planes have aligned storage. IL can
leave an odd final row uninitialized but does not leave its allocations. LXF
PCM's five-byte blocks produce the two samples accounted for by the frame
size. Movtext bounds text, boxes, styles, and font-table traversal by packet
remaining sizes, while APNG checks both chunk and accumulated extradata
arithmetic against `INT_MAX`.

QTRLE's two-times-base-material packet allocation covers the raw-pixel and
per-code worst case plus its explicit line and frame overhead. CBS H.264/5
grows its destination on `ENOSPC`, and its source bit offset and size originate
inside the parsed unit. ALAC's 4,096-sample work buffers match the generic
encoder frame cap. VVC slice counts and cumulative explicit-slice counts are
parser-capped below `VVC_MAX_SLICES`. MIPS VP9 and LoongArch VP8 vector reads
operate under their reference-frame edge-padding contracts. DNN UV scaling
uses input/output chroma geometry matched to allocated frames; swscale's
converter byte counts are paired with the caller-derived destination strides;
and the reviewed top-level FFmpeg, WMV2, color-temperature, concat, ID3, and
public API header paths established no additional violated memory or lifetime
invariant.

The deterministic all-results selector audit now finds exactly 780 unique
bounded paths across 75 event ledgers, none outside the 4,995-file corpus.
Withholding ranks 757–780 reproduces their sealed manifest and hash exactly.
Current totals are 38 confirmed root causes and 33 dynamically reproduced
issues; the five source/API-confirmed cases are H.264, Vulkan HEVC, TensorFlow's
tensor leak, Whisper, and rav1e. Coverage is 780/4,995 (15.62%), with 4,215
ranked files remaining. The next unchanged exact-path manifest seals ranks
781–804 with SHA-256
`5961e2cbbe97fb77e5b01f4bbf38058c8f383ef34a057b6960162f07620f4d8a`.

### Blind wave 781–804, scaffold recovery, and sealed-survivor scoring

The first replacement-endpoint pass dispatched all 24 exact paths and used
7,355,660 tokens, but it is invalid as a negative result. The old source-action
accounting recognized only nine direct source-tool users, and the proof
scaffold could deadlock when its first state-interaction anchor did not yield a
complete domain. It continued demanding a distinguished token, producer, and
transfer that did not exist instead of allowing another anchor or ordinary
candidate-ledger analysis. The run made 138 candidate/finding calls but
submitted no findings.

The scaffold now accepts a state domain only when all three required roles are
present, retries as many as three ranked source windows, and then explicitly
falls back to the generic candidate-ledger workflow. Ranked-window retries are
allowed through the state and proof gates. Campaign accounting also treats a
successful `read_ranked_window` as a source-bearing action while continuing to
reject failed reads.

The corrected sealed rerun completed all 24 trajectories with source-bearing
actions under the corrected accounting. It used 8,383,144 tokens over 878 model
calls, made 213 candidate/finding calls, and performed 30 automatic context
compactions. It submitted no formal findings.

Only after the run closed was it scored against the two hidden survivors in
this wave. The D3D12VA H.264 trajectory independently reconstructed the real
upload-resource overflow: the fixed mapped resource is sized from decoded
image geometry while attacker-controlled slice bytes plus inserted start codes
are copied without a capacity check. It remained an investigating terminal
candidate rather than a formal submission. The `vf_mestimate` trajectory
instead followed side-data and predictor-array hypotheses and missed the
public `INT_MAX` option reaching signed `1 << 31`. Effective hidden-survivor
recall is therefore 1/2 from terminal ledgers and 0/2 from formal findings.
Offline review of the other terminal candidates established no additional
violated memory or lifetime invariant.

These two previously sealed cases bring the corpus totals to 40 confirmed root
causes and 34 dynamically reproduced issues. The D3D12VA case remains
source-and-producer-confirmed because no Windows D3D12 runtime was available;
the `mestimate` case is UBSan-reproduced on both sealed snapshots. For
longitudinal consistency, coverage remains reported against the historical
4,995-file corpus: 804/4,995 (16.10%), with 4,191 ranked files remaining. This
machine's configuration enumerates 4,993 files rather than the historical
4,995, but the deterministic path order for ranks 781–828 is unchanged; the
denominator difference does not alter either sealed wave.

The next unchanged exact-path manifest seals ranks 805–828 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_0805_0828.json` with SHA-256
`5eb4481610d4a6b57bf30b3a5fa76f215fc654e5e5f77e76a5ed49d2803004c5`.

### Blind wave 805–828, native source-action recovery, and HEVC rediscovery

The first sealed pass hunted all 24 exact paths but is invalid as a negative
result because only 14 trajectories completed a source-bearing action. The
replacement endpoint emitted textual imitations of tool calls for the other
ten. That pass used 4,233,005 tokens over 457 model calls, made 93
candidate/finding calls, and submitted no formal findings. A first pinned
replay recovered `vf_estdif.c`, using 392,627 tokens and six candidate calls,
but the remaining nine paths still emitted text. A bounded prompt-only retry
then stopped those nine honestly as `no_source_action`, using 84,202 tokens and
making no candidate calls; it did not improve native-tool coverage.

The client now carries OpenAI-compatible required tool selection through
`extra_body` while preserving the DeepSeek thinking-off passthrough. For the
window scaffold, the hunter structurally requires `rank_source_windows` and
then `read_ranked_window` by name until one source read succeeds. Failed source
tools returned as either structured errors or `ERROR:` strings do not satisfy
coverage. A live generic and named-tool probe confirmed that the replacement
endpoint honors both request shapes. The proof-refinement profile retains one
bounded text-only retry as a fail-closed fallback.

The first structural replay recovered five more paths. It used 1,991,453
tokens and made 48 candidate calls; three concurrent hunters failed on
endpoint HTTP 500 responses and `vcr1.c` selected an invalid initial path. A
final four-path replay used named tool selection at concurrency one and
recovered all four remaining paths, using 1,277,622 tokens and 30 candidate
calls. The accepted primary and recovery artifacts therefore close source
coverage at 24/24 with 7,894,707 tokens over 872 model calls, 177
candidate/finding calls, 24 context compactions, and no formal findings.

Offline review promoted no new root cause. The strongest terminal ledger did
independently reconstruct the already-confirmed D3D12VA upload overflow in the
HEVC backend: the resource is sized from decoded-image geometry while every
accepted slice byte plus an inserted start code is copied without a capacity
check. The other terminal candidates resolved to concrete contracts. FITS can
store `NAXIS1` through `NAXIS999`, but its eight-byte keyword field cannot
represent `NAXIS1000` and the exact sequence check rejects the truncated key
before indexing past `naxisn[998]`. MLV's packet API allocates the requested
read size and handles short input, XBM's worst-case row and header bytes fit
its formula, and MicroDVD's style parser only accumulates a bounded bitmask.
H.264 prediction modes remain below the lookup-table bounds, FFV1 slice-count
products are explicitly capped, and codec-parameter extradata addition is
guarded below `INT32_MAX`.

The reviewed filter leads likewise stayed inside their allocations: ANLMDN's
`K`, `S`, `H`, and `N` relations cover every SSD neighbor; SITI performs no
gradient writes for sub-three-pixel dimensions; reverse grows each array
before indexing; ESTDIF clamps interpolation coordinates; and W3FDIF,
grayworld, select, colorspace, and swscale inherit negotiated plane geometry
and stride contracts. CNG's reflection coefficients can destabilize numeric
output but not the fixed synthesis buffers. The VCR1 side-data, FFV1 Vulkan,
movenc CENC, Argo ASF, and EATGQ candidates similarly lacked a producer that
violated the relevant allocation, packet-padding, or framework invariant.

Only after that adjudication was complete was the wave scored against its one
sealed survivor. The HEVC trajectory is a terminal-ledger hit on the existing
D3D12VA H.264/HEVC root, so effective recall is 1/1 from terminal ledgers and
0/1 from formal findings. Because this is the other duplicated backend for a
root already counted after ranks 781–804, totals remain 40 confirmed root
causes and 34 dynamically reproduced issues. Coverage is 828/4,995 (16.58%),
with 4,167 historically ranked files remaining. This machine enumerates 4,993
files, but directly slicing its deterministic order reproduces ranks 805–828
exactly.

The next unchanged exact-path manifest seals ranks 829–852 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_0829_0852.json` with SHA-256
`03fd69edb49c46053faf005d622eedd34036c29fef1d7f79f89f08d130869c82`.

### Blind wave 829–852 and libxevd packet-boundary read

The unchanged treatment completed all 24 exact-path trajectories with a
successful source-bearing action. It used 8,769,899 tokens over 889 model
calls, made 176 candidate/finding calls, performed 23 automatic context
compactions, and submitted one formal finding. Peak estimated context was
11,987 tokens and the largest individual input was 17,272 tokens.

The formal libxevd finding survives with a corrected sink. XEVD NAL length
prefixes are four bytes, not the two bytes stated in the hunter's prose, and
the claimed next-loop read is unreachable because an oversized `bs_read_pos`
makes the loop exit. The root invariant is nevertheless real:
`read_nal_unit_length` accepts `info.nalu_len` without comparing it with the
remaining packet, and the current iteration forwards that unchecked value as
`bitb.ssize` to `xevd_decode`.

An actual public FFmpeg decoder call with the eight packet bytes
`00 00 01 00 3a 00 05 64` declares a 256-byte NAL followed by a four-byte SEI
payload whose own payload size is 100. The packet allocation is exactly those
eight bytes plus FFmpeg's 64-byte padding. ASan reports a heap-buffer-overflow
read immediately beyond the complete 72-byte allocation through
`xevd_bsr_flush`, `xevd_bsr_read`, `xevd_eco_sei`, `xevd_dec_nalu`,
`libxevd_receive_frame`, and `avcodec_send_packet`. The pinned XEVD revision is
`0f066b3ea33834fe4e25b41c32c66f912f0b5d30`; the FFmpeg revision is
`795bccdaf57772b1803914dee2f32d52776518e2`. Durable artifacts are
`evaluations/ffmpeg_xevd_length_reproducer.c` and
`evaluations/run_ffmpeg_xevd_length_reproducer.py`.

The remaining terminal leads resolve to concrete contracts. High-bit-depth
H.264 doubles coefficient storage with the pixel width; HEVC transform blocks
are capped at 64; QSV's bounded writer stops advancing; FFV1 allocates every
65,536-entry encoder map; and CBS rejects bit reads beyond the unit. DXV checks
that both words of every eight-byte combination key remain, MMS advances its
pointer only while decrementing the same remaining length, and ordinary MP3
file offsets cannot approach signed overflow. Fax reference runs terminate at
the validated line width, while dictionary ownership flags require
`av_malloc`-compatible adopted values.

VAAPI tone-map metadata remains in the live filter context and procamp's enum
values match its four-entry capability array. YADIF uses one negotiated frame
geometry and per-plane allocation, AFIR returns before a nonpositive tail
copy, Media Foundation callers only read the returned diagnostic string,
MSRLE breaks before the allowed one-past pixel, and VVC validates the slice,
picture header, PPS, SPS, and their IDs before use. The reviewed D3D12 H.264
encoder, GIF decoder, and HDR encoder paths add no independent violated
memory or lifetime invariant.

Only after that adjudication closed was the wave compared with the sealed
survivor set. No sealed survivor falls in ranks 829–852, so libxevd is a novel
root rather than a rediscovery. The formal-finding novelty result is 1/1, with
the exact sink repaired offline. Current totals are 41 confirmed root causes
and 35 dynamically reproduced issues. Coverage is 852/4,995 (17.06%), with
4,143 historically ranked files remaining.

Directly slicing this machine's unchanged 4,993-file deterministic order
reproduces ranks 829–852 and their committed manifest exactly. The next
unchanged exact-path manifest seals ranks 853–876 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_0853_0876.json` with SHA-256
`19ad49230ad2664e5f09adf862eb7d5597c2d2c5e48a57801abd49483e31bc9a`.

### Blind wave 853–876 and readvitc zero-width pit group

The unchanged treatment completed all 24 exact-path trajectories with a
successful source-bearing action. It used 8,350,832 tokens over 862 model
calls, made 199 candidate/finding calls, performed 23 automatic context
compactions, and submitted no formal findings. There were no endpoint or
native-tool failures.

Offline review found one novel root in `vf_readvitc.c`, through a narrower
mechanism than its terminal ledger proposed. For negotiated widths one through
nine, `config_props` computes `grp_width = width * 5 / 48` as zero. On a 1x1
row the mutually ordered black and white threshold scans necessarily advance
`x` to `width`; the zero-width half-pit calculation does not step back. The
remaining-group check uses strict greater-than, so it accepts
`grp_start_pos + grp_width == width`, and `get_pit_avg3` reads `line[width]`
and `line[width + 1]`.

A public `buffer -> readvitc -> buffersink` graph with a valid refcounted 1x1
gray frame backed by an exact one-byte plane makes ASan report a one-byte
heap-buffer-overflow read immediately after that allocation. Ordinary FFmpeg
frames include row padding, which masks the allocation boundary without
making the out-of-range active-row access valid. Durable artifacts are
`evaluations/ffmpeg_readvitc_small_width_reproducer.c` and
`evaluations/run_ffmpeg_readvitc_small_width_reproducer.py`.

The other terminal leads resolve to concrete bounds. VP9 transform sizes are
encoded from zero through three, so its 96-byte edge scratch is exact even at
16-bit depth. The APV syntax layer derives minimum tile dimensions that cap
both tile-start arrays at 20 entries, QOI RGB input leaves alpha fixed at 255
and cannot emit an RGBA opcode, SMPTE 436M decodes its byte-sized ANC count
into an identically sized 255-byte payload, and HEVC SAO stores exactly the
five offsets indexed by its DSP. MM Video uses the checked bytestream getters,
TTA's signed 30-bit index size is either bounded or rejected by packet growth,
and TrueHD's rewritten header region remains algebraically inside `out_size`.

RoQ's eight-frame allocation and counter agree, CFHD alpha allocation and
processing use the same frame dimensions, VMAF Motion receives the actual
source linesize, and the texture DSP arguments are fixed wrapper constants.
VC-1 overlap helpers are called only with codec-owned padded blocks; AudioToolbox
inherits its supported codec and converter channel contract; and libdavs2
allocates from the external picture's own dimensions. The HDR10+ serializer's
fixed arrays are safe for structures produced by the validated T.35 parser;
out-of-range caller-constructed public structures are outside this media-input
root set. Likewise, expression NaN/Inf-to-integer conversion is configuration
UB without a demonstrated out-of-range access. The probetest utility, GIF
muxer, DNxHD decoder, speech normalizer, and remaining reviewed paths exposed
no violated allocation, progress, or lifetime invariant.

Only after adjudication closed was the wave compared with the sealed survivor
set. No prior survivor falls in ranks 853–876, so readvitc is a novel root.
Current totals are 42 confirmed root causes and 36 dynamically reproduced
issues. Coverage is 876/4,995 (17.54%), with 4,119 historically ranked files
remaining.

Directly slicing this machine's unchanged 4,993-file deterministic order
reproduces ranks 853–876 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 877–900 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_0877_0900.json` with SHA-256
`820bf185f4049c468b6fa0a8b43d015a0f90eb10afec1ee63ad427fa7d4427b0`.

### Blind wave 877–900 and four public-path audio roots

The unchanged treatment completed all 24 exact-path trajectories with a
successful source-bearing action. It used 9,532,624 tokens over 953 model
calls, made 191 candidate/finding calls, performed 30 automatic context
compactions, and submitted no formal findings. There were no endpoint,
reporting, or native-tool failures.

Offline review found four novel roots in three files. The hunter's proposed
RTP/AMR payload-overflow arithmetic was false, but `rtpenc_amr.c` has a simpler
public boundary failure: a zero-length AMR `AVPacket` reaches
`ff_rtp_send_amr`, which reads `buff[0]`, advances the pointer, decrements
`size` to -1, and passes that value to `memcpy`. A public RTP output context
with custom packet I/O makes ASan abort at the copy with
`negative-size-param`.

The proposed PCM-DVD group-size arithmetic was likewise false: each group
writes 12 bytes as intended. The independent root is the encoder's advertised
`AV_CODEC_CAP_SMALL_LAST_FRAME` contract. For interleaved S32 5.1 input,
`nb_samples=1` supplies six samples, while division by the four-sample block
size makes `blocks` zero. The `do ... while` still enters and attempts the
complete six-group, 24-sample block. An exact 24-byte input frame makes ASan
report a four-byte read immediately beyond the allocation. The durable ASan
build disables optimization and the forced-inline attribute without changing
source, preserving C argument evaluation that an optimized undefined path can
otherwise transform into a nonterminating loop.

`af_chorus.c` contains two distinct configuration roots. A modulation speed
above the negotiated sample rate truncates `length[n]` to zero; processing one
sample then reads the empty lookup table at index zero. Separately, the option
list count check combines mismatches with `&&`, so two delays, two decays, one
speed, and two depths are accepted before output configuration reads
`speeds[1]`. Public `abuffer -> chorus -> abuffersink` graphs reproduce both
four-byte heap-buffer-overflow reads under ASan.

The durable artifacts are
`evaluations/ffmpeg_rtp_amr_zero_length_reproducer.c`,
`evaluations/run_ffmpeg_rtp_amr_zero_length_reproducer.py`,
`evaluations/ffmpeg_pcm_dvd_small_last_frame_reproducer.c`,
`evaluations/run_ffmpeg_pcm_dvd_small_last_frame_reproducer.py`,
`evaluations/ffmpeg_chorus_speed_reproducer.c`,
`evaluations/run_ffmpeg_chorus_speed_reproducer.py`,
`evaluations/ffmpeg_chorus_mismatched_lists_reproducer.c`, and
`evaluations/run_ffmpeg_chorus_mismatched_lists_reproducer.py`.

The other terminal leads resolve to concrete contracts. Decoder `get_buffer2`
alignment physically covers H.274's partial 8x8 processing. JPEG2000 dimensions,
DSS combinatorial indices, HTML subtitle scanning, AMR depacketization, XWMA,
bprint, cellauto, XFace, libxavs2, QSV, KGV1, PNM, CAVS block allocation, HEVC
profile validation, BRSTM, and WMA remain within their validated allocation or
producer bounds. Broader reviews of AVUI, avectorscope, and sinc found no
independent violated memory-safety invariant.

Only after adjudication and all four public-path reproductions completed was
the wave compared with the sealed survivor set. None of the three files had a
prior survivor, so the four roots are novel rather than rediscoveries. Current
totals are 46 confirmed root causes and 40 dynamically reproduced issues.
Coverage is 900/4,995 (18.02%), with 4,095 historically ranked files
remaining.

Directly slicing this machine's unchanged 4,993-file deterministic order
reproduces ranks 877–900 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 901–924 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_0901_0924.json` with SHA-256
`9d283f5847e43c2534c816a607bbf19065d43d1027c3e6d13025d76af41dfa0b`.

### Blind wave 901–924 and three public-path roots

The unchanged treatment completed all 24 exact-path trajectories with a
successful source-bearing action. It used 8,961,555 tokens over 905 model
calls, made 166 candidate/finding calls, performed 26 automatic context
compactions, and submitted no formal findings. There were no endpoint,
reporting, or native-tool failures.

Offline review found three novel roots. `libmodplug.c` documents `max_size=0`
as disabling the input-size limit, and its known-size branch consequently
leaves a positive file size unclamped. Allocation still uses `av_malloc(0)`,
however, before `avio_read` copies the positive known size into that minimum
backing allocation. A public custom AVIO input reporting 4,096 bytes makes ASan
report a 4,096-byte heap-buffer-overflow write immediately after the
allocator's one-byte region.

`vf_kerndeint.c` accepts a 1x1 YUV420P frame despite assuming a second source
row. With default `order=0`, the filter advances the luma source pointer to
nonexistent row one before its first unconditional field-copy `memcpy`. A
public `buffer -> kerndeint -> buffersink` graph with exact one-byte planes
makes ASan report a one-byte heap-buffer-overflow read immediately after the
luma allocation.

`scd.c` accepts the file-supplied PCM channel count zero because it rejects only
values above eight. This derives `block_align=0`; the zero-byte `av_get_packet`
succeeds, and timestamp calculation then divides by the zero channel count. A
complete public custom-AVIO SCD input reaches the expression through
`av_read_frame`, where UBSan reports division by zero and aborts.

The durable artifacts are
`evaluations/ffmpeg_libmodplug_zero_limit_reproducer.c`,
`evaluations/run_ffmpeg_libmodplug_zero_limit_reproducer.py`,
`evaluations/ffmpeg_kerndeint_small_height_reproducer.c`,
`evaluations/run_ffmpeg_kerndeint_small_height_reproducer.py`,
`evaluations/ffmpeg_scd_zero_channels_reproducer.c`, and
`evaluations/run_ffmpeg_scd_zero_channels_reproducer.py`.

The proposed VP9 superframe unsigned-sum wrap is false. `init_get_bits8`
rejects every constituent packet above `INT_MAX / 8`, and at most seven packets
can be merged, so their total cannot wrap a 32-bit unsigned accumulator. SBC,
MSRLE, XWD, VAAPI H.264/H.265, BMV, Midivid, fade, DeckLink, MIPS DSP,
mcompand, nlmeans Vulkan, SIFF, EXR, Sierpinski, dblur, and 8SVX likewise close
under their concrete allocation, format, stride, padding, or public-API
contracts.

Only after adjudication and all three public-path reproductions completed was
the wave compared with the sealed survivor set. None of the three files had a
prior survivor, so all three roots are novel rather than rediscoveries. Current
totals are 49 confirmed root causes and 43 dynamically reproduced issues.
Coverage is 924/4,995 (18.50%), with 4,071 historically ranked files
remaining.

Directly slicing this machine's unchanged deterministic order reproduces ranks
901–924 and their committed manifest and SHA-256 exactly. The next unchanged
exact-path manifest seals ranks 925–948 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_0925_0948.json` with SHA-256
`884569b529ad1cf5840d18c9123ad6ba51f5e8c962b13bde3c4039f9f0bbd163`.

### Blind wave 925–948 and two architecture-gated roots

The initial sealed run examined all 24 paths but an inference-endpoint outage
left `libavfilter/af_channelmap.c` without a completed source-bearing action. A
deterministic sparse replay of rank 933 completed that path. Together the run
and replay used 8,259,953 tokens over 854 model calls, made 170
candidate/finding calls, performed 24 automatic context compactions, and
submitted no formal findings. All 24 exact-path trajectories therefore ended
with a successful source-bearing action.

Offline review found two novel architecture-gated roots. The little-endian PPC
VSX `hyscale_fast_vsx` implementation handles every destination width in
16-pixel iterations. A public two-byte GRAY8 row scaled to three pixels with
`SWS_FAST_BILINEAR` selects that implementation on VSX, and the first iteration
loads source offsets 0–15 and 1–16 before repairing its tail. The public
`sws_scale` producer places its exact two-byte row before a guard page and
proves that the geometry is accepted. The arm64 host does not execute VSX, so
the 15-byte overread is source- and producer-confirmed rather than dynamically
reproduced.

The VDPAU HEVC backend contains an independent instance of the previously
observed hardware-RPS capacity failure. The official `VdpPictureInfoHEVC`
layout gives `RefPicSetStCurrBefore`, `RefPicSetStCurrAfter`, and
`RefPicSetLtCurr` eight entries each. FFmpeg permits more than eight live
references in an individual RPS list. VDPAU clamps the three `NumPoc*` fields
to eight but then iterates the original `h->rps[*].nb_refs` values while
writing the arrays. Nine resolved surfaces therefore write index eight. The
same producer invariant is explicitly checked by NVDEC, confirming the
missing backend guard. With no VDPAU runtime on this machine, this root is
retained at root-cause-explained evidence.

The durable VSX artifacts are
`evaluations/ffmpeg_swscale_vsx_tight_row_producer.c` and
`evaluations/run_ffmpeg_swscale_vsx_tight_row_proof.py`. Its ignored proof
record is
`results/sourcehunt-optimization/swscale-vsx-tight-row-proof.json`.

The remaining terminal leads close under concrete contracts. Unchecked
bytestream helpers were called only after length checks; refstruct pool
callbacks remain stable; motion-estimation coefficient indices stay within
0–63; D3D12 scaling descriptors are validated by the driver API; DV audio
writes fit the profile-owned layout; GXF, SGI RLE, AudioToolbox, and textutils
operations are length-bounded; and the integer swscale wrapper advances by the
exact block element count. Mimic rejects resolution changes before ring
backreferences. OpenCL convolution matrices are restricted to 9, 25, or 49
entries. AIC and DXV allocations cover their worst cases. MIPS and LoongArch
DSP paths consume codec-owned padded frames or scratch rows. libcdio supplies a
lead-out TOC sentinel, and SAP's SDP builders use size-bounded appends into the
remaining announcement buffer.

Neither file had a prior survivor entry, so both roots are novel.
Current totals are 51 confirmed root causes and 43 dynamically reproduced
issues. Coverage is 948/4,995 (18.98%), with 4,047 historically ranked files
remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 925–948 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 949–972 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_0949_0972.json` with SHA-256
`0947447d4440ec963531bb70c4a16f676c514fec9a8f081d0e904ac4b1296bae`.

### Blind wave 949–972 and three public-configuration roots

The sealed run completed all 24 exact-path trajectories with a successful
source-bearing action. It used 7,195,478 tokens over 795 model calls, made 167
candidate/finding calls, performed 28 automatic context compactions, and
produced zero accepted formal findings. The replacement inference endpoint
remained healthy for the complete run.

Offline review found three novel roots. The ARLS filter accepts orders that are
not multiples of 16, rounds the selected order up for its kernel allocation,
and initializes the coefficient offset from that aligned size. The sample path
then calculates the copy source using the original order. With public
`order=17`, the kernel size is 32 and the initial offset is 31, so the first
17-float copy begins at coefficient index -14. A public two-input
`abuffer -> arls -> abuffersink` graph processing one sample makes ASan report
a 68-byte heap-buffer-overflow read beginning 56 bytes before the coefficient
allocation.

The concat filter's ordinary activation path preserves complete
`nb_outputs`-sized segment groups, but its public `next` command bypasses the
end-of-input check. In a one-segment graph, the first command reads the valid
input state and advances `cur_idx` to `nb_inputs`. A second command calls
`find_next_delta_ts` again and reads `cat->in[nb_inputs]`. A public
`abuffer -> concat -> abuffersink` graph issuing two
`avfilter_graph_send_command` calls makes ASan report an eight-byte
heap-buffer-overflow read immediately after the 24-byte input-state
allocation.

The OpenCL tonemap filter accepts every integer through `INT_MAX` for its
public `transfer` option, although its initializer permits only BT.709 or
BT.2020-10 output transfer characteristics. A supplied value is copied to the
output frame and `trc_out` before initialization. A valid OpenCL P010 HDR frame
with `transfer=100` therefore reaches an always-enabled `av_assert0` and calls
`abort` instead of returning an unsupported-option error. The sealed build on
this host has OpenCL disabled, so this configuration-triggered denial of
service is retained at root-cause-explained evidence rather than dynamically
reproduced.

The durable dynamic artifacts are
`evaluations/ffmpeg_arls_unaligned_order_reproducer.c`,
`evaluations/run_ffmpeg_arls_unaligned_order_reproducer.py`,
`evaluations/ffmpeg_concat_repeated_next_reproducer.c`, and
`evaluations/run_ffmpeg_concat_repeated_next_reproducer.py`. Their ignored
proof records are
`results/sourcehunt-optimization/arls-unaligned-order-reproducer.json` and
`results/sourcehunt-optimization/concat-repeated-next-reproducer.json`; both
record `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2`.

The remaining terminal leads close under concrete contracts. Crossfeed's
consumed frames and side buffers have the exact configured block size. The
softfloat interpolation tables intentionally include the extra endpoint, and
the square-root callers preserve normalized positive mantissas. RTP VC2HQ
checks each fragment span and sizes its final packet from the dynamic buffer.
Texture DSP consumes valid frame strides. Raw packet allocation rejects sizes
that would collide with packet padding. XSUB converts the suspected negative
bit-writer capacity to a zero-capacity writer and returns
`AVERROR_BUFFER_TOO_SMALL`. FIFO callbacks receive a documented maximum and
all in-tree callbacks honor it. RPZA's four-color branch guarantees a nonzero
selected component range. YOP's pending low nibble and source pointer checks
prevent a second tag read past the packet. PNM's image-size allocation already
includes every float plane. JPEG XS reads from the full padded parser packet;
its wrong CDT start pointer causes semantic misparsing rather than an
allocation overread. CBS SEI allocations, AMF buffers, MPC8 parsing, URL
helpers, Vulkan specialization lists, logging, sample-format copies, pixel
descriptors, and the remaining codec/DSP paths likewise remain within their
producer, allocation, or public-API contracts.

None of the three files had a prior survivor entry, so all three roots are
novel. Current totals are 54 confirmed root causes and 45 dynamically
reproduced issues. Coverage is 972/4,995 (19.46%), with 4,023 historically
ranked files remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 949–972 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 973–996 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_0973_0996.json` with SHA-256
`e3c114a57a72045d56d9eb100e81c7769714e4258f6af2c0df353102f4211937`.

### Post-hoc confirmation of the H.264 slice-sentinel survivor

After the H.264 slice-sentinel root had already been discovered and sealed, an
operator supplied independent repair evidence. The repair rejects
`current_slice >= 0xFFFE` before incrementing the wider counter, confirming the
exact collision boundary with the `uint16_t` table's `0xFFFF` sentinel. The
additional trace confirms that each picture re-poisons the spare table column,
that the false top-left match is gated through `deblocking_filter == 2`, and
that the resulting `top_borders[...][mb_x - 1]` pointer reaches luma and chroma
`XCHG` writes at `mb_x == 0`. This post-hoc material was not supplied to any
blind trajectory, ranking pass, or inference prompt.

### Blind wave 973–996 and invariant-heavy closures

The sealed run completed all 24 exact-path trajectories with a successful
source-bearing action. It used 8,149,017 tokens over 891 model calls, made 224
candidate/finding calls, performed 26 automatic context compactions, and
produced zero accepted formal findings. The replacement inference endpoint
completed the run without reporting failures.

Offline review found no new confirmed root cause. The strongest table-index
lead was in the ELS arithmetic decoder. A sanitizer-instrumented state probe
confirmed that `ctx->j` can finish a decode call negative, reaching -17, but
the source transition graph closes the apparent underflow: the only rungs with
`ALps == -108` are 171 and 172, neither has an incoming transition, and the
sole G2M/ePIC caller zero-initializes every rung. The reachable graph stopped at
rung 170 in the targeted probe, so a negative `j` cannot combine with either
dangerous table offset.

The other terminal leads also close under concrete allocation or producer
contracts. RPZA's rounded final 4x4 blocks are backed by the codec-specific
four-pixel width and height alignment required by `avcodec_align_dimensions2`.
RTP/JPEG marker lookahead remains inside packet padding, while its variable
table payloads have explicit segment-span checks. VMNC cursor storage is exactly
`cur_w * cur_h * bpp` and both screen copies clamp the visible rectangle before
using frame linesizes. VAAPI H.264 rejects a full DPB before appending; NVDEC
plane geometry follows the mapped CUDA frame and its HEVC path already enforces
the hardware RPS capacities. TMV's packet consumption, font index, and frame
writes match their exact dimensions. ASV tables, BlockDSP callers, compand's
delay ring, IAMF OBU spans, quirc image storage, kvazaar chunks, packet side
data, fixed AAC scaling, and the remaining codec/filter paths likewise retain
their table, stride, allocation, library, or public-API invariants. The packet
side-data aliasing theory requires caller ownership misuse, and an OpenCL kernel
argument mismatch returns `CL_INVALID_ARG_INDEX` rather than writing through an
invalid argument slot.

No survivor entry was added. Current totals remain 54 confirmed root causes and
45 dynamically reproduced issues. Coverage is 996/4,995 (19.94%), with 3,999
historically ranked files remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 973–996 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 997–1020 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_0997_1020.json` with SHA-256
`80ee549f21a8845b0c65c8b2b5647b463554e2b3afb148d9903c5d3f0ec9199f`.

### Blind wave 997–1020 and an empty hardware-encoder flush crash

The sealed run completed all 24 exact-path trajectories with a successful
source-bearing action. It used 7,847,498 tokens over 865 model calls, made 186
candidate/finding calls, performed 25 automatic context compactions, and
produced zero accepted formal findings. The replacement inference endpoint
completed the run without reporting failures.

Offline review found one novel root in the shared VAAPI/D3D12 encoder state
machine. The public `avcodec_send_frame(ctx, NULL)` API explicitly permits an
empty-stream flush. Generic encoding marks the context as draining and
immediately enters the hardware receive callback. `ff_encode_get_frame` returns
EOF, the callback converts that status into `frame == NULL`, and it calls
`hw_base_encode_send_frame` before checking whether `pic_start` is empty. With
no submitted frames, `input_order == decode_delay == 0` and `pic_end == NULL`;
the timestamp-repair condition therefore succeeds and reads `pic_end->pts`.
A sanitizer-instrumented direct production-function harness reports UBSan null
member access at `hw_base_encode.c:508`, followed by an ASan SEGV at address
offset `0x28` from NULL.

The durable artifacts are
`evaluations/ffmpeg_hw_base_encode_empty_flush_reproducer.c` and
`evaluations/run_ffmpeg_hw_base_encode_empty_flush_reproducer.py`. The ignored
proof record is
`results/sourcehunt-optimization/hw-base-encode-empty-flush-reproducer.json`;
it records `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2`.

The remaining terminal leads close under concrete contracts. An exhaustive
calculation across every MetaSound mode and period coefficient confirms that
`add_peak` consumes exactly the shape length and that its largest speech index
remains inside the mode-sized output (the tightest 512-sample modes stop at
index 509). Dirac's speculative two-byte refill remains inside the padded
parser packet, and its overread state supplies the format-required one bits.
YUV4's odd final row and column land in decoder-owned aligned padding, while
its input-size arithmetic is bounded by the image-size validator. Indeo, RL,
and Photo CD arrays share their exact producer counts; HEVC motion-vector
indices share the allocation's minimum-PU geometry. OpenCL remap uses image
objects rather than raw unchecked pointers. A64 palette values are fixed,
strictly increasing, and cover the complete dither range. Framequeue sample
metadata, swscale slices, JACK buffers, vvenc access units, ZMQ command replies,
MV stream indices, RIFF header fields, telecine frames, graph2dot formats, and
the remaining encoder/filter paths likewise close under their allocation,
external-library, metadata-only, or public-API producer invariants.

The hardware encoder file had no prior survivor entry, so the root is novel.
Current totals are 55 confirmed root causes and 46 dynamically reproduced
issues. Coverage is 1,020/4,995 (20.42%), with 3,975 historically ranked files
remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 997–1020 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 1021–1044 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1021_1044.json` with SHA-256
`0cbb26440c0d20c9cf16978679ce45e5afb32bb518a6f1dec7a526bc7bc95fd4`.

### Blind wave 1021–1044 and a CamStudio stale-heap disclosure

The sealed run completed all 24 exact-path trajectories with a successful
source-bearing action. It used 7,919,824 tokens over 865 model calls, made 181
candidate/finding calls, performed 25 automatic context compactions, and
produced zero accepted formal findings. The replacement inference endpoint
completed the run without reporting failures.

Offline review confirmed one novel root in the CamStudio decoder. For widths
not divisible by four, its compatibility calculation permits a decompressed
length shorter than the decoder's aligned buffer. The output copy nevertheless
uses the visible row length and aligned source stride. A public 5x1 BGR24
context therefore allocates a 16-byte decompression row and computes
`bugdelta == 4`; a valid zlib keyframe that expands to 12 bytes passes the
exception but `copy_frame_default` publishes 15 bytes. The three additional
pixel bytes come from the untouched heap allocation. An ASan allocator-fill
proof deterministically returns three `0xA5` bytes in the decoded AVFrame. The
trajectory rejected an initial false LZO-overflow theory and then isolated this
short-output mechanism, but did not promote it through the formal proof gate.

The durable artifacts are
`evaluations/ffmpeg_cscd_short_output_disclosure_reproducer.c` and
`evaluations/run_ffmpeg_cscd_short_output_disclosure_reproducer.py`. The
ignored proof record is
`results/sourcehunt-optimization/cscd-short-output-disclosure-reproducer.json`;
it records `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2`.

The remaining terminal leads close under concrete contracts. NotchLC's
16-bit delta and ring cursor keep both history indices in the 64 KiB window,
and the cursor resets on the exact byte that reaches the boundary. VVC caps
both overridden and default active-reference counts at 15, matching its weight
arrays. FLAC constrains LPC order to the current residual partition, which is
no larger than the validated block size. H.264 verifies the complete intra-PCM
bit count after validating chroma format and bit depth. MPEG-4 AC buffers share
the validated macroblock geometry, while MPEG audio's synthesis offset remains
a multiple of 32 with a maximum of 480, making its 1024-element wrap copy
exact. VAAPI VP8's frame-header check implies the hardware header subtraction
cannot underflow. ProRes RAW invokes the Vulkan slice callback exactly once per
allocated tile, and HEVC validates the active SPS identifier before storing it.
The MIPS DSP paths consume fixed codec blocks backed by padded frames. Pulse
rejects reads larger than the packet remainder; libplacebo creates exactly one
filter pad and one private input object per configured input; and APNG chunk
spans remain inside the validated packet. AMF extradata comes from the
external encoder's small SPS/PPS buffer. Hash, file-open, CAVS, RoQ, CSCD's
bounded decompressor writes, and the remaining filter/codec paths likewise
retain their API, array, allocation, or producer invariants.

The already-confirmed PCM-DVD short-final-frame root appeared in this rank
window, but its trajectory terminated as a degenerate loop after 28 source
steps without generating a candidate. This is retained as optimization
evidence and does not add a duplicate survivor.

The CamStudio file had no prior survivor entry, so the root is novel. Current
totals are 56 confirmed root causes and 47 dynamically reproduced issues.
Coverage is 1,044/4,995 (20.90%), with 3,951 historically ranked files
remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 1021–1044 and their committed manifest and SHA-256 exactly.
The next unchanged exact-path manifest seals ranks 1045–1068 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1045_1068.json` with SHA-256
`606cd6d6abf898b363bf813a88c1417f8b60b67669d66352f29efde1db6a9f44`.

### Blind wave 1045–1068 and producer-contract closures

The sealed run completed all 24 exact-path trajectories with a successful
source-bearing action. It used 7,214,185 tokens over 787 model calls, made 148
candidate/finding calls, performed 19 automatic context compactions, and
produced zero accepted formal findings. The replacement inference endpoint
completed the run without reporting failures.

Offline review found no new confirmed root cause. The most concrete apparent
overflow was in the shared Huffman length generator, but its `h`, `up`, `map`,
and `len` arrays are views into one deliberately oversized allocation. The
bytes remaining from `len` cover its maximum internal-node index
`2 * size - 2`, and the corresponding `up` indices remain below the separately
reserved `2 * stats_size` entries. MSRLE's 4-bit raw-row theory also closes
arithmetically: its padded stride is `ceil(width / 8) * 4`, which is always at
least the `ceil(width / 2)` bytes read by the nibble loop. CPiA checks each
destination pointer at the top of every compressed-token iteration, so a large
skip can move a cursor beyond the row but cannot be followed by a write.

The other terminal leads close under producer and allocation contracts.
Rawvideo's image-size validator bounds the bitpacked and v210 products before
their `int` packet sizes are calculated. GEQ uses overflow-checking allocation
for the exact subsampled plane dimensions. Colormap accepts only positive
image-size options and caps both its map count and Gaussian workspace at 64.
CUDA scaling receives valid frame cropping metadata and samples through bounded
texture resources; MediaCodec's JNI capacity is the direct buffer's actual
backing capacity. VapourSynth asserts the external frame geometry, and the
framerate SAD inputs are complete frames from the same negotiated link.
TwinVQ's fixed mode, period, and shape domains keep its rounding table and peak
writes in range. MxPEG's two 16-bit macroblock dimensions cannot overflow their
unsigned product, and its packet-span check rejects an unavailable bitmask.
The robust MPEG-audio RTP splitter advances only by a header plus an ADU already
shown to fit the remaining buffer. DASH templates use fixed format patterns and
bounded `snprintf`; AIFF chunk sizes remain in `int64_t` and AVIO bounds reads;
and the mux path's suspicious NULL-data cases violate the public AVPacket
contract rather than arise from accepted media. Back-reference copies, vflip,
ANM, IMM5, OpenCL overlay, AES, NLMeans, the MIPS IDCT, and the remaining paths
likewise retain their source, destination, library, or frame-allocation
invariants.

No survivor entry was added. Current totals remain 56 confirmed root causes and
47 dynamically reproduced issues. Coverage is 1,068/4,995 (21.38%), with 3,927
historically ranked files remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 1045–1068 and their committed manifest and SHA-256 exactly.
The next unchanged exact-path manifest seals ranks 1069–1092 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1069_1092.json` with SHA-256
`99ba2473feae3eea95b4b0468a6dba13d5e4fb3f1b7e67855b3e638bb04afbc3`.

### Blind wave 1069–1092 and an IAMF FLAC extradata overflow

The sealed run completed all 24 exact-path trajectories with a successful
source-bearing action. It used 6,749,450 tokens over 752 model calls, made 160
candidate/finding calls, performed 21 automatic context compactions, and
produced zero accepted formal findings. The replacement inference endpoint
completed the run without reporting failures.

Offline review confirmed one novel root in the IAMF muxer's FLAC
codec-configuration rewrite. Both initial stream extradata and packet-supplied
replacement extradata are duplicated with exact-sized `av_memdup` allocations,
which discard the public input buffer's required padding. No FLAC minimum-size
guard precedes `update_extradata`; that function parses through an optimized bit
reader and then unconditionally copies a 13-byte rewrite back into the duplicate.
A production-function proof supplies a correctly padded public 12-byte codec
configuration. `fill_codec_config` creates an exact 12-byte duplicate, and ASan
reports a four-byte heap-buffer-overflow read beginning one byte beyond that
allocation in `get_bits`, with `av_memdup` in the allocation trace. Without
sanitizer termination, the subsequent 13-byte copy also exceeds the allocation
by one byte. A later public FFmpeg repair independently confirms the root by
replacing both exact-sized duplicates with overflow-checked padded allocations.

The durable artifacts are
`evaluations/ffmpeg_iamf_flac_short_extradata_reproducer.c` and
`evaluations/run_ffmpeg_iamf_flac_short_extradata_reproducer.py`. The ignored
proof record is
`results/sourcehunt-optimization/iamf-flac-short-extradata-reproducer.json`; it
records `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2`.

The remaining terminal leads close under concrete contracts. Xiph RTP enters
its unfragmented raw buffering path only when the complete frame is no larger
than `max_pkt_size`; larger packets take the bounded fragment loop. Indeo 2 run
codes may advance the inter-row cursor beyond width, but the loop exits before
any access and resets the cursor on the next row. Rotate's four-byte temporary
matches the maximum pixel step of its explicit format list, and both packed and
planar overlay loops clamp the source and destination intervals. APV bounds
each component by the remaining tile size and rechecks the complete bit span;
H.261 rejects every scan index at 64; VMDAudio's chunk equation produces exactly
one output block; and PCX validates the complete packed or planar scanline.

The other candidates likewise close under producer, allocation, or API
invariants. ALSA's reordered multi-channel frame size keeps the power-of-two
growth below signed overflow. AAX retains a nonempty zero-initialized segment
array and bounds each transition. OpenHarmony copies the minimum of packet size
and framework-reported buffer capacity. MSS arithmetic models retain their
cumulative-probability and palette domains. libjxl consumes valid AVFrame
geometry; OCIO slices come from the bounded filter scheduler; QSV geometry is
validated by the hardware API; and format negotiation, gradients, vibrance,
ICO reads, libsrt options, and the remaining filter/codec paths stay within
their frame, library, or public-API contracts.

The IAMF writer had no prior survivor entry, so the root is novel. Current
totals are 57 confirmed root causes and 48 dynamically reproduced issues.
Coverage is 1,092/4,995 (21.86%), with 3,903 historically ranked files
remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 1069–1092 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 1093–1116 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1093_1116.json` with SHA-256
`bfba488d4b1e361f292be4ea5ba086a63d3ce265298f5e04a08fe3874fb01da2`.

### Blind wave 1093–1116 and a blurdetect chroma heap overflow

The sealed campaign covers all 24 exact paths. Ten already-terminal
trajectories were reused from the first retry, and exactly 14 unfinished paths
were replayed to completion in
`results/sourcehunt-optimization/ffmpeg-blind-campaign-ranks-1093-1116-retry2/`
under session `blind-pinned-files-n0014-8da0f664`. The replay used 4,851,743
tokens over 542 model calls, made 140 candidate/finding calls, performed 21
automatic context compactions, and had no failed settlements or accepted formal
findings. Combined with the reused trajectories, the complete wave used
7,810,929 tokens over 863 calls, made 214 candidate/finding calls, and performed
31 compactions. The replacement inference endpoint completed the replay without
reporting failures.

Offline review confirmed one novel root in `vf_blurdetect`. Its shared float
block-score array is allocated from floor-divided full-resolution geometry, but
each selected plane independently ceil-subsamples both the plane and configured
block dimensions. For a 19x19 YUV420P frame with 10x10 blocks, the allocation
contains one float while the 10x10 chroma plane is processed as four 5x5 blocks.
Edge-bearing chroma therefore appends scores past the allocation through the
unchecked `blks[blkcnt]` write. Running the production filter under ASan reports
a four-byte heap-buffer-overflow write immediately after the four-byte
allocation. The blind trajectory found the allocation/write pair but rejected
it after considering only full-resolution division; cross-plane refinement in
offline review exposed the reachable mismatched geometry.

The durable reproducer is
`evaluations/run_ffmpeg_blurdetect_chroma_blocks_reproducer.py`. The ignored
proof record is
`results/sourcehunt-optimization/blurdetect-chroma-blocks-reproducer.json`; it
records `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2`.

Review also extended the existing D3D12 upload-capacity survivor without adding
a duplicate root. The VC-1 backend performs unchecked start-code and slice
copies into the common raw-image-sized resource; later repair `1307db3d3c` adds
the exact missing remaining-capacity check. AV1 can accumulate partial tile
groups into a raw-image-sized heap buffer and then copy the completed frame into
the equally fixed D3D12 resource without bounding either operation. Later
repairs `a90fbb6bc9` and `e1ef95c779` independently add the slice-buffer and
frame-resource checks. These are codec-specific manifestations of the already
sealed H.264/HEVC capacity-policy root.

The remaining terminal leads close under concrete contracts. `vf_showinfo`'s
detection-box loop would require malformed public `AVFrame` side data; every
in-tree producer allocates the declared boxes, while the actual unchecked DNN
classification count is already represented by the existing classification
survivor. BRender's 16-bit width prevents row-width overflow and its later
division guard closes total-size overflow. JPEG2000 and VC-1 parser state bounds
close their apparent accesses. WBMP truncated frames use zero-initialized frame
pools; AASC always targets the full 1024-byte PAL8 palette; HAP offset and
allocation invariants hold; and RPL checks `nb_index_entries` before indexing.

The other candidates likewise close under producer, platform, or API contracts.
`audioconvert` channel maps require valid public indexes. Media Foundation
encoder buffers follow framework capacity contracts. Guided, dejudder, Vulkan,
SHA, SHA-512, LXF, OpenH264, BSF, and `sidxindex` leads retain their validated
frame, allocation, state, or library bounds.

Only the blurdetect file adds a new root. Current totals are 58 confirmed root
causes and 49 dynamically reproduced issues. Coverage is 1,116/4,995 (22.34%),
with 3,879 historically ranked files remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 1093–1116 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 1117–1140 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1117_1140.json` with SHA-256
`5ed7257f74c66a62b8faca10f25b9966993efa0c088cf41189dbe9d33076e243`.

### Blind wave 1117–1140 and two memory-safety roots

The sealed run completed all 24 exact-path trajectories with a successful
source-bearing action. It used 6,782,282 tokens over 768 model calls, made 169
candidate/finding calls, performed 29 automatic context compactions, and had no
model or tool failures. Its single formal finding was rejected offline. The
replacement inference endpoint completed the run without reported failures.

Offline review confirmed a dynamically reproduced root in the RTP/AAC
packetizer. When stream extradata is absent, `ff_rtp_send_aac` assumes a
seven-byte in-band ADTS header and subtracts seven without checking the packet
size. A one-byte public packet becomes size -6, satisfies the ordinary
single-packet branch, and reaches `memcpy` with that negative length. A direct
production-packetizer harness deterministically aborts under ASan with
`negative-size-param` in `ff_rtp_send_aac`. Later FFmpeg repair
`c77a16487a37ae450fa8ea5a94fd6488e40277b7` independently confirms the root by
adding the exact missing `size < 7` guard.

Review also confirmed a GPU out-of-bounds write in `overlay_cuda`. The host
rounds the main plane dimensions up to complete 32x16 CUDA blocks, but the
kernel receives no main width or height and clips threads only to the overlay
rectangle. A valid 32x18 NV12 main frame with a 32x32 overlay at the origin
therefore leaves rounded threads enabled through luma row 31 and chroma row 15.
With a normalized 32-byte pitch, the main allocation is 864 bytes while the
last luma and chroma writes reach offsets 1023 and 1087, overrunning it by 160
and 224 bytes respectively. Larger aligned CUDA pitches preserve and increase
the out-of-bounds relationship. No CUDA runtime was available locally, so this
root is source- and exact-geometry-confirmed rather than sanitizer-observed.

The durable artifacts are
`evaluations/ffmpeg_rtp_aac_short_adts_reproducer.c`,
`evaluations/run_ffmpeg_rtp_aac_short_adts_reproducer.py`, and
`evaluations/run_ffmpeg_overlay_cuda_grid_proof.py`. The ignored proof records
are
`results/sourcehunt-optimization/rtp-aac-short-adts-reproducer.json` and
`results/sourcehunt-optimization/overlay-cuda-grid-proof.json`; both record
`expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2`.

The formal Sun Raster finding is not a vulnerability: the extra trigger and
run reads remain inside the mandatory zeroed `AV_INPUT_BUFFER_PADDING_SIZE`
tail. Aura consumes exactly one row, DCA's oversized frame value only delays
marker acceptance, and SWF's zero denominator requires a malformed public time
base. H.261 and LATM reject their proposed negative sizes, while unsharp,
RIPEMD, PCM rechunk, FLAC picture, silence detection, GSM, and DV marker paths
retain their arithmetic and allocation bounds.

The remaining candidates close under producer or API contracts. CUDA transfer
would require a malformed caller-supplied `AVFrame`; KMS relies on trusted
kernel mapping metadata; transpose NPP receives already-validated hardware
frame dimensions; libwebp retains cloned or refcounted planes; and OpenCORE AMR
rejects the empty-packet theory before its decoder callback. Premultiply and
pseudocolor are bounded by negotiated plane geometry and the complete 65,536
entry LUT. Murmur3 retains only a possible hash-correctness edge case at
`state_pos == 16`, not a memory-safety issue.

The two files add distinct roots. Current totals are 60 confirmed root causes
and 50 dynamically reproduced issues. Coverage is 1,140/4,995 (22.82%), with
3,855 historically ranked files remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 1117–1140 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 1141–1164 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1141_1164.json` with SHA-256
`6807fee70ca54862a07d9bf371a8648ed7ca311a6583efd2357cfec1a06fa3f9`.

### Blind wave 1141–1164 and two sanitizer-confirmed overreads

The sealed run completed all 24 exact-path trajectories with a successful
source-bearing action. It used 6,995,869 tokens over 767 model calls, made 165
candidate/finding calls, performed 23 automatic context compactions, and
produced no formal findings. The replacement inference endpoint completed the
run without model or tool failures.

Offline review confirmed a configuration-gated CLLC overread. The decoder's
frame-level guard requires only one input bit per output pixel, but
attacker-defined one-bit ARGB VLC tables can make every pixel consume four
symbols. The pixel loops perform optimized cache loads without a remaining-bit
check. FFmpeg exposes `safe_bitstream_reader` as a configurable feature; in the
supported disabled configuration, codec callers must keep every unchecked load
inside the input and its padding. A public 64x64 ARGB decode with a 512-byte
packet passes the 4,096-bit guard exactly but consumes a 136-bit header plus
16,384 pixel bits. ASan reports a four-byte heap-buffer-overflow read beginning
exactly after the decoder's 644-byte padded swap allocation.

Review also confirmed a default-code-path overread in the `segment` filter. The
filter appends `INT64_MAX` as its final output sentinel, but `INT64_MAX` is a
valid `AVFrame` timestamp because only `INT64_MIN` is reserved as
`AV_NOPTS_VALUE`. A frame equal to the sentinel advances `current_point` across
both the configured split and the sentinel. The `while` condition then indexes
`points[nb_points]` before the post-loop bound check can run. A public one-pixel
buffer-to-segment graph with `timestamps=0` and pts `INT64_MAX`
deterministically makes ASan report an eight-byte heap-buffer-overflow read
exactly after the two-entry, 16-byte point allocation.

The durable artifacts are
`evaluations/ffmpeg_cllc_short_packet_reproducer.c`,
`evaluations/run_ffmpeg_cllc_short_packet_reproducer.py`,
`evaluations/ffmpeg_segment_max_pts_reproducer.c`, and
`evaluations/run_ffmpeg_segment_max_pts_reproducer.py`. The ignored proof
records are
`results/sourcehunt-optimization/cllc-short-packet-reproducer.json` and
`results/sourcehunt-optimization/segment-max-pts-reproducer.json`; both record
`expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2`.

The other terminal leads close under concrete invariants. TTA's decode buffer
matches the complete frame-length-by-channel loop, and FPS's frame count tracks
its populated two-slot queue. SheerVideo, VP8 DSP, and LoongArch VP9 DSP consume
validated frame strides and block storage. RLE's raw branch reserves both its
header and payload. LCEVC receives crop values repaired by the generic decoder,
and Ogg packet size remains bounded by its dynamically grown stream buffer.

The remaining arithmetic and API candidates also close. BGMC's algebra keeps
`delta` in zero through five; Microsoft Video 1 requires four-aligned
dimensions; DVB subtitle RLE's per-run costs stay inside its documented
worst-case line reservation; and H.264 QP and slice-offset domains fit the
padded deblocking tables. AviSynth geometry belongs to the loaded plugin
contract, subtitle style storage is dynamically grown and null-terminated, and
the PDV, C93/VOC, FITS, loop, MPEG-H, resolver, and format-option paths retain
their allocation, library, or immutable-index bounds.

The CLLC and segment files add distinct roots. Current totals are 62 confirmed
root causes and 52 dynamically reproduced issues. Coverage is 1,164/4,995
(23.30%), with 3,831 historically ranked files remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 1141–1164 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 1165–1188 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1165_1188.json` with SHA-256
`36e2ad7ac4bd3b845540da599e13e3bb11be36b0a6f78029ded6e1e62cf9bf61`.

### Blind wave 1165–1188 and nine dynamically confirmed roots

The sealed run completed all 24 exact-path trajectories with a successful
source-bearing action. It used 7,730,121 tokens over 834 model calls, made 221
candidate/finding calls, performed 25 automatic context compactions, and
produced no accepted formal findings. The replacement inference endpoint again
completed without model, tool, or reporting failures.

Offline review confirmed six independent TD-SC roots. Raw `WAR` tiles allocate
exactly the attacker-provided `tile_size` but copy `w * 3 * h` bytes; a 64x64
tile backed by four bytes produces a 192-byte ASan read exactly after the
allocation. Compressed tiles likewise trust the outer tile dimensions after
decoding an independently sized JPEG; a claimed 64x64 tile over a 1x1 JPEG
produces a one-byte ASan read immediately after the luma plane. Later repairs
`e9e6fb879835a4016b433ad2c4a224f62c686de3` and
`bb69a090a7cad34e21c645c8bcedbdd4ed92db5b` add the exact missing raw-size and
decoded-JPEG-dimension guards.

TD-SC's monochrome cursor loop advances by a complete aligned row and then
applies the row padding a second time. A valid 1x2 cursor writes its second
pixel exactly after a 256-byte allocation; later repair
`242ff799c75f20bade946314c8d741d0887ee11c` removes both redundant advances.
The tile-size check also counts the following 24-byte tile header as payload.
A 24-byte nominal raw tile containing only that header leaves its 24-byte heap
buffer untouched, and ASan allocator fill is copied verbatim into decoded
pixels. Repair `bf4eb194cfd35c65d523685d35168d7107394e9c` adds those 24 bytes to
the input bound.

Two state-transition bugs complete the TD-SC set. Resizing an existing 1x1
BGR24 reference frame to 256x32 without unreferencing it preserves a 96-byte
linesize, allocates only 3,328 bytes, and lets the pixel conversion write
through byte 3,743. ASan catches the first byte beyond the allocation; repair
`fd3ee52fab34d98a95b787d0b5ff45685766200c` clears the stale frame state before
reallocation. Separately, a cursor-only update accepts `INT_MAX` as its x
position and overflows `x + w` before clipping. UBSan reproduces the signed
overflow, while repair `8de8405796df0c11c52772dd14bf6ed552d25c07` moves an
unsigned frame-bound check ahead of the arithmetic.

The raw-RGB reshuffler adds a seventh memory-corruption root. AVI's public width
and bit-depth formula can produce a 1,431,655,768-byte row; multiplying by
three rows wraps the destination payload to eight bytes while all row offsets
and the padding length keep the large stride. With a 216-byte source packet,
ASan reports a 1,431,655,696-byte write beginning exactly after the eight-byte
payload and mandatory 64-byte packet padding. Later repair
`d3ad8a7fee6a647c6362e4a105d949282d50a98f` widens the intermediate and rejects
products that cannot fit an `AVPacket`.

Review also found two still-unfixed filter crashes. Varblur accepts 1x1 integer
planes, where every clamped horizontal and vertical span is zero; its
summed-area calculation divides by the zero span, and UBSan aborts in
`blur_plane8`. Atadenoise advertises four-plane alpha formats and accepts alpha
bit 8 in its public plane mask, but queue population stores only planes zero
through two. Selecting alpha therefore forms temporal pointers from null queue
entries. UBSan diagnoses the null-pointer arithmetic, execution continues into
the production `fweight_row8` callback, and ASan aborts on its zero-page read.

The durable artifacts are
`evaluations/ffmpeg_tdsc_war_short_tile_reproducer.c`,
`evaluations/run_ffmpeg_tdsc_war_short_tile_reproducer.py`,
`evaluations/ffmpeg_tdsc_additional_reproducers.c`,
`evaluations/run_ffmpeg_tdsc_additional_reproducers.py`,
`evaluations/ffmpeg_raw_rgb_stride_overflow_reproducer.c`,
`evaluations/run_ffmpeg_raw_rgb_stride_overflow_reproducer.py`,
`evaluations/ffmpeg_varblur_unit_geometry_reproducer.c`,
`evaluations/run_ffmpeg_varblur_unit_geometry_reproducer.py`,
`evaluations/ffmpeg_atadenoise_alpha_plane_reproducer.c`, and
`evaluations/run_ffmpeg_atadenoise_alpha_plane_reproducer.py`. Their ignored
proof records under `results/sourcehunt-optimization/` all record
`expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2`.

The XBM and V408 formal attempts do not survive adjudication. XBM's one- and
two-byte logical reads remain within the mandatory zeroed
`AV_INPUT_BUFFER_PADDING_SIZE` packet tail and then reject the input. V408's
apparent `4 * width * height` overflow is precluded by
`av_image_check_size2`, whose conservative eight-byte stride bound keeps the
product representable before decoder entry. The generic unchecked bitreader is
likewise an intentional configured contract rather than a standalone root;
the prior CLLC result is the concrete caller that violates it.

The remaining candidates close under producer or allocation invariants.
Speex sizes both header and encoded copies from the same library results; VP8
edge filters operate on padded decoder frames; SBC's bounded block/subband
state keeps its wrap buffer valid; and Sun Raster's doubled RLE allocation
covers the two-byte worst case. E-AC-3 exponent and channel domains fit their
tables, while Vulkan AV1 reference indices are syntax-bounded. Fieldorder and
hflip copy only active row bytes through valid frame linesizes; shear clamps
all sampled coordinates; VAAPI transpose swaps dimensions for every rotating
mode; and QR padding cannot be smaller than its rendered code. Removelogo,
freezedetect, Argo BRP, ISOM descriptors, swscale component tables, CYUV, and
the remaining codec paths retain their explicit geometry, descriptor, or
packet bounds.

The nine mechanisms add distinct roots. Current totals are 71 confirmed
root causes and 61 dynamically reproduced issues. Coverage is 1,188/4,995
(23.78%), with 3,807 historically ranked files remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 1165–1188 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 1189–1212 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1189_1212.json` with SHA-256
`265b487f7d8a3b7700933f210067d36767f8b8c4199c59965850004c7474c628`.

### Blind wave 1189–1212 and closed arithmetic candidates

The sealed run completed all 24 exact-path trajectories with a successful
source-bearing action. It used 7,567,837 tokens over 867 model calls, made 215
candidate/finding calls, performed 28 automatic context compactions, and
produced no accepted formal findings. The replacement inference endpoint again
completed without model, tool, or reporting failures.

Offline review found no additional security root. Speex's packet-duration
arithmetic is deliberately bounded to `INT32_MAX / 256`; even the maximum 255
Ogg packet segments produce 2,139,094,785, still below `INT32_MAX`. EVC's
16-bit NAL count can wrap after 65,536 same-type units, but the local count is
used identically for the reallocation size and write index, so the arrays remain
memory-safe and only the emitted configuration semantics are affected. H.266's
lone unchecked two-byte configuration read remains within required input
padding, while its subsequent byte reads and skips clamp at the logical end.
AV1 OBU size parsing likewise retains its bitreader and remaining-buffer bounds.

The arbitrary-integer helper has a genuine standalone edge behavior: passing
the most-negative 128-bit `AVInteger` directly to `av_mod_i` recurses because
two's-complement negation produces the same value. No untrusted production path
constructs that value. The old `av_rescale_rnd` big-integer branch is compiled
out, and AVI's reachable products occupy far fewer than 128 bits. Treat this as
a malformed public-API caller case rather than an FFmpeg input vulnerability.
The negative-shift index theory is also safe because both array reads are
guarded after unsigned conversion.

The remaining memory candidates close under exact allocation or API contracts.
QOI row offsets fit the validated image linesize; VC-1 and H.265/6 motion
compensation use padded decoder frames; LJPEG and Rockchip MPP receive encoder
frames matching the opened context; and monochrome's maximum chroma index is
exactly `ceil(width / 2^subsampling) - 1`. Threshold uses pixel counts in its
typed kernels, pad validates geometry before checking backing-buffer extents,
and Vulkan gblur allocates exactly the shader-visible kernel length. MQ flushes
at most three bytes into its four-byte pass buffer. ATSC A/53, frame CRC,
acrossfade, AC-4, Argo CVG, WTV, OpenCL source loading, and hardware-H.264 HRD
retain their buffer, producer, or option bounds.

Totals remain 71 confirmed root causes and 61 dynamically reproduced issues.
Coverage is 1,212/4,995 (24.26%), with 3,783 historically ranked files
remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 1189–1212 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 1213–1236 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1213_1236.json` with SHA-256
`a590597815ced85a491b5f6404b003682d6cefebc5fed84abafb80d6ee8be19b`.

### Blind wave 1213–1236 and six dynamically confirmed roots

The sealed run completed all 24 exact-path trajectories with a successful
source-bearing action. It used 6,318,573 tokens over 711 model calls, made 150
candidate/finding calls, performed 17 automatic context compactions, and
produced no accepted formal findings. The replacement inference endpoint again
completed without model or tool failures.

Offline review confirmed six independent roots. Libxavs advertises delay and
accepts a public flush before any frame, but its first zero-NAL result computes
DTS from PTS-ring indices -1 and -2. With three ring entries, ASan reports an
eight-byte read immediately before the allocation. The ASS muxer's
unparenthesized carriage-return/newline condition evaluates `p[-1]` after a
one-byte newline is removed; ASan reproduces the underflow, and later repair
`aa1f4ed774` adds exactly the missing parentheses.

The VC-2 HQ RTP packetizer validates a data-unit length only against its input
frame. A 200-byte sequence unit forwards 187 bytes into a fixed 64-byte payload
buffer, and ASan catches the write; repair `1afd5c3dda` adds the missing payload
capacity check. Sega FILM reads a packet-controlled 24-bit Cinepak size and uses
zero directly as a modulo divisor. A complete four-byte packet makes UBSan
abort at that expression.

Two information disclosures complete the set. RSCC gives zlib a 16-byte
full-frame capacity, accepts a valid stream that expands to four bytes, ignores
the returned length, and copies all 16 declared tile bytes. The production
decoder proof observes twelve stale markers in the returned frame; repair
`a5fe21a1a4` explicitly names the heap disclosure and zero-fills that tail. SBC
accepts a low-delay stereo configuration whose derived bitpool is 249 against a
maximum of 128. It allocates a 133-byte output, writes three header bytes,
ignores the packer's error, and publishes all 130 untouched tail bytes. Repair
`3540a6a308`, titled `Don't output uninitialized data`, moves the exact bitpool
check into initialization.

The durable artifacts are
`evaluations/ffmpeg_libxavs_empty_flush_reproducer.c`,
`evaluations/ffmpeg_libxavs_stub/xavs.h`,
`evaluations/run_ffmpeg_libxavs_empty_flush_reproducer.py`,
`evaluations/ffmpeg_assenc_newline_underflow_reproducer.c`,
`evaluations/run_ffmpeg_assenc_newline_underflow_reproducer.py`,
`evaluations/ffmpeg_rtp_vc2hq_payload_overflow_reproducer.c`,
`evaluations/run_ffmpeg_rtp_vc2hq_payload_overflow_reproducer.py`,
`evaluations/ffmpeg_segafilm_zero_cinepak_size_reproducer.c`,
`evaluations/run_ffmpeg_segafilm_zero_cinepak_size_reproducer.py`,
`evaluations/ffmpeg_rscc_short_deflate_disclosure_reproducer.c`,
`evaluations/run_ffmpeg_rscc_short_deflate_disclosure_reproducer.py`,
`evaluations/ffmpeg_sbc_invalid_bitpool_disclosure_reproducer.c`, and
`evaluations/run_ffmpeg_sbc_invalid_bitpool_disclosure_reproducer.py`. Their
ignored proof records under `results/sourcehunt-optimization/` all record
`expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2`.

Review also extended the existing D3D12 upload-capacity root to VP9. Its backend
copies the accepted frame into the same raw-image-sized upload resource without
a capacity check; later repair `3abec89a45` adds that exact comparison. This is
a codec-specific variant of the already recorded H.264, HEVC, VC-1, and AV1
mechanism, not a seventh root.

The remaining repair leads do not add survivors. H.264 parser repairs
`3c9ae91f19` and `b7e56970da` are later branch cherry-picks of original commits
`73681f888d` and `30a6b78bd4`, both already ancestors of the pinned snapshot.
The MPEG-4 DSP `ptrdiff_t` change in `7b05d16ce7` aligns its callback type with
the caller, while reachable frame linesizes still originate in the public
`int`-sized `AVFrame.linesize` domain. Neither is a pinned-source vulnerability.
The user-supplied H.264 slice-sentinel chain independently corroborates the
existing slice-counter survivor and is not counted again.

Other terminal candidates close under packet, producer, or platform contracts.
JPEG-LS, ARBC, MPEG-1/2, TAK, EVC, VP9 superframe, RFC 4175, and the filter
paths retain their validated size or frame-state bounds. FFplay, framebuffer,
hardware-map, and random-seed leads require trusted device/framework state or
have no memory-safety effect.

The six mechanisms raise the totals to 77 confirmed root causes and 67
dynamically reproduced issues. Coverage is 1,236/4,995 (24.74%), with 3,759
historically ranked files remaining.

Directly slicing this machine's unchanged 4,995-file deterministic order
reproduces ranks 1213–1236 and their committed manifest and SHA-256 exactly. The
next unchanged exact-path manifest seals ranks 1237–1260 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1237_1260.json` with SHA-256
`eba7617217a4b9ca6db6cca4007efc677d8f926821b69ea75be07e02fd995a96`.

### Blind wave 1237–1260 and four confirmed resource/memory roots

The wave completed all 24 exact-path trajectories across an interrupted initial
run and a 19-path retry. Five completed paths from the first run were preserved.
Together the runs used 7,924,804 tokens over 877 model calls, made 199
candidate/finding calls, performed 27 automatic context compactions, and
produced no accepted formal findings. One transport stall caused the split; the
replacement inference endpoint otherwise completed every remaining path.

Offline review confirmed a remotely reachable RTP/JPEG stack overwrite. A
start packet with `q=255` may carry 1,024 table bytes, which the parser converts
to sixteen quantization tables while building a JPEG header in
`uint8_t hdr[1024]`. Checked writes saturate at the end of `hdr`, but the raw
DHT-length backpatch then writes two bytes through the one-past-end pointer. The
complete production parser aborts under ASan. Later repair `d84bec2bd6` caps the input at
four 64-byte tables and names the out-of-array access.

HEVC CBS has a separate allocation-amplification root. Vulnerable
`H265RawVPS` embeds 1,024 HRD structures and occupies 7,924,248 bytes. CBS
allocates and zero-fills that entire structure before parsing each VPS and
retains one content object per unit. Sixteen valid 27-byte VPS NAL units turn a
432-byte packet into 126,787,968 content bytes through the production read
entry; 1,024 units project to 8,114,429,952 bytes from 27,648 input bytes.
Repair `d2dd0a0a8f`, tied to a ClusterFuzz OOM testcase, moves the HRD array to
an allocation sized by the parsed count.

Two denial-of-service roots complete the set. WinRT gfxcapture accepts crops
through `INT_MAX` and documents `width=-1` as a rounding control. For a
1,920-pixel capture with border capture enabled, `crop_left=1921` and
`crop_right=INT_MAX` form `cap_w=INT_MIN` without prior overflow; the rounding
branch then evaluates `INT_MIN / -1` before generic frame-geometry validation.
The exact arithmetic proof aborts under UBSan, while full filter execution
remains Windows-gated. Separately, a two-line ffconcat file can list itself as
its first entry. Production ffprobe recursively allocates format contexts and
opens descriptors until the process limit returns `EMFILE`; a 64-descriptor
proof records sixty recursive unwind failures. Later repair `597036b692` adds
a default generic demuxer recursion limit of ten and names `self_ref.ffconcat`.

The durable artifacts are
`evaluations/ffmpeg_rtp_jpeg_qtable_length_reproducer.c`,
`evaluations/run_ffmpeg_rtp_jpeg_qtable_length_reproducer.py`,
`evaluations/ffmpeg_cbs_h265_vps_allocation_amplification_reproducer.c`,
`evaluations/run_ffmpeg_cbs_h265_vps_allocation_amplification_reproducer.py`,
`evaluations/ffmpeg_gfxcapture_crop_division_overflow_reproducer.c`,
`evaluations/run_ffmpeg_gfxcapture_crop_division_overflow_reproducer.py`, and
`evaluations/run_ffmpeg_concat_self_reference_reproducer.py`. All four ignored
proof records report `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2`. RTP/JPEG, CBS, and concat execute
production paths; gfxcapture is retained as source-confirmed because its
production backend is Windows-only on this host.

The other terminal leads close under exact bounds or semantics. A valid AMR-WB
frame-header byte is nonzero, so mandatory zero padding stops the probe scan.
AAC's largest copied PCE is about 306 bytes against `MAX_PCE_SIZE=320`.
Swscale's signed-arithmetic repair preserves modulo color conversion without a
memory-safety effect. RTP/JPEG's cached-table `memcmp` is protected by
short-circuit evaluation; the independent header backpatch above is the real
root. The MPEG, H.264, VVC, frame, filter, and remaining codec candidates retain
their producer or geometry bounds. The user-supplied H.264 slice-table and
`top_borders[-1]` chain independently corroborates the existing slice-sentinel
survivor and is not counted again.

The four mechanisms raise the totals to 81 confirmed root causes and 70
dynamically reproduced issues. Coverage is 1,260/4,995 (25.23%), with 3,735
historically ranked files remaining.

Directly slicing the unchanged deterministic order reproduces ranks 1237–1260
and their committed manifest exactly. The next exact-path manifest seals ranks
1261–1284 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1261_1284.json` with SHA-256
`e9ba37500413ad54cbf3189e0e2ce1c386e3f103fb98437848337b628d306d50`.

### Blind wave 1261–1284 and the ADX channel-transition crash

The sealed run completed all 24 exact-path trajectories with successful source
work. It used 7,365,049 tokens, made 176 candidate/finding calls, and produced
no accepted formal findings. The replacement inference endpoint completed
without model or transport failures. RFC 4175 reached the repeated-action guard
at step 40 only after its source had already been examined.

Offline review confirmed one decoder root. Valid initial ADX extradata can set
the public and private decoder state to two channels. A packet-side
`AV_PKT_DATA_NEW_EXTRADATA` header can then change the public layout to one
channel, but the vulnerable branch updates only that layout, coefficients, and
EOF state. `ff_get_buffer` consequently allocates one planar S16 channel while
the stale `c->channels == 2` loop still calls `adx_decode` for `samples[1]`.
The 36-byte public decoder proof aborts under ASan on the resulting zero-page
write at `adxdec.c:232`. Later repair `c10e7f5dc1`, titled `sync decoder channel
state on NEW_EXTRADATA`, synchronizes the private count, marks the header parsed,
resets predictors when the count changes, and explicitly names the out-of-array
access.

The durable artifacts are
`evaluations/ffmpeg_adx_new_extradata_channel_reproducer.c` and
`evaluations/run_ffmpeg_adx_new_extradata_channel_reproducer.py`. The ignored
proof record reports `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2` and confirms every source and
runtime predicate through the production decoder object.

The remaining terminal candidates close under exact bounds or contracts.
`af_apsyclip` always derives 128 psychoacoustic bins and its fourteen allocated
rows match the generated spread sequence. AOM film grain accepts only 8-, 9-,
10-, or 12-bit frames, keeping its scaling table at or below 4,096 entries.
VAAPI drawbox passes invalid negative regions to the driver boundary rather than
indexing host memory, where the API is expected to reject them. Westwood VQA and
TX repairs found through broad all-history searches predate the pinned snapshot.
The other codec, filter, and platform leads retain their caller, format, frame,
allocation, or producer contracts. The user-supplied H.264 slice-table and
`top_borders[-1]` evidence continues to corroborate the existing slice-sentinel
survivor and is not counted again.

The ADX mechanism raises the totals to 82 confirmed root causes and 71
dynamically reproduced issues. Coverage is 1,284/4,995 (25.71%), with 3,711
historically ranked files remaining.

Directly slicing the unchanged deterministic order reproduces ranks 1261–1284
and their committed manifest and SHA-256 exactly. The next exact-path manifest
seals ranks 1285–1308 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1285_1308.json` with SHA-256
`053757224ea45fb70ccc4d2f5ff2ff139334ee7cdf388b98aeb7375943f5dbd2`.

### Blind wave 1285–1308 and the AVOption binary-array overflow

The wave achieved successful source work on all 24 exact paths across an
interrupted 19-path initial session and a five-path retry. Together they used
6,649,848 tokens over 731 settled model calls and made 172 candidate/finding
calls. The endpoint recovered from shorter connection and read timeouts, but
three long in-flight requests required cancellation after their paths had
already completed source-bearing actions. No formal finding was accepted by the
online scaffold.

Offline review confirmed one new public-API memory-corruption root. The AVOption
header documents its array flag as combinable with regular option types, while a
binary scalar is defined as a pointer immediately followed by an integer byte
length. The implementation nevertheless sizes every binary array element as
only `sizeof(uint8_t *)`. A public `av_opt_set` call on one hexadecimal binary
element allocates an eight-byte slot and dispatches it to `set_string_binary`,
whose first length initialization writes four bytes at offset eight. ASan
reports the write exactly zero bytes past that allocation at `opt.c:365`.
No in-tree binary-array option currently exists, so the finding's scope is an
API consumer that exposes this documented descriptor combination.

The durable artifacts are
`evaluations/ffmpeg_opt_binary_array_reproducer.c` and
`evaluations/run_ffmpeg_opt_binary_array_reproducer.py`. The ignored proof
record reports `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2`, with all source and runtime
predicates true.

The campaign also independently rediscovered the ARLS order-17 heap under-read,
including its exact `17 -> 32` alignment and `coeffs - 14` source. That root and
its public graph proof were already recorded in ranks 949–972, so it is not
counted again. Other terminal candidates close under exact contracts: XSUB
resets its bitmap pointer between even and odd interlaced fields rather than
adding an extra row; QDraw's non-pixmap palette index guard rejects values above
255; the merge-sort tail selects whichever run remains without leaving its
range; and resampler, parser, frame, hardware, and DSP paths retain their
caller, allocation, or producer bounds.

The AVOption mechanism raises the totals to 83 confirmed root causes and 72
dynamically reproduced issues. Coverage is 1,308/4,995 (26.19%), with 3,687
historically ranked files remaining.

Directly slicing the unchanged deterministic order reproduces ranks 1285–1308
and their committed manifest and SHA-256 exactly. The next exact-path manifest
seals ranks 1309–1332 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1309_1332.json` with SHA-256
`7d251fab475e3490cc8bf4ac39449df05af17a1f6aabeba7cac6c343178651b6`.

### Blind wave 1309–1332 and five independently reproduced roots

The wave achieved successful source-bearing work on all 24 exact paths across
an interrupted 20-path initial session and a four-path retry containing only
previously untouched targets. Together the sessions used 7,242,051 tokens over
819 settled model calls and made 165 candidate/finding calls. Two long endpoint
reads were cancelled only after every started path had already completed source
actions; the retry then completed `dca_exss`, `xfaceenc`, `vf_scale_vulkan`, and
`wavarc`. The online scaffold submitted one formal finding, for TrueMotion2RT.

Offline review and production-path proofs confirmed five distinct roots. First,
`vf_swaprect` allocated one shared temporary row as the input width times plane
zero's pixel step. An odd-width 17-pixel NV12 frame therefore allocated 17
bytes, but the interleaved chroma iteration copied nine two-byte samples. The
public filter graph makes ASan report an 18-byte heap write exactly after the
17-byte allocation. Later repair `a7e38b617b32f996beaa371bbf04b39907d7a527`
sizes the row for the widest plane and explicitly identifies the out-of-array
access.

The same filter contains an independent option-domain root. Its public runtime
width expression has no positive-range check, and the later `FFMIN3` caps only
the upper side. `w=-1` consequently reaches the first plane's `memcpy` as size
-1; ASan aborts with `negative-size-param`. The widest-plane repair does not
address this mechanism, which remains present in current `origin/master`. It is
classified as a low-severity configuration-triggered denial of service rather
than conflated with the odd-width media geometry.

The concat protocol accumulates individually valid signed 64-bit child sizes
without guarding their sum. Two public `subfile` URLs can each advertise a
9,000,000,000,000,000,000-byte logical range while both remain backed by one
tiny seekable file. A public `avio_open2` call makes UBSan abort on the second
addition at `concat.c:119`. Later repair
`702b0784b73d22da4004757a1f4f3b4cbae5f969`, titled `guard total_size
overflow`, checks the exact addition in both concat variants.

DHAV duration discovery caps its tail allocation at one MiB but checked a
footer-derived absolute position with `pos + 20`. A seekable custom input with
logical size `INT64_MAX` and a final `dhav` footer whose `seek_back` is zero
derives `pos=INT64_MAX`; the addition wraps and the subsequent date load reads
four bytes sixteen bytes beyond the tail buffer. ASan reproduces that exact
over-read through the production demuxer. Later repair
`50e65074f5cca638d6dd4cf9db4b6dcf4f0a863e`, titled `Fix second integer
overflow in get_duration()`, rewrites the bound in subtraction form.

Finally, TrueMotion2RT compares luma demand with four times the complete
packet's bit capacity, then initializes its reader after the variable header,
skips 32 bits, and also consumes two chroma planes. The default safe reader
clamps an exhausted malformed stream. In FFmpeg's supported
`--disable-safe-bitstream-reader` configuration, however, the index continues
through memory. A public 50-byte packet declaring a 20x20 four-bit-delta frame
passes the guard and makes ASan report a four-byte read exactly after the
packet's 64-byte mandatory padding. The online finding correctly identified
the arithmetic but overstated default-build impact; the survivor explicitly
records the required configuration and uses medium severity.

The durable artifacts are
`evaluations/run_ffmpeg_swaprect_odd_nv12_reproducer.py`,
`evaluations/run_ffmpeg_swaprect_negative_width_reproducer.py`,
`evaluations/ffmpeg_concat_total_size_overflow_reproducer.c`,
`evaluations/run_ffmpeg_concat_total_size_overflow_reproducer.py`,
`evaluations/ffmpeg_dhav_duration_overflow_reproducer.c`,
`evaluations/run_ffmpeg_dhav_duration_overflow_reproducer.py`,
`evaluations/ffmpeg_truemotion2rt_unchecked_reader_reproducer.c`, and
`evaluations/run_ffmpeg_truemotion2rt_unchecked_reader_reproducer.py`. Every
ignored proof record reports `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2`.

The remaining terminal leads close under concrete bounds and contracts. Xan's
WC3 dimensions pass through `ff_set_dimensions` and `av_image_check_size2`
before its product allocations. FLAC picture zero-copy and truncation paths
retain `len <= left` or allocate the complete declared length. DCA EXSS first
bounds `exss_size` to the real packet and then bounds every asset offset against
it. WavArc's dangerous format lengths become negative during conversion or
cross `ff_alloc_extradata`'s `INT32_MAX - padding` rejection threshold before
the read. AOM film-grain references inherit the parser's point-count caps, and
the AAP, CELP, DCT, LC3, AVS, XFace, Vulkan, hardware, and metric paths retain
their row, frame, allocation, or producer contracts.

The user-supplied H.264 slice-table details independently confirm the existing
`h264-slice-sentinel-collision` survivor: the 16-bit `0xFFFF` poison value,
spare `mb_stride` column, deblocking-only equality, `top_borders[-1]`, and
96-byte underflow all match its recorded trace. This is corroboration, not a
new root, and is not counted again.

The five mechanisms raise the totals to 88 confirmed root causes and 77
dynamically reproduced issues. Coverage is 1,332/4,995 (26.67%), with 3,663
historically ranked files remaining.

Directly slicing the unchanged deterministic order reproduces ranks 1309–1332
and their committed manifest exactly. The next exact-path manifest seals ranks
1333–1356 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1333_1356.json` with SHA-256
`1f0e32f25d1a5f9bef29ffd19edb71d7a0cc62a648892b888c8f0e9aab7f0dac`.

### Blind wave 1333–1356 and the RTP/ASF zero-chunk loop

The wave achieved successful source-bearing work on all 24 exact paths across
an 18-path initial session and three retries that added two previously
untouched targets apiece. Together the four sessions used 6,450,962 tokens over
735 settled model calls and made 145 candidate/finding calls. No formal finding
was accepted by the online scaffold. Three sessions were interrupted only
after source work when endpoint reads stalled for several minutes; the final
two-path retry completed normally.

Offline review confirmed one remotely reachable infinite-loop root. The WMS
SDP parser base64-decodes an RTSP server-controlled ASF header before calling
`rtp_asf_fix_header`. A 54-byte decoded payload places an unknown ASF object at
offset 30 with exactly one 24-byte object header remaining. Its attacker-owned
64-bit size can be zero: the vulnerable upper-only bound accepts that value,
`p += chunksize` makes no progress, and the `do/while` condition repeats the
same object forever. A differential production-function proof times out on the
pinned build, while exact repair
`11d5f475be95d22d5f0692220cc772b116abc632` rejects the identical payload and
returns `-1094995529`. The repair adds the missing minimum-object-size guard and
explicitly says `Fixes: infinite loop`.

The durable artifacts are
`evaluations/ffmpeg_rtp_asf_zero_chunk_reproducer.c` and
`evaluations/run_ffmpeg_rtp_asf_zero_chunk_reproducer.py`. The ignored proof
record reports `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2` and records both sides of the
timeout/return differential through the production WMS SDP entry.

The remaining terminal leads close under concrete bounds and contracts. V308
dimensions pass the generic decoder product gate before its arithmetic; FRWU's
odd-height writes remain inside FFmpeg's 32-row padded frame allocation; and
M101 packets reserve and validate a full 40-byte stride for each partial 10-bit
block. VQF bit counts remain bounded with positive packet sizes. H.264 MIPS DSP
operates on fixed codec-owned blocks, tee's partially opened child array is
zeroed and excluded by `child_count`, and APETAG caps the outer tag at 16 MiB.
APV rejects oversized components with a 64-bit bits-left comparison before the
later integer expression, while its metadata-size underflow fails at the huge
allocation rather than entering the data loop. OpenCL formats preserve plane
counts, JPEG2000 DWT buffers include their extension margin, and RFC 2190's
header minimums, padded RTP storage, and bit-reader bounds contain the
zero-payload and end-bit cases. The other filter, codec, format, and utility
paths retain their allocation, frame, or producer contracts.

The user-supplied H.264 slice-table evidence remains an independent
confirmation of `h264-slice-sentinel-collision`: the `0xFFFF` poison value,
spare `mb_stride` column, deblocking-only equality, `top_borders[-1]`, and
96-byte underflow match the recorded mechanism exactly. It is corroboration,
not a new root, and is not counted again.

The RTP/ASF mechanism raises the totals to 89 confirmed root causes and 78
dynamically reproduced issues. Coverage is 1,356/4,995 (27.15%), with 3,639
historically ranked files remaining.

Directly slicing the unchanged deterministic order reproduces ranks 1333–1356
and their committed manifest and SHA-256 exactly. The next exact-path manifest
seals ranks 1357–1380 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1357_1380.json` with SHA-256
`27e4a672fa822e0c96f423beaa4c1ee2bb4b432c4e677fe6342bd5d9aecb4c41`.

### Blind wave 1357–1380 and Icecast metadata header injection

The wave achieved successful source-bearing work on all 24 exact paths across
an interrupted three-path initial session and a 21-path retry containing only
untouched targets. Together the sessions used 7,184,094 tokens over 811 settled
model calls and made 153 candidate/finding calls. Two long in-flight reads were
cancelled after all three initial paths had source actions. The retry later
survived several long reads and one automatically recovered socket timeout,
then completed normally. The online scaffold submitted no formal findings.

Offline review confirmed one HTTP-header-injection root. Icecast accepts stream
metadata through public string AVOptions, and its helper appended every
nonempty value to a custom HTTP-header block without checking for CR or LF.
Supplying `ice_name=safe-name\r\nX-Injected: yes` consequently terminated the
intended `Ice-Name` value and created a second outbound header when the HTTP
protocol appended the custom block verbatim. A loopback public `avio_open2`
proof captures both lines from the pinned build. Exact repair
`99e1ecca36455689c0c417a02ca36cd5b6e2346d` makes the identical open succeed
without transmitting either poisoned line and logs that it refused an
`Ice-Name` value containing CR/LF. The repair is titled `reject CR/LF in
metadata header values` and credits a security report. Scope requires an
application to derive an Icecast metadata option from untrusted data; ordinary
media payload bytes do not control the option.

The durable artifacts are
`evaluations/ffmpeg_icecast_header_injection_reproducer.c` and
`evaluations/run_ffmpeg_icecast_header_injection_reproducer.py`. The ignored
proof record reports `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2` and preserves both complete
loopback requests from protocol-enabled pinned and repaired builds.

The remaining terminal leads close under concrete contracts. An AV1 packet too
short to make the no-size OBU calculation negative also exhausts its extension
header, and the negative bits-left check rejects it before returning a size.
ADX writes exactly 128 bits into its 16-byte block; V210's strideless packet
check overaccounts rather than undercounts the row decoder's reads; and H.264
reference management caps short plus long references below the Vulkan arrays.
VVC transform dimensions stay inside the CTB coefficient arena, while the SVT
JPEG XS wrapper applies the library's validated component geometry after
updating public dimensions and before allocating the frame.

Average blur clamps both radii to plane geometry and includes its fixed margin;
tile, pad CUDA, Super2xSaI, color, stack, and deinterlace paths retain negotiated
frame or device bounds. RTP's packet-size option is a socket-buffer hint rather
than a copy allocation. RTSP's dynamic-packet arithmetic ends exactly at the
input boundary, AMV inherits the valid `AVPacket` size contract, THP is capped
by `ffio_limit`, and a short MM packet is released by the demux framework.
VFW's byte count comes from the trusted capture driver. Interleave can map an
extreme timestamp to the library's overflow sentinel and misorder that frame,
but it creates no memory, lifetime, disclosure, or sustained-availability
violation. The other format, filter, codec, external-library, and hardware
paths similarly retain their caller, allocation, or producer contracts.

The user-supplied H.264 slice-table chain continues to corroborate the existing
`h264-slice-sentinel-collision` survivor and is not counted again.

The Icecast mechanism raises the totals to 90 confirmed root causes and 79
dynamically reproduced issues. Coverage is 1,380/4,995 (27.63%), with 3,615
historically ranked files remaining.

Directly slicing the unchanged deterministic order reproduces ranks 1357–1380
and their committed manifest and SHA-256 exactly. The next exact-path manifest
seals ranks 1381–1404 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1381_1404.json` with SHA-256
`32f0d93791d714d75e648386bbcf96da04822e6d04b1ec8967709e9f8947919a`.

### Blind wave 1381–1404 and DOVI RPU no-metadata out-of-bounds read

The wave completed source-bearing work on all 24 exact paths in one natural
session. It settled 826 model calls using 7,116,542 input tokens and 166,716
output tokens, 7,283,258 total, and made 163 candidate/finding calls. The
online scaffold submitted no formal findings.

Offline review confirmed one high-severity memory-safety root in the public
AV1 `dovi_rpu` bitstream filter. An AV1 ITU-T T.35 metadata OBU with the Dolby
provider identifiers can carry an RPU type that the parser deliberately
ignores with a successful return. `ff_dovi_get_metadata()` then reports no
metadata, and `update_rpu()` represents that state as `rpu = NULL` and
`rpu_size = 0`. The vulnerable AV1 caller nevertheless wraps that result in an
`AVBufferRef`, assigns `t35->payload = rpu + 1`, and assigns
`t35->payload_size = rpu_size - 1`. CBS serialization consequently reads from
address 1 with an effectively unbounded unsigned payload size.

A public 56-byte packet sent through `av_bsf_get_by_name("dovi_rpu")`,
`av_bsf_send_packet()`, and `av_bsf_receive_packet()` deterministically aborts
the pinned ASan build in `cbs_av1_write_obu`. Exact later repair
`534f16d866c732a85c34ac576d66d578669578f1`, titled `handle update_rpu()
returning no RPU`, adds the missing `!rpu || rpu_size <= 1` AV1 guard and
identifies the issue as an out-of-array access. The identical packet passes the
same public filter path on that commit and is emitted intact with no sanitizer
failure. The packet includes in-payload trailing storage so the differential
reaches this exact post-parse invariant rather than the pinned reader's normal
padded-input precondition.

The durable artifacts are
`evaluations/ffmpeg_dovi_rpu_no_metadata_reproducer.c` and
`evaluations/run_ffmpeg_dovi_rpu_no_metadata_reproducer.py`. The ignored proof
record reports `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2` and preserves the address-one ASan
trace plus the clean repaired output.

The remaining terminal leads close under concrete bounds and ownership
contracts. VIMA allocates exactly the declared sample count and its safe bit
reader contains an exhausted packet; VP9 reference indices are three-bit
values indexing eight entries; and the AAC/VBN encoder paths operate on
encoder-owned, validated dimensions. The format-internal declarations expose
no direct sink, while `ff_alloc_extradata()` rejects negative and near-`INT_MAX`
sizes. IDCIN and MMF ultimately use EOF-aware AVIO packet reads, and PMP resets
`current_packet` exactly when its stream cycle reaches the computed
`(num_streams - 1) * audio_packets + 1` boundary.

ANLMS inherits one common channel-layout and sample-rate domain from default
format negotiation, so both input frames match the output channel loop. QSV,
CUDA, VAAPI, color, crop, lens, perspective, and color-constancy paths retain
their negotiated frame, region, plane, or hardware-surface bounds;
perspective's LUT stride is the logical eight-bit plane width from
`av_image_fill_linesizes()`, not an allocated frame's padded stride. DNN queue
entries retain caller-owned values and empty-pop handling at their consumers.
The x86 vertical filter count is capped by `MAX_FILTER_SIZE`, and the LoongArch
LASX vector paths add `YUVRGB_TABLE_HEADROOM` before their direct lookup macro,
matching the scalar fallback. LittleCMS serializes an unchanged profile twice
with a deterministic required size. The post-snapshot AMF error-path frame
cleanup repairs a one-frame failure leak; it does not establish an
attacker-repeatable sustained-exhaustion root. No other post-snapshot change on
these paths provides a security repair oracle.

The user-supplied H.264 slice-table chain remains strong independent
corroboration of `h264-slice-sentinel-collision` and is not counted again.

The DOVI mechanism raises the totals to 91 confirmed root causes and 80
dynamically reproduced issues. Coverage is 1,404/4,995 (28.11%), with 3,591
historically ranked files remaining.

Directly slicing the unchanged deterministic order reproduces ranks 1381–1404
and their committed manifest and SHA-256 exactly. The next exact-path manifest
seals ranks 1405–1428 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1405_1428.json` with SHA-256
`a0dda410fd3bd0799189981e386fd8fc740bc6fba0852c186c5017305aa4346d`.

### Blind wave 1405–1428 closure

The wave completed source-bearing work on all 24 exact paths in one natural
session. It settled 778 model calls using 6,977,620 input tokens and 162,809
output tokens, 7,140,429 total, and made 164 candidate calls. The online
scaffold submitted no formal findings.

Offline adjudication confirmed no new root cause. The strongest apparent lead
was FlashSV's compressed-block output exceeding its nominal per-block packet
budget. `compress2()` can write at most the explicit input-plus-twelve cap, but
`ff_alloc_packet()` uses a reusable padded allocation with substantially more
than twelve bytes of growth room per block. The legacy encoder then copies the
actual returned size into a newly sized refcounted packet. This can produce a
compression error or malformed output, but it does not cross the allocated
object. SGI's packed-row accesses exactly match depth times width times bytes
per channel; its RLE packet arithmetic remains below the generic image-size
gate, and oversized doubled allocations are rejected by `ff_alloc_packet()`.

The LoongArch RGB tail mirrors the scalar `ceil(width / 2)` pair writer. On
arm64, public `sws_scale()` probes with a 17-pixel RGB24 stride and a three-byte
terminal canary completed five scaled rows without changing the canary. The
stronger probe used YUV444P10LE input and Lanczos scaling to force the generic
RGB output path. This rules out an architecture-independent odd-width
overwrite; the architecture-specific helper remains closed by its pair-writer
contract rather than by direct dynamic reproduction here. PNM's persistent
ASCII scan offset is either
relative to a header at buffer offset zero or reset when a prefixed buffered
header fails resynchronization. AAC TNS limits its history reads to the number
of already traversed coefficients and divides one bounded LPC order among its
filters. AC-3's 16-entry mantissa counter is encoder-only and receives the
0–15 AC-3 BAP table; the 0–19 E-AC-3 table is used only by the decoder path
that does not call that counter.

The remaining candidates close under established contracts. Dirac pads every
IDWT height to the decomposition power of two, so Haar's odd row cursor never
equals its even height. Snow dispatches only 16/32-stride blocks to its fixed
assembly kernels and falls back for subsampled 4/8-stride chroma. H.264 qpel
inherits reference-edge padding, VP9 IDCT receives a writable codec-owned
coefficient block, and VAAPI allocates two `VABufferID` elements for every
counted slice. Blackframe, Faan IDCT, D3D11 scale, LCEVC, and OpenCL NLMeans
retain their negotiated frame, ownership, queue-order, and parameter bounds;
AV1 Annex B and Sega FILM apply their size and table-index checks before the
candidate operations. The previously recorded SBC encoder disclosure and Sega
FILM muxer division are companion-file roots, not new findings in `sbc.c` or
`segafilm.c`.

Post-snapshot changes on these paths are non-oracular: H.264 and Dirac widen
stride types, AAC TNS changes audio behavior, DNN and Vulkan changes add or
refactor backends, LCEVC adds formats and adjusts unknown initial dimensions,
and blackframe adopts an overflow-safe shared slice helper. The D3D11 scale
change removes one duplicate configuration-time buffer reference; it does not
establish an attacker-repeatable sustained-exhaustion root.

The user-supplied H.264 slice-table chain remains strong independent
corroboration of `h264-slice-sentinel-collision` and is not counted again.

Totals remain 91 confirmed root causes and 80 dynamically reproduced issues.
Coverage is 1,428/4,995 (28.59%), with 3,567 historically ranked files
remaining.

Directly slicing the unchanged deterministic order reproduces ranks 1405–1428
and their committed manifest and SHA-256 exactly. The next exact-path manifest
seals ranks 1429–1452 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1429_1452.json` with SHA-256
`bdc9eb6015cda6b0e43b16048087649733c64ec87d611d3f5290ffa1db288bd4`.

### Blind wave 1429–1452 and three disclosure/injection roots

The wave completed source-bearing work on all 24 exact paths in one natural
session. It settled 788 model calls using 6,815,368 input tokens and 187,020
output tokens, 7,002,388 total, and made 168 candidate/finding calls. The
online scaffold submitted no formal findings; one attempted generic
large-packet IMX report was rejected by the proof-refinement gate.

Offline review confirmed an MVC2 uninitialized-stack disclosure. The decoder
stores 128 palette entries in an uninitialized automatic array, initializes
only the packet-declared count, then uses later seven-bit palette indices
without checking them against that count. An eight-byte public packet declares
a 4x4 frame and zero colors, then selects index zero. Compiling the unchanged
vulnerable decoder source as the public registry symbol with deterministic
pattern and zero automatic-variable initialization produces
`pixel=aaaaaaaa` and `pixel=00000000` respectively. The correct repair is to
reject each undeclared index; zero initialization is only the differential
proof.

The durable MVC2 artifacts are
`evaluations/ffmpeg_mvc2_palette_disclosure_reproducer.c` and
`evaluations/run_ffmpeg_mvc2_palette_disclosure_reproducer.py`. The ignored
proof record reports `expected_observed=true` at pinned FFmpeg commit
`795bccdaf57772b1803914dee2f32d52776518e2` and preserves both public-decoder
outputs.

MermaidHTML graph output contains an independent stored output-injection/XSS
root. `graphprint.c` passes the input `AVFormatContext` URL to the Mermaid text
formatter, which substitutes only double quotes before writing the value as
HTML markup. MermaidHTML inserts that diagram inside the standalone report's
`<pre class="mermaid">`; a pre element does not suppress nested tag parsing.
An input filename containing `<img src=x onerror=alert(4242)>` consequently
creates an active image element with the event-handler attribute when the
report is opened. Scope requires an operator to request MermaidHTML output and
open a report containing an attacker-influenced URL or filename.

The Mermaid proof is
`evaluations/run_ffmpeg_mermaidhtml_injection_reproducer.py`. It invokes the
public ffmpeg graph-output path, then validates the generated report with
Python's HTML parser without opening a browser. The ignored proof record
reports `expected_observed=true` and records an `img` element with exactly
`src=x` and `onerror=alert(4242)` inside the Mermaid pre element.

VBLE exposes a third, separate information disclosure. It forces YUV420P and
uses `av_image_get_buffer_size()` for the complete image, but restores both
chroma planes with floor-divided `width / 2` and `height / 2`. The visible
chroma dimensions are ceiling-divided for odd YUV420P geometry. A valid 3x3
public decoder packet therefore has logical 2x2 U and V planes while VBLE
writes only the first sample of each. A public `get_buffer2` callback fills the
codec-owned frame with `0xA5`; the returned output is
`u=00a5/a5a5 v=00a5/a5a5`, proving that six visible chroma samples retain
prior buffer contents.

The durable VBLE artifacts are
`evaluations/ffmpeg_vble_odd_chroma_disclosure_reproducer.c` and
`evaluations/run_ffmpeg_vble_odd_chroma_disclosure_reproducer.py`. Its ignored
ASan proof record reports `expected_observed=true` and preserves the six
visible marker bytes.

The remaining candidates close under concrete bounds and contracts. The safe
bit reader and mandatory packet padding contain Golomb probes; SGI's seek
helper clamps offsets and generic dimension validation rejects zero geometry.
DSI CIN and IMX apply integer, file-size, and chunked-read limits; IMX's 768
palette-byte maximum maps exactly to its 1,024-byte palette, while a declared
packet size does not create allocation amplification beyond supplied data.
MOFLEX uses `av_append_packet()`, which grows storage before each read, and
WebVTT operates on NUL-terminated subtitle chunks. Attached-picture callers
include mandatory padding, and the shared extradata helper rejects negative
and near-`INT_MAX` sizes.

The MIPS pixel helpers retain fixed codec-owned 8x8/16x8 geometry. PGS's
segment cursor starts below `INT_MAX` and adds at most 65,538, so its unsigned
sum cannot wrap. AptX receives framework-sized frames padded to a four-sample
boundary, and FDK AAC's allocation follows the library's documented
768-byte-per-channel maximum. Median clips radii before allocating its
scratch state. Neighbor OpenCL and stack VAAPI preserve negotiated plane,
hardware-format, and validated-region contracts; the proposed VAAPI-to-USPP
trace connected unrelated filters. Agate and sidechain compression negotiate
their input/FIFO layouts. Axcorrelate's maximum window index is
`available - 1`; on its first invocation `s->used` remains false throughout
the channel loop, so each channel initializes its own accumulator.

TPad's apparent NULL clone requires activation with no queued frame, no EOF,
and no output request. The scheduler only makes the filter ready there because
one of those states changed: a queued frame takes the peek branch, EOF takes
the status branch, and an output request makes `FF_FILTER_FORWARD_WANTED`
return before the clone. TLS callers initialize their `AVBPrint` objects.
Float swscale dithering uses a power-of-two matrix: the block-aligned base plus
31 remains inside each padded matrix row, including the production 16x16 Bayer
case. HSV keying retains negotiated plane bounds. No post-snapshot change on
these paths supplies a contrary security repair oracle.

The user-supplied H.264 slice-table chain remains strong independent
corroboration of `h264-slice-sentinel-collision`: its `0xFFFF` poison,
deblocking-only equality, spare stride column, `top_borders[-1]`, and 96-byte
underflow align with the recorded mechanism. It is not counted again.

The three new roots raise the totals to 94 confirmed root causes and 83
dynamically reproduced issues. Coverage is 1,452/4,995 (29.07%), with 3,543
historically ranked files remaining.

Directly slicing the unchanged deterministic order reproduces ranks 1429–1452
and their committed manifest and SHA-256 exactly. The next exact-path manifest
seals ranks 1453–1476 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1453_1476.json` with SHA-256
`e6343e4a35fd0bd076fe22c36d6f3c17b60066095853647ae086f10094ea645c`.

### Blind wave 1453–1476, four roots, and trace compatibility

The wave completed source-bearing work on all 24 exact paths in one natural
session. It settled 747 model calls using 6,175,782 input tokens and 200,070
output tokens, 6,375,852 total, and made 190 candidate/finding calls. The
online scaffold retained no formal finding. All five `record_finding` calls
were attempts to report the same MJPEG-A logical over-read; the first preceded
candidate validation, two exposed a flattened-trace compatibility crash, and
two were repeat-suppressed. Offline review closed the candidate because every
AVPacket carries at least 64 zeroed padding bytes, which contain its two-byte
read.

The compatibility failure was still useful optimizer evidence. The local
model sent an otherwise valid ordered trace directly as a list instead of the
documented object containing `steps`. `record_finding` called `.get()` before
its validation block and lost the report to an `AttributeError`.
`clearwing/agent/tools/hunt/reporting.py` now normalizes this common flattened
form before constructing the authoritative trace, with a regression test in
`tests/test_sourcehunt_hunter.py`. The schema remains strict for conforming
providers; the runtime fallback prevents local-model evidence loss.

Offline repair-oracle review confirmed a one-byte S/PDIF AAC probe over-read.
The vulnerable bound requires seven ADTS bytes relative to the four-byte sync,
but `spdif_get_offset_and_codec()` starts the parser at `buf[5]`. A logical
14-byte buffer containing the sync, burst header, and six ADTS bytes therefore
admits a seventh byte from outside the declared range. This is production
reachable through WAV/W64 automatic S/PDIF detection, whose short-read buffer
reserves but does not initialize padding. Exact repair `15bbf3a21d` adds the
missing byte and identifies the OSS-Fuzz result as a read of uninitialized
memory.

The durable S/PDIF artifacts are
`evaluations/ffmpeg_spdif_aac_probe_boundary_reproducer.c` and
`evaluations/run_ffmpeg_spdif_aac_probe_boundary_reproducer.py`. The runner
links the pinned static libraries twice, once with the pinned probe source and
once with the exact repaired source. With a 14-byte logical buffer inside a
15-byte allocation whose `fc` tail completes the ADTS header, both runs report
`adts=0 samples=1024 frames=1 score=12`; only the vulnerable probe consumes the
logical tail and sets `codec=86018`, while the repair leaves `codec=0`. Its
ignored proof record reports `expected_observed=true`.

Two exact post-snapshot repairs establish platform-specific write overflows.
D3D12 MPEG-2 allocates an upload resource from decoded frame geometry, sums
attacker-controlled compressed slice sizes independently, and copies the full
compressed picture to that resource without comparing the sizes. Exact repair
`26a9f9b3ae` adds `ctx_pic->bitstream_size > ctx->bitstream_size` immediately
before the mapping and copy. SCTP with `max_streams` accepts a zero- or one-byte
read, passes `buf + 2` and `size - 2` to `recvmsg`, and then stores a two-byte
stream ID into the undersized caller buffer. Public direct AVIO preserves the
small request. Exact repair `5c3602abaa` adds the same `size < 2` guard already
present in the write path. Both roots remain source-confirmed because this
macOS host has neither D3D12 decode nor the SCTP kernel/API support required
for faithful runtime proofs.

The PowerPC AltiVec general vertical YUV-to-packed-RGB path contains a fourth
root. Its dispatch installs six packed RGB routines without requiring a
multiple-of-16 destination width. `yuv2packedX_altivec()` loops while
`i < dstW` but emits a complete sixteen-pixel block on every iteration: 48
bytes for RGB24/BGR24 or 64 bytes for the 32-bit layouts. The final partial
iteration therefore overruns an exact-size public `sws_scale` destination.
The apparent scratch tail is dead because the loop exits with `i >= dstW` and
tests `if (i < dstW)`. This remains source-confirmed pending a PowerPC/AltiVec
runtime proof.

The remaining online candidates close under concrete contracts. LSCR's
bytestream seek clamps to the packet, ULTI's masked codebook index matches its
16 KiB table, and ADTS/MJPEG reads stay inside mandatory packet padding.
Aliaspix dimensions remain identical across validation, allocation, and run
bounds; MSMPEG4's macroblock walk and neighbor padding contain its predictors.
Gradfun's 16-element prefix contains every negative `dc` index and its ring
rows fit the `(radius + 1)` allocation. LZW grows its bit width with the table,
while PAM and R210 allocation/write geometry agree with validated frame
contracts. The framepool repair follows a temporary post-snapshot stack
refactor and does not repair the pinned heap-owned implementation. Normalize,
Haas, hardware upload, FRM, LRC, uncoded-frame, and the remaining utility paths
retain negotiated bounds or affect correctness rather than memory safety.

The user-supplied H.264 slice-table chain remains strong independent
corroboration of `h264-slice-sentinel-collision`: the `0xFFFF` poison, picture
re-poisoning of the spare stride column, deblocking-only equality,
`top_borders[-1]`, and 96-byte underflow all align with the recorded mechanism.
It is not counted again.

The four new roots raise the totals to 98 confirmed root causes and 84
dynamically reproduced issues. Coverage is 1,476/4,995 (29.55%), with 3,519
historically ranked files remaining.

Directly slicing the unchanged 4,995-file deterministic order reproduces
ranks 1453–1476 and their committed manifest exactly. The next exact-path
manifest seals ranks 1477–1500 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1477_1500.json` with SHA-256
`2ab8cef2dc00ae7f5bef73ab84118f80b7fca7b730f6b0d904ec952a0c4f469f`.

### Blind wave 1477–1500 and three malformed-IMF roots

The wave completed source-bearing work on all 24 exact paths in one natural
session. It settled 853 model calls using 7,662,578 input tokens and 196,451
output tokens, 7,859,029 total, and made 207 candidate/finding calls. The
online scaffold retained no formal finding. Its sole `record_finding` call
proposed that an MTV segment shorter than the declared raw frame lets the raw
decoder over-read; offline review closed it because packet-backed RGB565 takes
the no-copy path and `raw_decode()` rejects `buf_size < frame_size` before
publishing image planes.

Offline repair-oracle review recovered two independent IMF null dereferences.
An AssetMap Chunk without `Path` makes `xmlNodeGetContent()` return NULL, which
`imf_uri_is_url()` immediately passes to `strstr()`. Exact repair `0fe4bd4b43`
validates the Path node and content first. Separately, a MainImageSequence
without a ResourceList creates and publishes a playback track with zero
resources. Stream initialization then unconditionally opens resource zero and
dereferences the NULL resource pointer. Exact repair `a76190152d` rejects the
empty virtual track before publication.

The same AssetMap loop contains a third, unrepaired progress failure. A child
whose name is not `Asset` executes `continue` before the loop's only
`xmlNextElementSibling()` assignment, so the same node is retried forever. A
minimal `AssetList` containing `Annotation` pins production ffprobe beyond a
two-second deadline.

`evaluations/run_ffmpeg_imf_crash_reproducer.py` is the durable proof for all
three roots. It runs ASan-enabled IMF/libxml builds at the pinned commit and at
the two exact upstream repairs. The ignored report records zero-page aborts for
both malformed crash packages, clean invalid-data rejection at the repaired
revision, and the independent bounded-time non-Asset hang; it reports
`expected_observed=true`.

The remaining candidates close under concrete bounds and contracts. CBS H.264
checks both every array-length field and each declared NAL size. WBMP dimensions
cannot reach bit 31 after generic image validation; BMP's same validation keeps
row-size products representable. RTV1 allocates its aligned block geometry,
CLJR receives ceil-divided chroma storage and a padded safe bit reader, and
VBLE-like odd-plane underallocation is absent. MIPS chroma helpers receive fixed
H.264 block heights, SpeedHQ run and coefficient indices fit their 65-entry and
12-bit domains, and SCPR's row-padding arithmetic maps the apparent negative
index to the prior row's last visible pixel.

ASDR and decorrelate share negotiated layouts. VAAPI reference topology,
D3D12 frame/context geometry, DirectShow sample lengths, and RKMpp descriptor
ownership are framework contracts; RKMpp intentionally exposes only the public
descriptor portion of its combined private allocation. RV40 uses codec-owned
padded frames, PP BNK's music branch is exactly two equal-sized tracks, and the
swscale op backend explicitly declares the padding its vector kernels require.
SetPTS NaN/Inf conversion remains configuration-only integer-cast UB without a
demonstrated out-of-range access, matching the earlier campaign exclusion.

The user-supplied H.264 slice-table chain remains strong independent
corroboration of `h264-slice-sentinel-collision`: the `0xFFFF` poison, picture
re-poisoning of the spare stride column, deblocking-only equality,
`top_borders[-1]`, and 96-byte underflow all align with the recorded mechanism.
It is not counted again.

The three new roots raise the totals to 101 confirmed root causes and 87
dynamically reproduced issues. Coverage is 1,500/4,995 (30.03%), with 3,495
historically ranked files remaining.

Directly slicing the unchanged 4,995-file deterministic order reproduces ranks
1477–1500 and their committed manifest exactly. The next exact-path manifest
seals ranks 1501–1524 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1501_1524.json` with SHA-256
`10c36e53b2d38a99999a2bb951a81f0c2bfce634d958acc6b0fe559d83887d04`.

### Blind wave 1501–1524 and three dynamically reproduced roots

The wave completed source-bearing work on all 24 exact paths. It settled 838
model calls using 7,560,110 input tokens and 189,535 output tokens, 7,749,645
total, and recorded 211 raw candidate/finding calls. The online scaffold retained
no formal finding; offline invariant review recovered three distinct roots.

Bethsoft VID accepts a truncated literal run because both checked
`bytestream2_get_buffer()` calls discard the actual copied-byte count. A public
two-byte I-frame packet declares one literal pixel but supplies no payload, yet
the decoder advances by the declared length and publishes its frame. The durable
marker-filled `get_buffer2` proof returns a successful 2x2 PAL8 frame with all
four visible pixels still equal to `0xA5` (`a5a5/a5a5`). The bundled demuxer
rejects its own short literal reads, so this root's input surface is a public
decoder packet or another packet producer.

fieldhint uses ceiling-half height for both field copies. That is correct for the
top field, but the bottom field begins at input row one and advances by two rows;
on every odd plane height its final iteration therefore reads row `height`.
FFmpeg's ordinary padded frames mask the allocation boundary, while the public
buffer source validly accepts refcounted exact-size planes. A 1x1 gray
`buffer -> fieldhint -> buffersink` proof with a complete one-byte backing makes
ASan report a one-byte heap read immediately after that allocation in
`av_image_copy_plane()`.

fftfilt registers `weight_Y`, `weight_U`, and `weight_V` as public two-argument
expression functions. Their shared `lum()` helper casts both results to integers
and indexes the FFT plane without comparing either coordinate with its allocated
strides. Configuring a valid 16x16 public graph with
`weight_Y=weight_Y(100,0)` makes ASan report a four-byte read in `weight_Y`, 768
bytes beyond an 8,192-byte allocation during graph configuration. This root
requires control of the fftfilt expression.

The durable artifacts are the three matching C harnesses and runners:
`evaluations/run_ffmpeg_bethsoft_truncated_frame_disclosure_reproducer.py`,
`evaluations/run_ffmpeg_fieldhint_odd_height_reproducer.py`, and
`evaluations/run_ffmpeg_fftfilt_expression_oob_reproducer.py`. Their ignored
reports all record the pinned commit and `expected_observed=true`.

The remaining candidates close under concrete contracts. AVS3 parser reads stay
inside mandatory zeroed packet padding, PVA truncation is handled by packet
reads, and Blend, DRMeter, Exposure, Acrossover, Yaepblur, and Silenceremove
retain negotiated frame or circular-buffer geometry. FFTFilt's ordinary transform
strides exceed its loop bounds; only its callable expression lookup violates an
allocation. D3D11 surface indices are pool-produced, and caller-forged hardware
frames remain outside the media-input root set. VC-1, G.722, CBS H.264, MPEG
error recovery, and VP9 reorder paths preserve their codec-owned array domains.

SDR2's unsigned sizes convert to negative `int` arguments and are rejected before
allocation rather than wrapping to a small successful packet. TIFF's `count > 4`
short-circuit forces offset seeking before its multiplication can matter. MOV
channel-map loops are bounded by their allocated channel counts, while the later
temporary-layout repair does not apply to the pinned ownership model. The LUT3D
base index is mathematically at most `size - 1`; its later padding change removes
clamping for speed rather than repairing an over-read. VAAPI Scale's later error
propagation change follows post-snapshot dimension validation and does not expose
a pinned allocation violation. TCP and timer paths are either lifecycle-safe or
developer-only instrumentation.

The user-supplied H.264 slice-table chain remains independent corroboration of
`h264-slice-sentinel-collision` and is not counted again.

The three new roots raise the totals to 104 confirmed root causes and 90
dynamically reproduced issues. Coverage is 1,524/4,995 (30.51%), with 3,471
historically ranked files remaining.

Direct deterministic regeneration reproduces the committed ranks 1501–1524 and
seals ranks 1525–1548 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1525_1548.json` with SHA-256
`073d8f2ec03c7d492d463cccd6bc07220a5fe2ad189e6556230180b478b36076`.

### Blind wave 1525–1548 and the OpenColorIO format-contract root

The wave completed source-bearing work on all 24 exact paths in one session. It
settled 831 model calls using 7,345,178 input tokens and 172,104 output tokens,
7,517,282 total, and made 205 raw candidate/finding calls. The online scaffold
retained no formal finding; offline invariant review recovered one root.

OpenColorIO's public `format` option independently selects the pixel format used
to allocate its output frame, but `query_formats()` assigns one common format
set to both links and never advertises that selected output. A valid
`GBRPF32 -> ocio=format=rgb24 -> geq -> buffersink` graph consequently leaves
the downstream link negotiated as three-plane GBRPF32 while emitting a
one-plane RGB24 frame. GEQ configures three float planes from the negotiated
link and its public sum expressions then dereference a missing plane.

`evaluations/run_ffmpeg_opencolorio_format_mismatch_reproducer.py` is the
durable proof. This machine lacks libOpenColorIO, so the harness stubs only a
successful external transform call; pinned FFmpeg still performs graph
negotiation, RGB24 allocation, emission on the GBRPF32 link, and the downstream
access. The ignored report records `negotiated=gbrpf32le selected=rgb24` and an
ASan zero-page read in `geq_filter_frame`, with `expected_observed=true`.

The ordinary candidates close under concrete contracts. PAL8 frames reserve a
fixed 1,024-byte palette; H.263 qscale remains in its decoded range; codec edge
and packet padding cover the examined speculative reads; paired filter frames
retain the same negotiated layout; and coordinate paths clip or wrap before
access. The entropy-state indices are bounded by their state machines, while
libdc1394 packet/frame ownership is retained through packet refcounting.

The user-supplied H.264 slice-table chain again independently confirms
`h264-slice-sentinel-collision`: the 16-bit `0xFFFF` poison and spare stride
column collide with slice 65535, the deblocking-only top-left equality enables
`top_borders[-1]`, and the luma/chroma exchanges write through the 96-byte heap
underflow. Repair `6d57428858` rejects `current_slice >= 0xFFFE` before the
increment. This is corroboration of the existing root and is not counted again.

The new root raises the totals to 105 confirmed root causes and 91 dynamically
reproduced issues. Coverage is 1,548/4,995 (30.99%), with 3,447 historically
ranked files remaining.

Direct deterministic regeneration reproduces ranks 1525–1548 exactly and seals
ranks 1549–1572 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1549_1572.json` with SHA-256
`a25deba0d3b601d7b4b9c5e75cdc43e44198571321ed58cc035a6b793d1aa2b1`.

### Blind wave 1549–1572 and three dynamically reproduced roots

The wave completed source-bearing work on all 24 exact paths in one session. It
settled 802 model calls using 6,876,760 input tokens and 186,290 output tokens,
7,063,050 total, and made 223 raw candidate/finding calls. Its one formal online
finding was the ZMQ reply-size truncation below; offline invariant review also
recovered the DVD subtitle parser and deblock roots.

The DVD subtitle parser buffers partial declared packets but checks the next
chunk with `packet_index + buf_size <= packet_len`. After a two-byte prefix of
an eight-byte packet, an `INT_MAX` chunk overflows the signed sum negative and
admits the original enormous positive length to `memcpy`. The durable proof
virtually maps the full source range, and ASan reports a 2,147,483,647-byte write
immediately after the 72-byte packet-plus-padding allocation. Exact later repair
`1b5cd3a792` replaces the addition with subtraction and explicitly cites signed
integer overflow and out-of-array access.

Deblock schedules its vertical kernel at every `x < width` block boundary even
when the final partial block lacks the kernel's two-pixel right radius. It also
modifies writable inputs in place, so a valid public buffer source can move in a
refcounted frame with an exact visible linesize and allocation. A tight 9x8 gray
frame reaches boundary x=8; ASan reports a one-byte read immediately after its
72-byte plane in `deblockv8_strong`. Threshold-satisfying data also reaches the
kernel's corresponding `x+1` and `x+2` writes.

Finally, zmqsend stores `zmq_msg_size() + 1` from `size_t` into an `int`. On the
reproduced 64-bit build, an exact `2^32-1`-byte malicious reply truncates the sum
to zero. `av_malloc(0)` supplies a one-byte object, while subtracting one makes
the `memcpy` length `SIZE_MAX`. The durable harness stubs only successful
external ZMQ transport calls and its public message-size contract; pinned
`tools/zmqsend.c` reaches ASan `negative-size-param` with size -1.

The three matching runners are
`evaluations/run_ffmpeg_dvdsub_parser_size_overflow_reproducer.py`,
`evaluations/run_ffmpeg_deblock_tight_stride_reproducer.py`, and
`evaluations/run_ffmpeg_zmqsend_size_truncation_reproducer.py`. Their ignored
reports pin the campaign commit and record `expected_observed=true`.

The remaining candidates close under concrete bounds and contracts. EVC's
439-iteration maximum fits its 440-entry tile array; RV dimensions are validated
before consistent macroblock reallocation, and codec-owned frames retain edge
padding. DFPWM packed audio allocations include every channel, FITS receives
valid per-plane linesizes, MIPS MP3 synthesis has 1,024-float channel buffers,
and PAL8 reserves its fixed 1,024-byte palette.

Graph-wide image validation keeps edgedetect products representable. Multiply
and amultiply consume matching negotiated frame/sample geometries, audio frame
pools include the vector alignment tail, HQDN3D's centered LUT bounds exactly
cover its pixel-difference domain, and FFTDNOIZ clamps every partial export.
TAK's last-frame fields exactly fill their padded 64-bit reader, FSB's THP packet
and extradata layouts match their channel products, TSCC uses zlib's bounded
produced-byte count, and AVIO callback sizes are API contracts. The remaining
graph-parser, TTML, and RTP/AC-3 leads affect ownership-safe lists, timestamps,
or bounded memory consumption rather than an allocation violation.

The three roots raise the totals to 108 confirmed root causes and 94 dynamically
reproduced issues. Coverage is 1,572/4,995 (31.47%), with 3,423 historically
ranked files remaining.

Direct deterministic regeneration reproduces ranks 1549–1572 exactly and seals
ranks 1573–1596 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1573_1596.json` with SHA-256
`bd5f9ebf46a59e19f7311562d1077f48581ddc8edc60e487626a78e58598db42`.

### Blind wave 1573–1596 and zero surviving roots

The wave completed source-bearing work on all 24 exact paths in one session. It
settled 803 model calls using 7,171,918 input tokens and 202,243 output tokens,
7,374,161 total, and made 186 raw candidate/finding calls. The online scaffold
retained no formal finding, and offline invariant review recovered no new root.

The strongest apparent edge accesses close under exact loop bounds. Phase starts
at row one and processes only through row `h - 3`, so its two-row lookahead
reaches at most the final valid row while its one-row lookbehind reaches row
zero. PNM's previous-byte tests follow an unavoidable advance over the validated
magic and token bytes. Weave allocates double-height output planes and removes
the one excess subsampled field row with its compensation term.

The remaining candidates close under syntax, option, and allocation contracts.
AV1 CBS bounds both tile-group endpoints by the parsed tile count; GIF sub-block
lengths are one byte against a 256-byte array; and the range coder's two-byte
bootstrap is covered by mandatory packet padding. AFreqShift's runtime order is
still option-bounded by `MAX_NB_COEFFS`, Hilbert caps each copy by its remaining
tap count, Scroll normalizes finite positions before subsampling, and
MergePlanes validates every configured input and plane before processing.

Frei0r's tight intermediary is copied row-wise by the generic frame helper.
Buffer-source frames are documented to conform to their configured parameters;
the CUDA, AMF, Vulkan, and DRM paths likewise consume negotiated or
framework-owned hardware-frame geometry and descriptors. ASS extradata size and
storage are one public codec-context contract, while SAUCE dimensions pass
generic image validation before allocation. The AHX and CRI parser leads affect
framing or bounded progress rather than an allocation, and the libtls null-check
typo is reachable only if its configuration allocation itself fails.

Totals therefore remain 108 confirmed root causes and 94 dynamically reproduced
issues. Coverage is 1,596/4,995 (31.95%), with 3,399 historically ranked files
remaining.

Direct deterministic regeneration reproduces ranks 1573–1596 exactly and seals
ranks 1597–1620 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1597_1620.json` with SHA-256
`709c7efda0610a1f58a3c97987dc9f4e90ac4ab034334e8f8e0704f90d493658`.

### Blind wave 1597–1620 and two dynamically reproduced roots

The wave completed source-bearing work on all 24 exact paths in one session. It
settled 879 model calls using 7,827,174 input tokens and 208,921 output tokens,
8,036,095 total, and made 237 raw candidate/finding calls. The online scaffold
retained no formal finding; offline invariant review recovered two exact later
repairs and reproduced both roots.

Codecview draws every `AVVideoBlockParams` rectangle without intersecting it
with the visible frame. The public side-data API can describe a block beginning
at `src_y == height`, while a uniquely owned refcounted frame retains exact-size
planes through the public buffer source and writable-input path. A 4x4 YUV420P
frame with an exact 16-byte luma plane and one block at `(0,4)+1x1` makes ASan
report a one-byte write immediately after that allocation. Exact later repair
`c568f40597` clamps blocks to the visible region.

MWSC unconditionally constructs a previous-frame byte reader on its first
packet, when the reference frame's data pointer and linesize are both zero. A
public 1x1 packet whose zlib stream expands to `01 00 00 ff` selects a one-pixel
previous-frame copy. UBSan aborts in `bytestream2_init` for applying a zero
offset to the null pointer. Exact OSS-Fuzz repair `ba825ce85f` conditionally
initializes the reader and rejects a copy run when the reference is absent.

The durable artifacts are
`evaluations/run_ffmpeg_codecview_block_geometry_reproducer.py` and
`evaluations/run_ffmpeg_mwsc_missing_reference_reproducer.py`, with their
matching C harnesses. Their ignored reports pin the campaign commit and record
`expected_observed=true`.

The remaining candidates close under exact contracts. Three-dimensional STR's
huge unsigned chunk length narrows to a negative `int` rejected by packet
growth. CMS receives fixed positive LUT dimensions with matching embedded
arrays. ProRes has all seven quantization matrices, including the codec-default
index. Dolby E derives at most eight channels from fixed tables, caps converted
words at its 3,072-byte buffer, and checks remaining input before every skip.
The decode_simple early-return leak is bounded to one developer-tool invocation
and process exit.

Packet padding covers DCA's speculative readers and the examined RKA edge;
codec-owned allocations cover WCMV, Snow DWT, V210, and the MIPS helpers. The
remaining filter, Vulkan, swscale, ALSA, and bitstream-filter leads retain
negotiated geometry, fixed input counts, or validated dimensions. The
user-supplied H.264 slice-table chain remains independent corroboration of
`h264-slice-sentinel-collision` and is not counted again.

The two roots raise the totals to 110 confirmed root causes and 96 dynamically
reproduced issues. Coverage is 1,620/4,995 (32.43%), with 3,375 historically
ranked files remaining.

Direct deterministic regeneration reproduces ranks 1597–1620 exactly and seals
ranks 1621–1644 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1621_1644.json` with SHA-256
`ecd13e777f50246eec454b31a8fcafa350d3cf5449f1e7906c6c1948e5e23385`.

### Blind wave 1621–1644 and one reproduced RTP/H.263 variant

The wave completed source-bearing work on all 24 exact paths in one session. It
settled 860 model calls using 8,035,936 input tokens and 159,596 output tokens,
8,195,532 total, and made 219 raw candidate/finding calls. The online scaffold
retained no formal finding. Offline invariant review reproduced one sibling
variant of an existing root but recovered no new root cause.

The generic RTP muxer accepts any packet size greater than its 12-byte outer
header. With public `packet_size=13`, it therefore advertises one byte of payload
capacity. The H.263 packetizer reserves two additional payload-header bytes and
computes `FFMIN(max_packet_size - 2, size)` as signed -1. Its split-marker path
preserves that value, and `memcpy` converts it to `SIZE_MAX`. A public RTP muxer
and valid padded four-byte H.263 packet make ASan report
`negative-size-param (size=-1)` directly in `ff_rtp_send_h263`.

`evaluations/run_ffmpeg_rtp_h263_rfc4629_small_packet_reproducer.py` and its
matching C harness are the durable proof. The ignored report pins the campaign
commit, records the accepted 13-byte packet size and one-byte capacity, and
reports `expected_observed=true`. This is the RFC4629 sibling of the already
counted RFC2190 undersized-packet failure: both subtract an H.263-specific
payload header from the generic RTP capacity and pass a negative length to
`memcpy`, so the corpus retains one root with two distinct proof harnesses.

The ordinary codec and demuxer leads close under allocation or framing
invariants. PTX's codec-owned linesize covers exactly `width * 2`; Dirac and VVC
DSP paths receive padded codec frames; and MQC's `raw` field is an integer mode
flag, not the unrelated local pointer found by the model. SAMI and JACOsub work
from terminated copies or packet padding, TTML's allocation includes its full
signature base, and ProRes metadata checks 28 bytes before writing offsets
22–24. ASF's UTF-16 readers cannot subtract more than their remaining length,
while AEA and VPK packet loops remain self-consistent under their validated
channel and block products.

The filter leads also close. GBlur allocates aligned full-resolution luma
geometry, which dominates every subsampled plane; BlackDetect reduces through
an explicit 16-slot modulo; and Delogo, ACrusher, and Deesser retain negotiated
frame/sample bounds. AFDelaySrc can emit IEEE-754 infinity or NaN for a chosen
coefficient configuration, but floating division does not trap under the
supported runtime and does not escape its allocated sample plane. GraphDump is
text-only.

Finally, AVBufferPool's outstanding-buffer reference keeps its pool alive;
thread-queue index/data desynchronization requires an allocation failure and
does not create an allocation escape; and PulseAudio's typed control-message
payload is a public caller contract rather than media-controlled data. The RTP
resynchronization lookahead remains inside mandatory packet padding.

Totals therefore remain 110 confirmed root causes and 96 dynamically
reproduced issues. Coverage is 1,644/4,995 (32.91%), with 3,351 historically
ranked files remaining.

Direct deterministic regeneration reproduces ranks 1621–1644 exactly and seals
ranks 1645–1668 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1645_1668.json` with SHA-256
`f20f5239ff8e8e9b62c67e07571a534650f6e4107dba417f99669fecd4e89369`.

### Blind wave 1645–1668 and eight confirmed roots

The wave completed source-bearing work on all 24 exact paths in one pinned
session. It settled 951 model calls using 9,058,672 input tokens and 186,080
output tokens, 9,244,752 total, and made 242 raw candidate/finding calls. The
online scaffold retained one formal `noise.c` finding, but its proposed sink is
false: `amount &&` excludes a zero divisor and ordinary negative integer
divisors are defined. Offline invariant review rejected that formulation and
recovered eight distinct roots, including a different, dynamically reproduced
division-by-zero path in the same file.

Ogg/CELT accepts an unchecked 32-bit extra-header count. The public value
`0x7FFFFFFE` derives `INT_MAX` pending headers, and every following Ogg page is
consumed as another header. A bounded custom-AVIO proof supplies 4,096 valid
repeated pages and confirms that all are consumed before its reader injects
EIO. Exact later repair `87439ed619` caps the count at 16 and explicitly
identifies the effectively infinite streaming loop.

Colorlevels maps planar RGB work to separate data planes but starts every
automatic-range scan at `data[0]` and reuses the packed component index as an
in-plane byte offset. A uniquely owned public 4x4 GBRP frame with exact 16-byte
planes and red auto-minimum scanning therefore reads the green allocation at
offset two through its final row. ASan reports the one-byte read immediately
after that complete plane.

Image2's split-plane muxer stores each plane product and their sum in signed
`int`. Public 46,340x46,340 YUV420P geometry has individually representable
plane sizes but a true total of 3,221,093,400 bytes. The guard overflows
negative and accepts a valid one-byte padded packet; UBSan records the signed
overflow and production `avio_write` immediately makes ASan report a 4,096-byte
read beyond the packet and its mandatory padding.

Colorspace CUDA rounds every plane launch to complete 32x16 blocks, while its
conversion kernels receive no visible width or height and read every launched
coordinate. A public 32x1 YUV444P CUDA input has three one-row planes in an
exact `3*pitch` allocation. With normalized pitch 32, the luma launch reads
through offset 511 of a 96-byte input allocation; the independently allocated
output is height-aligned and covers the writes. The geometry and source path
are exact, but no CUDA runtime was available for a sanitizer replay.

Chromanr accepts 16-bit YUV444 frames and horizontal and vertical radii through
100, but its 16-bit Manhattan specialization accumulates matching U and V
samples in signed `int`. A uniform 201x201 public frame produces a mathematical
sum of 2,647,745,070 at its center, and UBSan aborts in production
`manhattan_slice16` when the accumulator crosses `INT_MAX`.

The noise bitstream filter's `drop` expression treats negative results as a
random drop period by narrowing to `int`, negating, and using the value as a
modulo divisor. Any negative fraction greater than -1 narrows to zero. A valid
one-byte MPEG-2 packet with public `drop=-0.5` reaches unsigned-state modulo
zero in production and UBSan aborts.

Swresample exposes `output_sample_bits` from zero through 64 independently of
output format. S32 initialization with the accepted value 33 evaluates
`1 << (32 - output_sample_bits)`. A public mono S32-to-S32 context reaches the
negative shift during `swr_init`, where UBSan aborts before conversion.

Finally, the public encryption-init side-data parser accepts a nonzero key-ID
count with `key_id_size == 0`. The allocator deliberately omits the `key_ids`
pointer array in that case, but parsing and cleanup still index it. A complete
20-byte side-data object declaring one zero-sized ID makes UBSan abort for
zero-offset arithmetic on the null pointer in
`av_encryption_init_info_get_side_data`.

The durable recorders and matching C harnesses cover Ogg/CELT, colorlevels,
image2, chromanr, noise, swresample, and encryption-init; the CUDA case has a
deterministic source-and-geometry proof. Their ignored reports under
`results/sourcehunt-optimization/` all pin commit
`795bccdaf57772b1803914dee2f32d52776518e2` and record
`expected_observed=true`.

The remaining leads close under concrete contracts. The ARM VC-1 helper returns
the remaining byte count, so its wrapper's derived skip never exceeds input;
bounded CBS getters contain short HEVC configuration records. AVCodec's generic
image-size check is stricter than PCX's six-byte-per-pixel worst-case RLE bound,
while ADX and ANM use bounded header, channel, record, and packet sizes.
AudioFIFO validates sample-buffer products before capacity changes. FLAC, MIPS,
Wasm SAO, and MPEGVideo helpers receive codec-owned lengths and padded buffers;
OpenCL helpers and the vibrato and sine filters retain negotiated geometry or
sample counts. XTEA's block count and storage are a public caller contract, and
generic RTP parsing bounds the SVQ3 and Opus payload lengths and supplies packet
padding.

The user-supplied H.264 line-by-line chain independently matches the existing
`h264-slice-sentinel-collision` survivor: the `0xFFFF` poison and per-picture
re-poisoning, spare stride column, deblocking-only equality,
`top_borders[-1]`, 96-byte record stride, and luma/chroma exchanges all align
with its recorded trace. This is stronger corroboration, not a new root, and is
not counted again.

The eight roots raise the totals to 118 confirmed root causes and 103
dynamically reproduced issues. Coverage is 1,668/4,995 (33.39%), with 3,327
historically ranked files remaining.

Direct deterministic regeneration reproduces ranks 1645–1668 exactly and seals
ranks 1669–1692 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1669_1692.json` with SHA-256
`c33432278b7327473f5929d86c12f0f9a6d3d35e0644d5a44f215144677f381f`.

### Blind wave 1669–1692 and two dynamically reproduced roots

The wave completed source-bearing work on all 24 exact paths in one pinned
session. It settled 907 model calls using 8,960,977 input tokens and 149,972
output tokens, 9,110,949 total, and made 175 raw candidate/finding calls. The
online scaffold retained no formal finding. Offline invariant review recovered
two distinct roots and reproduced both through public APIs.

Screenpresso allocates a nonzeroed full-frame deflate destination and accepts
zlib success without checking the returned output length. A public 4x1 BGR24
keyframe whose valid stream expands to only three bytes is therefore published
as a complete 12-byte visible row. With ASan's heap fill fixed to `0xA5`, the
decoder proof observes the three supplied bytes followed by all nine untouched
allocator bytes. Exact later repair `c22667d0fd` rejects deflate output shorter
than the aligned frame and explicitly identifies use of uninitialized memory.

Colorbalance advertises planar GBR formats both with and without alpha, and its
eventual alpha copy checks whether the fourth plane exists. Both planar
callbacks nevertheless form source and destination alpha pointers before that
guard. A public tight 4x4 GBRP frame has three valid planes but null `data[3]`
and zero `linesize[3]`. The production `color_balance8_p` callback evaluates
`data[3] + 0`, and UBSan aborts for applying a zero offset to a null pointer.
The higher-depth planar callback contains the same invariant.

The durable artifacts are
`evaluations/run_ffmpeg_screenpresso_short_output_disclosure_reproducer.py` and
`evaluations/run_ffmpeg_colorbalance_planar_alpha_null_reproducer.py`, with
their matching C harnesses. Their ignored reports pin commit
`795bccdaf57772b1803914dee2f32d52776518e2`, record the public inputs and
production sinks, and report `expected_observed=true`.

The transient online findings do not survive source contracts. EVC propagates
`parse_nal_unit`'s negative-size error immediately, before adjusting either the
data pointer or remaining length. S337M's probe may read beyond the logical
probe length after recognizing a trailing marker, but all six possible bytes
remain inside mandatory `AVPROBE_PADDING_SIZE` storage. MLP's parity lookahead
similarly remains inside mandatory packet/parser padding, while its major-sync
header is at most 60 bytes and is checked before the checksum read.

The remaining allocation leads also close. AV1 QSV starts each per-frame encode
control at zero with eight extension slots, and its callback can add only the
two HDR metadata objects; ROI is restricted to H.264 and HEVC. ATRAC's five-bit
quant-unit value either indexes its 32-entry table or is rejected, and its
maximum maps to exactly 16 allocated subbands. JPEG-LS regular contexts end at
364 while run contexts use the separately sized entries 365 and 366. The ALS
channel count reaches a codec-wide sane-channel rejection before allocation.

Filter geometry is likewise bounded by negotiated formats and sizes.
Asupercut's option maximum keeps coefficients and two-value state within ten
entries; Neighbor's middle kernel processes `width - 2`, so its two-pixel
lookahead ends at the last visible sample. LimitDiff and FreezeFrames require
matching input geometry and common formats, SelectiveColor guards every
two-byte profile read, and Convolve's checked square allocations dominate its
negotiated transforms. MediaCodec strings are freed on success and failure;
SRT and ffeval use completeness-checked dynamic buffers; and legacy swscale
buffer dimensions remain an explicit public caller contract.

R3D's seek path uses the offset count where it should use an index offset, but
that is a bounded correctness failure. MCA's coefficient-offset expression is
also semantically suspicious, yet all reads go through bounded AVIO operations
and its seek product fits signed 64-bit under the validated block, channel, and
sample-count domains. WebM's long-path history is feature work rather than a
memory-safety repair.

The two roots raise the totals to 120 confirmed root causes and 105 dynamically
reproduced issues. Coverage is 1,692/4,995 (33.87%), with 3,303 historically
ranked files remaining.

Direct deterministic regeneration reproduces ranks 1669–1692 exactly and seals
ranks 1693–1716 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1693_1716.json` with SHA-256
`725b7960fba6b9818fd6d46122303b72e8f6253ea75b8f66ceeb4e1c5b230335`.

### Blind wave 1693–1716 and four exact-repair roots

The wave completed source-bearing work on all 24 exact paths in one pinned
session. It settled 896 successful model calls using 8,703,696 input tokens and
171,840 output tokens, 8,875,536 total, and made 192 raw candidate/finding
calls. The online scaffold retained no formal finding. Offline invariant and
post-pin repair review recovered four distinct roots; two reproduce under the
local sanitizer build and two remain source-confirmed.

Boxblur accepts planar and single-component formats deeper than 16 bits but
allocates only two temporary bytes per image dimension and treats every
non-byte format as 16-bit. A public tight 4x4 GRAYF32LE frame therefore gives
`blur16` a four-byte pixel step while each temporary is only eight bytes. The
radius-two first pass makes a two-byte write at offset eight, and ASan aborts
immediately after the allocation. Exact repair `2ec918330e` rejects depths
above 16 and asserts the two supported pixel sizes.

MACE computes its output sample count in signed int while its decode loop keeps
the full packet size. A public one-channel MACE3 packet of size `0x55555556`,
backed by a valid sparse virtual mapping, makes `3 * buf_size` wrap from
4,294,967,298 to two. FFmpeg consequently allocates two S16P samples, then the
third production decode write crosses the allocation. UBSan records the count
overflow and ASan records the heap overflow. Exact repair `947c57d9e6` widens
the count and rejects values above `INT_MAX`.

Librist's read callback discards its caller's buffer size and copies the whole
received payload, up to 9,972 bytes. The production `async:` wrapper supplies a
concrete mismatch: it reserves and asks the inner URL for at most 4,096 bytes,
so a larger valid RIST payload overruns the FIFO destination. Exact repair
`8880a174d0` clamps the payload to the caller size and names out-of-array
access. The pinned sanitizer configuration has neither librist nor network
support, so this root is not counted as dynamically reproduced.

MCC aliases X and Y intentionally have zero length and a null value. A valid
MCC time-code line containing either alias passes that null source to
`bytestream2_put_buffer`, whose inlined `memcpy` is invoked even for the
zero-byte copy. Exact repair `e27d91ca71` guards the call on nonzero alias length
and explicitly identifies passing a null pointer. Apple Clang eliminates the
zero-byte operation without a sanitizer report, so this root is likewise
recorded at source-confirmed evidence rather than dynamic evidence.

The durable dynamic artifacts are
`evaluations/run_ffmpeg_boxblur_deep_format_reproducer.py` and
`evaluations/run_ffmpeg_mace_sample_count_overflow_reproducer.py`, with their
matching C harnesses. Both ignored reports pin commit
`795bccdaf57772b1803914dee2f32d52776518e2`, capture the exact later repair, and
report `expected_observed=true`.

The transient online leads close under concrete contracts. YUVA420P and
YUVA422P subsample chroma, not alpha, so lumakey's full-width alpha loop matches
the allocated plane. DVD navigation's PCI and DSI copies are fixed at 980 and
1,018 bytes and concatenate exactly into the 1,998-byte parser buffer. The
SVT-JPEG-XS bitrate is an application encoder setting rather than media input,
and the external encoder validates the derived configuration; the lead had no
concrete memory-safety sink.

The remaining demuxer and muxer paths are bounded. MicroDVD caps each line at
2,048 bytes and uses 64-bit subtitle timing arithmetic. Vivo's coded length is
at most two seven-bit bytes and its text header has a separate 1,024-byte cap;
OGM uses bounded byte readers and validates its direct-show header sizes. ICO
restricts geometry to 256x256 and relies on mandatory packet padding for its
fixed header probes, while nonpositive AVIO write lengths are ignored. AST and
VOC operate on framework-validated audio parameters and bounded AVIO reads.

Codec and platform helpers also retain their upstream contracts. AAC coupling
bands and FLV bit fields are validated by their parsers; bitpacked, DSD, GSM,
DVD navigation, and Lagarith operate on checked packet or codec-owned sizes.
The AArch64 and MIPS files select or define kernels whose padding and block
geometry belong to their callers, and the display helper touches only its
fixed nine-element matrix. D3D12 motion estimation, VideoToolbox transpose,
and SVT-JPEG-XS use negotiated frame geometry and API-reported resource
footprints.

The four roots raise the totals to 124 confirmed root causes and 107
dynamically reproduced issues. Coverage is 1,716/4,995 (34.35%), with 3,279
historically ranked files remaining.

Direct deterministic regeneration reproduces ranks 1693–1716 exactly and seals
ranks 1717–1740 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1717_1740.json` with SHA-256
`d3a5acd933eea660486e9e336f11c6d604884495f6aace6cf1df4a13eb9a5bf0`.

### Blind wave 1717–1740 and two OpenSSL peer-identity roots

The wave completed source-bearing work on all 24 exact paths in one pinned
session. It settled 902 model calls using 8,649,149 input tokens and 171,930
output tokens, 8,821,079 total, and made 209 raw candidate/finding calls. Its
single formal output explicitly said that URL decoding was bounded and that no
vulnerability existed, so offline review rejects that mislabeled negative
report rather than counting it.

The OpenSSL TLS client enables chain validation for `verify=1`, but its
identity block is guarded by `!s->numerichost`. A numeric-IP URL consequently
installs no hostname or IP target, and OpenSSL accepts any certificate chaining
to a trusted CA. A loopback public-API proof uses a local CA to sign a
`wrong.example`-only certificate with no IP SAN. OpenSSL accepts the chain and
independently rejects the certificate for `127.0.0.1`, while pinned FFmpeg
accepts `tls://127.0.0.1?...verify=1`. Exact repair `83c6922826` binds numeric
hosts through `X509_VERIFY_PARAM_set1_ip` and explicitly identifies acceptance
of any publicly trusted certificate for any name.

The pinned OpenSSL DTLS client has an independent identity omission. Its source
even notes that verification does not check the requested hostname; the path
enables CA-chain validation and sends SNI but never calls `SSL_set1_host`. A
second loopback public-API proof targets `dtls://localhost?...verify=1` with the
same trusted `wrong.example` certificate. OpenSSL independently rejects the
hostname while pinned FFmpeg completes the DTLS handshake. Later refactor
`e2eee22f16` removes the independent DTLS setup and routes it through
`tls_open`, whose nonnumeric client path binds `s->host` with
`SSL_set1_host`.

The durable artifacts are
`evaluations/run_ffmpeg_tls_openssl_numeric_ip_verify_reproducer.py` and
`evaluations/run_ffmpeg_dtls_openssl_hostname_verify_reproducer.py`, with their
matching C harnesses. Both ignored reports pin commit
`795bccdaf57772b1803914dee2f32d52776518e2`, record independent OpenSSL identity
rejections and successful FFmpeg connections, capture the later repairs, and
report `expected_observed=true`.

The strongest transient memory-safety leads close under concrete contracts.
DNxUC's `next = i - 7` is intentional cross-buffer parser bookkeeping and its
minimum minus seven remains inside `AV_INPUT_BUFFER_PADDING_SIZE`. ADTS's
maximum PCE field counts plus its 255-byte comment remain inside the 320-byte
destination. Slice threading counts the synchronous caller as the active
worker removed from the signaled-worker total. XBIN's `fontheight` is an int
loaded by `avio_r8`, not a negative signed byte. H.264 codec-string extradata
retains the framework's mandatory zero padding, while A64's positive-size/null
combination violates the public codec-parameter ownership contract.

The remaining filter, device, and library leads also close. Lagfun and
MaskedMinMax operate on negotiated matching geometry; NPP's rounded CUDA
allocation is larger than the processed image. ALSA cannot return more frames
than `snd_pcm_readi` was asked to fill. Libaom owns and validates the returned
image planes, VideoToolbox's sequence data is a bounded decoder buffer, and the
x86 edge kernels inherit caller-allocated borders and stride. Vorbis chapter
fields are reduced to bounded ints before their 64-byte formatting buffer, and
the CRC table marker selects the allocation-compatible implementation.

The two roots raise the totals to 126 confirmed root causes and 109 dynamically
reproduced issues. Historical coverage is 1,740/4,995 (34.83%), with 3,255
historically ranked files remaining.

Direct deterministic regeneration reproduces ranks 1717–1740 exactly and seals
ranks 1741–1764 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1741_1764.json` with SHA-256
`65a6a5af0f738f0ab74967aaf2d8e47d020a027dd8e44840c44155c47ca4cfd1`.

### Blind wave 1741–1764 and odd-width Bayer plane overrun

The wave completed source-bearing work on all 24 exact paths in one pinned
session. It settled 924 model calls using 9,021,650 input tokens and 163,964
output tokens, 9,185,614 total, and made 190 raw candidate/finding calls. It
submitted no formal findings.

Offline adjudication confirms one of the model's unresolved raw candidates.
Every Bayer conversion helper operates on two-pixel by two-row blocks, but the
public unscaled wrapper forwards `src_w` without requiring it to be even. A 3x2
`BAYER_BGGR8` frame with exact width-derived source and RGB24 destination
strides reaches a final block beginning at pixel two. That block reads source
offset six after a six-byte plane and writes destination offsets 18 through 20
after an 18-byte plane. Independent public-API guard-page runs terminate with
`SIGBUS` at the exact source and destination boundaries. The same pair loop and
missing width check remain in current `origin/master`; no later repair is known.

The durable artifact is
`evaluations/run_ffmpeg_bayer_odd_width_reproducer.py` with its matching C
harness. Its ignored report pins commit
`795bccdaf57772b1803914dee2f32d52776518e2`, records both independent boundary
faults, and reports `expected_observed=true`.

This wave also exposes a treatment-level closure failure. The hunter formed the
correct odd-width candidate but repeatedly issued an identical candidate update;
the duplicate-call guard skipped it and the candidate checkpoint then prevented
the caller validation needed for formal submission. The frozen treatment remains
unchanged for comparability, while offline adjudication retains the dynamically
confirmed root.

The other transient leads close under concrete contracts. RTP MPEG-TS bounds
its carry buffer with `FFMIN` and the transport parser stays within complete
188-byte packets; common mux validation rejects AIFF packets with invalid stream
indices. AAC coupling uses static scale-factor-band tables, rejects
`max_sfb > num_swb`, and stores 1,024 coefficients. H.263/x86 checks decoded
coefficient indices below 64, and XFace's preceding same-row guard excludes the
apparent bottom-row indices 47–49.

Format and framework contracts close the remaining stronger leads. WebP and QOA
fixed header probes remain in mandatory packet padding; invalid QOA read lengths
return an error. TED's automatic AVBPrint mode never allocates, MSF's block-align
field is an `int`, and SOL ignores the invalid timebase before downstream audio
rate checks reject it. VideoToolbox scaling rejects invalid dimensions and crop
metadata, libvpx buffer references preserve external-frame lifetime, XVideo's
destination rectangle controls server scaling rather than the shared source
buffer, and H.265 metadata rejects reserved VCL content before slice casting.
The MLP trajectory explicitly concluded that it had no vulnerability.

The Bayer root raises the totals to 127 confirmed root causes and 110
dynamically reproduced issues. Historical coverage is 1,764/4,995 (35.32%),
with 3,231 historically ranked files remaining.

Direct deterministic regeneration reproduces ranks 1741–1764 exactly and seals
ranks 1765–1788 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1765_1788.json` with SHA-256
`9a03c6f55d48748269920484c54cfc14d958bfd3943b1d81233a9cf932cd44e5`.

### Blind wave 1765–1788

The wave completed source-bearing work on all 24 exact paths in one pinned
session. It settled 914 model calls using 8,680,882 input tokens and 200,989
output tokens, 8,881,871 total, and made 249 raw candidate/finding calls. It
submitted one unverified formal finding.

The formal LZW stack-overflow report is false. Every dictionary prefix names a
strictly earlier, smaller code, so the prefix graph is acyclic and a single
expansion is bounded by the 4,096-code table. The decoder drains `sp` before it
reads the next code, and the `code == slot` special-case byte plus the preceding
code chain still fit the 4,096-byte stack. Writes from separate input codes do
not accumulate in the stack as the report claimed.

The remaining transient leads close under concrete bounds and contracts. The
UTF-8 helper reaches the terminating NUL before attempting another continuation
read; FSPP callers provide the even counts consumed by its two-unit loop; and
MSVCRT and RTSP formatting overflow candidates become rejected huge
allocations, not small writable buffers. BIT reads at most 160 bytes from its
164-byte buffer, RTMP-DH's secret buffer matches the fixed modulus, DTS tail
access stays in mandatory probe padding, EVC tile/reference arrays are bounded,
and the AAC-PS tables contain all 276 consumed entries.

Filter, library, and architecture-specific leads also close. BWDIF's vertical
references inherit caller edge/interior-row selection, SILENCEREMOVE cannot
prove output beyond input plus retained-silence storage, LibGME receives zero
input with an explicit zero length, and RSD's `INT_MAX / 36` channel bound keeps
`8 * channels` representable. Mastering-display helpers allocate exactly the
struct size and every reviewed decoder wrapper writes only declared fields.
RepeatFields copies the configured minimum row width from valid frames whose
strides cover that width. ARM and AArch64 resamplers normalize the phase index
below `phase_count` before indexing a bank allocated for `phase_count + 1`
filters. RTP MPEG-video's two tail bytes lie in mandatory packet padding after
a complete picture start code. AIX's zero sample rate produces an ignored
invalid timebase and is guarded by later audio-rate checks, not a division by
zero.

No new root survives adjudication, so totals remain 127 confirmed root causes
and 110 dynamically reproduced issues. Historical coverage is 1,788/4,995
(35.80%), with 3,207 historically ranked files remaining.

Direct deterministic regeneration reproduces ranks 1765–1788 exactly and seals
ranks 1789–1812 in
`evaluations/sourcehunt_ffmpeg_next_unseen_paths_1789_1812.json` with SHA-256
`e839ccaf9e4e6f3b4470eb0d5fb8ef5112dc2d5c041031e90a79e548d45f6bf3`.
