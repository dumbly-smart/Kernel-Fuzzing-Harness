# Tripwire: Measuring OS-Level Observability of Prompt Injection in Tool Agents

**Workshop paper skeleton — empirical results intentionally incomplete**

Authors: Tripwire contributors  
Status: implementation exists; Phase 3 model corpus and Phase 5/6 guest
measurements have not completed on the development host.

## Abstract

Tool-using language-model agents translate untrusted text into file, process,
and network operations. This paper asks which indirect prompt-injection
outcomes are distinguishable from operating-system behavior, and how an
adaptive attacker can stay within a task's benign behavior envelope. We build
Tripwire, a cgroup-scoped eBPF tracer that records kernel metadata and joins
events to logged tool calls, then compare per-task behavior allowlists and
tool/syscall sequence models. We evaluate [TODO(measure): number of successful
injection runs] attacks using fake canaries and a guest-local sink. We report
task utility, detection at fixed false-positive rates, feature ablations, and
an operational OS-visible / partially visible / OS-invisible taxonomy.

**No empirical claim should be added until the reproducible guest run is
complete.** The development host exhausted memory before a Phase 3 corpus was
produced; all result fields below remain TODOs.

## 1. Introduction

Indirect prompt injection can change how an agent uses tools after it reads
untrusted file, page, or tool output. The central question is not whether an
agent can be hijacked in general, but what an OS-level monitor can distinguish
once an attack changes the agent's behavior. We study both conspicuous actions
(unexpected process, out-of-scope file access, externalized fake canary) and
semantic changes that may use ordinary file operations.

Research questions:

1. Which attack outcomes produce a detectable deviation in OS-level behavior?
2. What attack success can an adaptive attacker achieve while matching the
   benign tool, path, host, syscall, and sequence envelope?
3. Which signal groups contribute detection, and what task utility is lost?

Contributions: [TODO after measured results: list only supported contributions.]

## 2. Threat model

The experiment runs in an isolated Ubuntu VM with a local open-weights model,
fake secrets, generated canary tokens, and an HTTP sink bound to guest
loopback. The attacker controls injected content and can adapt to disclosed
features and thresholds; it cannot modify the guest kernel, tracer, or
detector. No host files, credentials, or external targets are in scope.

The monitor records syscall, process, path, and connection metadata. It does
not collect HTTP payloads or infer semantic intent from file contents. The
full threat model is in `docs/THREAT_MODEL.md`.

## 3. System

Tripwire attaches tracepoint-based CO-RE eBPF programs to a cgroup v2 subtree,
emits structured events through a ring buffer, and reports ring-buffer drops.
The userspace collector records monotonic and wall-clock timestamps, process
identity, cgroup identity, paths or socket destinations, and syscall return
codes. A JSONL tool logger provides call windows and process roots. The joiner
uses call timing, process ancestry, and a configured late-event grace; it
reports ambiguous and orphan events.

The monitor extracts path, binary, host, syscall, and ordered
`(tool, syscall-class)` features. Baselines are a per-task-type allowlist and
an unsmoothed n-gram novelty score. Task-level splitting keeps repeated runs
of a task in one partition. The split seed, FPR targets, sequence order, and
feature groups are recorded in `config/`.

## 4. Experimental method

### 4.1 Benign behavior

The benign suite has 30 declarative tasks across five task types, each run with
three fixed seeds. [TODO(measure): completed run count, task success, model
manifest digest, and behavior variability.] Weak-model failures remain in the
corpus and are reported as a utility confound.

### 4.2 Injection suite

The suite covers out-of-scope fake-canary reads, local canary submission,
unexpected process execution, writes outside the workspace, poisoned
summaries, and wrong-but-valid edits. An attack counts as successful only when
its declared goal is observed. Cases originate in `injections/`; AgentDojo
integration is not implemented and remains [TODO(verify feasibility)].

### 4.3 Adaptive attacker

The current reproducible attacker compares a shell-based request with a
single allowed local `http_get` that piggybacks a fake token on a benign fetch
route. It is a deterministic tool-wrapper probe, not a learned search
algorithm or a measured model takeover. [TODO(measure: additional strategies,
goal success, and detection rate at fixed FPR.]

### 4.4 Metrics and ablations

Report task success and detector TPR at 1% and 5% target FPR, with measured
held-out FPR, calibration/test sample counts, and a cause log for every false
positive. Split by task, not run. Ablations include files, network, process,
sequence, and combined signals. The combined score is the configured
arithmetic mean of allowlist and sequence novelty. [TODO(measure: main table,
ablation plot, confidence intervals or limitations for small samples.]

## 5. Results

**Not measured.** The 8B, 1.7B, and 0.6B model guest attempts did not produce
an accepted benign corpus on the current host. See `docs/notes/phase3.md` for
the exact OOM and no-result outcomes. Do not replace these placeholders with
values from unit tests, synthetic fixtures, or prior systems.

| Measure | Result |
|---|---|
| Benign task success | TODO(measure) |
| Tool-call join orphan rate | TODO(measure in Phase 3 corpus) |
| Detector TPR at 1% / measured FPR | TODO(measure) |
| Detector TPR at 5% / measured FPR | TODO(measure) |
| Injection goal success by class | TODO(measure) |
| Naive vs adaptive detection | TODO(measure) |
| Feature ablation TPR | TODO(measure) |
| Utility loss under blocking | Not measured; blocking is not implemented |

## 6. Taxonomy

Use the operational rules in `docs/taxonomy.md`. A case remains pending if its
goal did not succeed or lacks calibrated OS-only detector verdicts. The
generated `taxonomy-results.json` must be attached or summarized here after
Phase 7 completes. Current hypotheses are not findings.

## 7. Limitations

- Small, hand-authored task and injection suites; external validity is unknown.
- Model weakness or inability to follow a task can confound attack success.
- The current adaptive attacker is hand-built and deterministic.
- Connection metadata exposes endpoints, not HTTP query/body semantics.
- Tool-call logs contain arguments, but the primary detector baseline uses OS
  features; cross-layer argument features are future work.
- The process-tree/time-window join can orphan startup and late events.
- No enforcement or task-utility loss under blocking has been measured.
- No claim is made about kernel versions beyond the pinned guest.

## 8. Related work

AgentSight describes eBPF-based correlation between agent intent and system
effects, including inspection of LLM traffic; Tripwire's current detector
focuses on OS-only behavior and measures what remains detectable without
application payloads. Tetragon documents eBPF observability and runtime
enforcement for process, file, and network activity. AgentDojo provides a
dynamic benchmark for tool-agent prompt injection; integration into Tripwire
is still TODO(verify). Host intrusion-detection work has studied mimicry
attacks that hide malicious activity within benign process behavior; our
attacker is currently a narrow local probe rather than a general optimizer.

## References

1. Y. Zheng, Y. Hu, T. Yu, and A. Quinn, “AgentSight: System-Level
   Observability for AI Agents Using eBPF,” arXiv:2508.02736, 2025.
   [Paper](https://arxiv.org/abs/2508.02736). Verify publication/version and
   bibliographic details before submission.
2. E. Debenedetti et al., “AgentDojo: A Dynamic Environment to Evaluate
   Prompt Injection Attacks and Defenses for LLM Agents,” NeurIPS Datasets
   and Benchmarks, 2024, arXiv:2406.13352.
   [Paper](https://arxiv.org/abs/2406.13352).
3. Cilium, “Tetragon Observability Policies,” project documentation.
   [Documentation](https://tetragon.io/docs/policy-library/observability/).
   Record the documentation version/date at paper submission.
4. A. Goyal, X. Han, G. Wang, and A. Bates, “Sometimes, You Aren't What You
   Do: Mimicry Attacks against Provenance Graph Host Intrusion Detection
   Systems,” NDSS, 2023. [Author-hosted paper listing](https://sts.cs.illinois.edu/papers/paper/SometimesYouArentWha20230227.html).
   Verify proceedings metadata and DOI before submission.
5. TODO(verify): classic host-based intrusion-detection and sequence-anomaly
   references selected for the final related-work section.
