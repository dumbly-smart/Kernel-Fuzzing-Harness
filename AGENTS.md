# Tripwire: standing instructions

- Research project: eBPF monitoring of tool-using LLM agents + adaptive attacker + taxonomy.
- Everything runs in a throwaway VM. Fake credentials and canary tokens only. Attacks target only my own local agent and local sinks.
- Work phase by phase; stop after each phase and summarize with acceptance results.
- No invented citations or numbers. Use TODO(verify) when unsure.
- Pin all versions. Keep configs explicit. Log research-relevant parameters.
- Small commits. Tests for parsing, joins, features, and metrics.
- Explain non-obvious eBPF/kernel decisions briefly in comments and docs/notes/.
- Report exact errors and diagnoses; never silently work around failures.

## Code discovery

Prefer codebase-memory MCP graph tools: list_projects/index_status at session start,
then search_graph, trace_path, get_code_snippet, and check_index_coverage for all
candidate paths. Default to Verify evidence. Validate coverage for negative claims;
read reported missing ranges directly. Use source search for non-code files,
literals, or insufficient graph coverage. A clean coverage result is not proof of
completeness. Preserve project, generation, queries, paths, coverage and unresolved
questions when delegating. Never claim graph access when tools are unavailable.
