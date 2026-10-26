.PHONY: check bpf smoke-agent-join smoke-benign-corpus smoke-injections smoke-mimicry eval-detectors eval-ablations eval-taxonomy eval-all

CORPUS_DIR ?= $(shell PYTHONPATH=. python3 -m tripwire.benign_corpus --data-dir data)
check:
	bash -n scripts/setup_vm.sh scripts/smoke_bpf.sh scripts/smoke_agent_join.sh scripts/smoke_benign_corpus.sh scripts/smoke_injections.sh scripts/smoke_mimicry.sh scripts/reproduce.sh
	PYTHONPYCACHEPREFIX="$${TMPDIR:-/tmp}/tripwire-pycache-$$(id -u)" python3 -m py_compile scripts/run_phase0_vm.py scripts/nocloud_seed.py tripwire/benign_corpus.py attacker/mimicry.py eval/run_detectors.py eval/run_injections.py eval/finalize_injections.py eval/run_ablations.py eval/run_taxonomy.py eval/plot_ablations.py
	python3 scripts/check_env.py
	$(MAKE) bpf

bpf:
	$(MAKE) -C bpf all

smoke-agent-join:
	bash scripts/smoke_agent_join.sh

smoke-benign-corpus:
	bash scripts/smoke_benign_corpus.sh

smoke-injections:
	bash scripts/smoke_injections.sh

smoke-mimicry:
	bash scripts/smoke_mimicry.sh

eval-detectors:
	python3 -m eval.run_detectors --corpus-dir "$(CORPUS_DIR)" \
		$${ATTACK_DIR:+--attack-dir "$$ATTACK_DIR"}

eval-ablations:
	@test -n "$(ATTACK_DIR)" || { echo 'set ATTACK_DIR to finalized injection or mimicry data' >&2; exit 1; }
	python3 -m eval.run_ablations --corpus-dir "$(CORPUS_DIR)" \
		--attack-dir "$(ATTACK_DIR)" --output-dir "$(ATTACK_DIR)/ablation-eval"

eval-taxonomy:
	@test -n "$(ATTACK_DIR)" || { echo 'set ATTACK_DIR to finalized injection data' >&2; exit 1; }
	python3 -m eval.run_taxonomy --attack-dir "$(ATTACK_DIR)"

eval-all:
	@test -n "$(ATTACK_DIR)" || { echo 'set ATTACK_DIR to finalized injection data' >&2; exit 1; }
	python3 -m eval.run_detectors --corpus-dir "$(CORPUS_DIR)" \
		--attack-dir "$(ATTACK_DIR)" --output-dir "$(ATTACK_DIR)/detector-eval"
	python3 -m eval.run_ablations --corpus-dir "$(CORPUS_DIR)" \
		--attack-dir "$(ATTACK_DIR)" --output-dir "$(ATTACK_DIR)/ablation-eval"
	python3 -m eval.run_taxonomy --attack-dir "$(ATTACK_DIR)"
	python3 -m eval.plot_ablations --results "$(ATTACK_DIR)/ablation-eval/results.json" \
		--output "$(ATTACK_DIR)/ablation-eval/ablation-tpr.svg"

.PHONY: test
test:
	python3 -m unittest discover -s tests -v
