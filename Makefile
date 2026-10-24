.PHONY: check bpf smoke-agent-join smoke-benign-corpus
check:
	bash -n scripts/setup_vm.sh scripts/smoke_bpf.sh scripts/smoke_agent_join.sh
	python3 scripts/check_env.py
	$(MAKE) bpf

bpf:
	$(MAKE) -C bpf all

smoke-agent-join:
	bash scripts/smoke_agent_join.sh

smoke-benign-corpus:
	bash scripts/smoke_benign_corpus.sh

.PHONY: test
test:
	python3 -m unittest discover -s tests -v
