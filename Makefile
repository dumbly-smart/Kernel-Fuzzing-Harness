.PHONY: check bpf
check:
	bash -n scripts/setup_vm.sh scripts/smoke_bpf.sh
	python3 scripts/check_env.py
	$(MAKE) bpf

bpf:
	$(MAKE) -C bpf all

.PHONY: test
test:
	python3 -m unittest discover -s tests -v
