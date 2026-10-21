.PHONY: check
check:
	bash -n scripts/setup_vm.sh
	python3 scripts/check_env.py

.PHONY: test
test:
	python3 -m unittest discover -s tests -v
