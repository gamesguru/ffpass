SHELL:=/bin/bash

.DEFAULT_GOAL=_help

# NOTE: must put a <TAB> character and two pound "\t##" to show up in this list.  Keep it brief! IGNORE_ME
.PHONY: _help
_help:
	@printf "\nUsage: make <command>, valid commands:\n\n"
	@grep "##" $(MAKEFILE_LIST) | grep -v IGNORE_ME | sed -e 's/##//' | column -t -s $$'\t'


.PHONY: build
build: lint	## Build release
build:
	-rm dist/*
	./setup.py sdist bdist_wheel


.PHONY: release
release: build	## Upload release to PyPI (via Twine)
	twine upload dist/*



LINT_LOCS_PY ?= ffpass/ scripts tests/

.PHONY: format
format:	## Not phased in yet, no-op
	-black --check ${LINT_LOCS_PY}
	-isort --check ${LINT_LOCS_PY}


.PHONY: lint
lint:	## Lint the code
	flake8 --count --show-source --statistics


.PHONY: test
test:	## Run pytest & show coverage report
	coverage run
	coverage report



.PHONY: install
install:	## Install from local source (via pip)
	pip install .


.PHONY: clean
clean:	## Clean up build files/cache
	rm -rf *.egg-info build dist
	rm -f .coverage
	find . \
		  -name .venv -prune \
		  -o -name __pycache__ -print \
		  -o -name .pytest_cache -print \
		| xargs -r rm -rf
