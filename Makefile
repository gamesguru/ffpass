SHELL:=/bin/bash

.PHONY: pypi
pypi: dist
	twine upload dist/*

.PHONY: dist
dist: flake8
	-rm dist/*
	./setup.py sdist bdist_wheel

.PHONY: flake8
flake8:
	flake8 . --exclude '*venv,build' --count --select=E901,E999,F821,F822,F823 --show-source --statistics
	flake8 . --exclude '*venv,build' --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
	# CI pipeline
	flake8 . --exclude='*venv,build' --ignore=E741,E501


.PHONY: install
install:
	pip install .

.PHONY: test
test:
	@echo 'Remember to run make install to test against the latest :)'
	coverage run -m pytest -svv tests/
	coverage report -m --omit="tests/*"


.PHONY: clean
clean:
	rm -rf *.egg-info build dist
	rm -f .coverage
	find . \
		  -name .venv -prune \
		  -o -name __pycache__ -print \
		  -o -name .pytest_cache -print \
		| xargs -r rm -rf
