.PHONY: pypi
pypi: dist
	twine upload dist/*

.PHONY: dist
dist: flake8
	-rm dist/*
	./setup.py sdist bdist_wheel

.PHONY: flake8
flake8:
	flake8 . --exclude '*venv' --count --select=E901,E999,F821,F822,F823 --show-source --statistics
	flake8 . --exclude '*venv' --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics


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
