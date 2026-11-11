.PHONY: setup test build docs check clean

setup:
	python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

test:
	.venv/bin/python -m pytest

build:
	.venv/bin/python -m tools.convert

docs:
	.venv/bin/python -m tools.convert && .venv/bin/python -m tools.coverage

check: test docs
	git diff --exit-code docs/

clean:
	rm -rf build .pytest_cache
