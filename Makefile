.PHONY: setup test telemetry docs check clean

setup:
	python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Offline: quality gates + synthetic replay (real-telemetry tests skip if samples are absent)
test:
	.venv/bin/python -m pytest

# Fetch pinned public EVTX samples, then run everything with telemetry required
telemetry:
	.venv/bin/python -m tools.fetch_samples
	REQUIRE_TELEMETRY=1 .venv/bin/python -m pytest

docs:
	.venv/bin/python -m tools.convert && .venv/bin/python -m tools.coverage

check: telemetry docs
	git diff --exit-code docs/

clean:
	rm -rf build .pytest_cache
