.PHONY: setup test telemetry docs check e2e-up e2e e2e-down clean

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

# End-to-end: run the compiled SPL inside a real Splunk (needs Docker)
e2e-up:
	docker compose -f e2e/docker-compose.yml up -d

e2e:
	.venv/bin/python -m tools.e2e_splunk

e2e-down:
	docker compose -f e2e/docker-compose.yml down -v

clean:
	rm -rf build .pytest_cache
