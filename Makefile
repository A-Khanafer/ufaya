# UFAYA developer gauntlet.
#
# Quick start:
#   make check              # everything you should run before pushing
#   make update-snapshots   # regenerate JSON snapshot fixtures (review before commit)
#   make build              # produce a wheel + sdist and inspect them
#   make smoke              # install the wheel into a fresh venv and import it
#
# All targets assume `.venv/` exists with the dev extras installed:
#   python -m venv .venv && .venv/bin/pip install -e '.[dev]'

PY        := .venv/bin/python
PIP       := .venv/bin/pip
PYTEST    := .venv/bin/pytest
RUFF      := .venv/bin/ruff
MYPY      := .venv/bin/mypy

.PHONY: check lint format type test snapshots schema update-snapshots build smoke clean

# ---- Pre-push gauntlet -------------------------------------------------------

check: lint type test  ## Run before every push.

lint:
	$(RUFF) check src/ tests/

format:
	$(RUFF) format src/ tests/

type:
	$(MYPY) src/

test:
	$(PYTEST) -q

# ---- Export contract ---------------------------------------------------------

# Snapshot regression — fails when the output changes at all.
# After an intentional change, run `make update-snapshots`, review the
# diff under tests/snapshots/, and commit.
snapshots:
	$(PYTEST) tests/test_export_snapshots.py -q

# Schema conformance — fails when the output stops matching the documented
# JSON Schema contract. Independent from snapshots.
schema:
	$(PYTEST) tests/test_export_schema.py -q

update-snapshots:
	UPDATE_SNAPSHOTS=1 $(PYTEST) tests/test_export_snapshots.py -q

# ---- Release rehearsal -------------------------------------------------------

# Build the wheel + sdist and validate they're publishable. Run before any
# `twine upload`. Setuptools-scm picks the version from the most recent git tag.
build: clean
	$(PY) -m build
	$(PY) -m twine check dist/*

# Install the freshly built wheel into a throwaway venv and import it. Catches
# packaging bugs (missing files, bad imports) that pytest can't see because it
# runs against the editable install.
smoke: build
	rm -rf /tmp/ufaya-smoke
	python3 -m venv /tmp/ufaya-smoke
	/tmp/ufaya-smoke/bin/pip install -q dist/ufaya-*.whl
	/tmp/ufaya-smoke/bin/python -c "import ufaya; \
print('imported ufaya', ufaya.__version__); \
d = ufaya.get_firewall_driver('juniper_srx', config_path='tests/fixtures/juniper_full.xml'); \
print('parsed', len(list(d.get_rules())), 'rules')"

clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info .pytest_cache/ .mypy_cache/ .ruff_cache/
