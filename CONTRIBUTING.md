# Contributing to basis-gateway

## Development setup

Both `basis-core` and `basis-gateway` must be checked out as siblings:

```
REPOS/
  basis-core/
  basis-gateway/
```

Install `basis-core` first so pip resolves it from the local editable install rather than PyPI:

```bash
cd ~/REPOS/basis-gateway

python3.10 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip setuptools wheel
pip install -e ../basis-core
pip install -e ".[dev]"
```

Verify the correct package is installed:

```bash
python -c "import basis_core; print(basis_core.__file__)"
```

The path must reference `../basis-core/src/basis_core/__init__.py`, not `.venv/site-packages`. If it does not, see [Troubleshooting](README.md#troubleshooting) in the README.

## Running tests

```bash
python -m pytest
```

Tests run without a live IdP. RSA keys and a mock JWKS server are generated locally.

## Linting and formatting

```bash
ruff check .
ruff format --check .
```

To auto-fix:

```bash
ruff check --fix .
ruff format .
```

## Type checking

```bash
mypy src --cache-dir /tmp/mypy-cache-basis-gateway
```

The `--cache-dir` flag avoids conflicts if you share `~/.mypy_cache` with other projects.

## Expectations

- All four checks (`pytest`, `ruff check`, `ruff format --check`, `mypy src`) must pass before merging.
- Documentation-only changes should not break any of the above.
- The gateway does not evaluate policy. Do not add authorization logic here — that belongs in `basis-core`.
