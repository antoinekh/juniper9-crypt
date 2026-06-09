# Changelog

## Unreleased

## v0.2.0 - 2026-06-09

### Changed

- Converted the single module to a `juniper9_crypt` package shipping a `py.typed` marker, so type checkers pick up the type annotations (PEP 561).
- Improved the algorithm diagram (dark-mode readability, ciphertext anatomy) and made it render on the PyPI page.
- `__version__` is now derived from package metadata; the version is maintained only in `pyproject.toml`.
- The publish workflow refuses to run when the release tag does not match the version in `pyproject.toml`.

### Fixed

- `decrypt()` now raises `ValueError` on truncated ciphertexts instead of silently decoding a wrong final character.
- `encrypt()` now raises `ValueError` for characters outside Latin-1 (code points above 255) instead of producing a ciphertext that decrypts to something else.
- CLI: `--encrypt ''` and `--decrypt ''` were silent no-ops exiting 0; empty strings are now processed like any other value (`--encrypt ''` produces a valid ciphertext, `--decrypt ''` reports an error and exits 2).

## v0.1.0 - 2026-06-09

- Initial release: `decrypt()`, `encrypt()`, `check()` Python API and `juniper9-crypt` CLI.
