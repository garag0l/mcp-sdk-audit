# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.2] - 2026-11-21

### Added
- Published to PyPI: `pipx install mcp-sdk-audit`.

### Fixed
- Release notes now contain only the tagged version's CHANGELOG section.

## [0.1.1] - 2026-11-21

### Fixed
- `action.yml` failed to load because of an unquoted colon in an input description. Use `@v0.1.1` or later for the GitHub Action.

## [0.1.0] - 2026-11-21

### Added
- Lockfile parsing for npm (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`), PyPI (`uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`, `requirements*.txt`) and Go (`go.mod`).
- Version matching against a bundled snapshot of 25 GitHub advisories for the official TypeScript, Python and Go MCP SDKs, plus `--online` lookups.
- 11 source rules (MCPA001–MCPA007 TypeScript, MCPA101–MCPA104 Python) for advisories where upgrading alone is not enough.
- Text, JSON and SARIF 2.1.0 output; `--fail-on` severity threshold.
- Composite GitHub Action with SARIF upload to code scanning.
- Test files skipped by default (`--include-tests` to include them).
