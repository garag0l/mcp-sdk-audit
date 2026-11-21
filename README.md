# mcp-sdk-audit

**Upgrading your MCP SDK isn't always enough. This finds the code that stays exposed after you upgrade.**

[![CI](https://github.com/garag0l/mcp-sdk-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/garag0l/mcp-sdk-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)

`mcp-sdk-audit` checks projects that use the official Model Context Protocol SDKs (TypeScript, Python, Go). It does two things:

1. **Dependencies.** It reads your lockfiles, including transitive dependencies, and matches every resolved MCP SDK version against the GitHub Advisory Database.
2. **Code.** Several 2026 advisories say that upgrading changes nothing unless you also change your code. The tool flags code that still has one of those problems, even when the SDK is already patched.

![mcp-sdk-audit output](docs/demo.svg)

## Why this exists

Between December 2025 and November 2026 the official MCP SDKs received a run of security advisories. Several of them have a fix that is **off by default**, or that only works once your code changes:

| Advisory | What upgrading alone leaves open |
|---|---|
| [GHSA-6qxp-vccf-f47h](https://github.com/advisories/GHSA-6qxp-vccf-f47h) (TS) / [GHSA-qx49-fqc8-xw99](https://github.com/advisories/GHSA-qx49-fqc8-xw99) (Py) | Bundled client-credentials and private-key-JWT providers still send secrets to whichever authorization server the MCP server names, until you pass `expectedIssuer` / `issuer=`. |
| [GHSA-rvq5-wwqv-78pq](https://github.com/advisories/GHSA-rvq5-wwqv-78pq) (TS) / [GHSA-w4fh-qvv9-3v23](https://github.com/advisories/GHSA-w4fh-qvv9-3v23) (Py) | Bearer auth accepts tokens issued for *other* services until you set `expectedResource` / `validate_token_resource=True`. |
| [GHSA-345p-7cg4-v4c7](https://github.com/advisories/GHSA-345p-7cg4-v4c7), [GHSA-jm63-cq47-j5jp](https://github.com/advisories/GHSA-jm63-cq47-j5jp) (TS) | A transport or server created once at startup and shared across clients sends one client's responses to another. Older README examples showed this pattern, and patched SDKs now fail at runtime on it. |
| [GHSA-6prh-2h8m-c8cw](https://github.com/advisories/GHSA-6prh-2h8m-c8cw) (TS) / [GHSA-5h93-6whr-6q8j](https://github.com/advisories/GHSA-5h93-6whr-6q8j) (Py) | `redirectPolicy: 'follow'` or a `follow_redirects=True` client brings back cross-origin redirect leaks of API keys and token-request bodies. |
| [GHSA-w48q-cv73-mx4w](https://github.com/advisories/GHSA-w48q-cv73-mx4w), [GHSA-9h52-p55h-vw2f](https://github.com/advisories/GHSA-9h52-p55h-vw2f), [GHSA-vj7q-gjh5-988w](https://github.com/advisories/GHSA-vj7q-gjh5-988w) | Hand-built Express apps and low-level Python transports get no DNS-rebinding / Host-header protection unless you add it. |

Dependabot, `npm audit`, `pip-audit` and `osv-scanner` stop being useful once the version is bumped. That's exactly the point where these advisories still need a code change.

## Install

```bash
pipx install git+https://github.com/garag0l/mcp-sdk-audit
# or
pip install git+https://github.com/garag0l/mcp-sdk-audit
```

Python 3.11+ and no third-party dependencies.

## Usage

```bash
mcp-sdk-audit                       # scan the current directory
mcp-sdk-audit path/to/project
mcp-sdk-audit --online              # use the latest advisories instead of the bundled snapshot
mcp-sdk-audit -f sarif -o mcp.sarif # SARIF for GitHub code scanning
mcp-sdk-audit -f json               # machine-readable
mcp-sdk-audit --fail-on high        # exit 1 only on high/critical (default: medium)
mcp-sdk-audit --include-tests       # also check test files (skipped by default)
mcp-sdk-audit --list-rules
```

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` usage error.

### GitHub Action

```yaml
name: mcp-sdk-audit
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # for SARIF upload
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: garag0l/mcp-sdk-audit@v0.1.1
        with:
          fail-on: high        # critical | high | medium | low | none
          # upload-sarif: "true"
          # online: "true"     # fetch fresh advisories with the job's GITHUB_TOKEN
```

Findings show up under **Security → Code scanning**, and the text report is added to the job summary.

## What it reads

| Ecosystem | Files |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1 and Berry), `bun.lock` |
| PyPI | `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`, `requirements*.txt` (pinned) |
| Go | `go.mod` |

Packages: `@modelcontextprotocol/{sdk,client,server,server-legacy,core,node,express,hono,fastify}`, `mcp` (PyPI), `github.com/modelcontextprotocol/go-sdk`.

## Source rules

| ID | Lang | Severity | Flags |
|---|---|---|---|
| <a id="mcpa001"></a>MCPA001 | TS | high | `ClientCredentialsProvider` / `PrivateKeyJwtProvider` / `StaticPrivateKeyJwtProvider` / `CrossAppAccessProvider` without `expectedIssuer` |
| <a id="mcpa002"></a>MCPA002 | TS | medium | `requireBearerAuth()` / `verifyBearerToken()` without `expectedResource` |
| <a id="mcpa003"></a>MCPA003 | TS | medium | `redirectPolicy: 'follow'` |
| <a id="mcpa004"></a>MCPA004 | TS | high | Stateless HTTP server transport created at module scope in a file that serves HTTP |
| <a id="mcpa005"></a>MCPA005 | TS | high | Module-scope `McpServer`/`Server` that `connect()`s inside a request handler |
| <a id="mcpa006"></a>MCPA006 | TS | medium | Deprecated experimental `taskStore` / `InMemoryTaskStore` |
| <a id="mcpa007"></a>MCPA007 | TS | low | `express()` + HTTP MCP transport with no Host-header validation or auth |
| <a id="mcpa101"></a>MCPA101 | Py | high | `ClientCredentialsOAuthProvider` / `PrivateKeyJWTOAuthProvider` / `RFC7523OAuthClientProvider` without `issuer=` |
| <a id="mcpa102"></a>MCPA102 | Py | medium | `AuthSettings(...)` without `validate_token_resource` |
| <a id="mcpa103"></a>MCPA103 | Py | medium | `follow_redirects=True` in files that use MCP client transports |
| <a id="mcpa104"></a>MCPA104 | Py | low | `StreamableHTTPSessionManager` / `SseServerTransport` / `websocket_server` without `security_settings` |

The rules are deliberately simple text heuristics. Comments and strings are masked, and definitions, spread or `**kwargs` options, and options passed by variable are skipped rather than guessed at. Every finding names the advisory behind it, so you can confirm or dismiss it in seconds. Tuning: against the official `typescript-sdk`, `python-sdk`, `servers` and `github-mcp-server` repos, the remaining findings are SDK examples that leave `expectedResource` / `validate_token_resource` unset. The advisories themselves describe that pattern.

No Go source rules yet: the Go advisories are fixed by upgrading alone. Go dependencies are still version-checked.

## Keeping advisories current

The package ships a snapshot of the advisories in [`src/mcp_sdk_audit/data/advisories.json`](src/mcp_sdk_audit/data/advisories.json). A scheduled workflow refreshes it daily and opens a PR. `--online` (and the Action's default) queries the GitHub Advisory Database at scan time instead, using `GITHUB_TOKEN` if it's set.

## Scope and responsible use

This is a defensive tool for code you own or are authorized to assess. It reads files and makes no network calls except `--online` advisory lookups to `api.github.com`. It doesn't exploit anything.

## Contributing

Issues and PRs are welcome, especially new rules when an advisory says "upgrading alone is not enough", false-positive reports with a minimal snippet, and more lockfile formats.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest && ruff check . && ruff format --check .
```

## License

[MIT](LICENSE)
