"""Find resolved MCP SDK versions in lockfiles and manifests (direct and transitive)."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .advisories import TRACKED

NPM_PKGS = set(TRACKED["npm"])
GO_MOD = TRACKED["go"][0]
RUST_CRATES = set(TRACKED["rust"])
RUBY_GEMS = set(TRACKED["rubygems"])
COMPOSER_PKGS = set(TRACKED["composer"])


@dataclass(frozen=True)
class Dep:
    ecosystem: str  # npm | pip | go | rust | rubygems | composer
    package: str
    version: str
    file: str
    line: int = 1


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def _npm_name_from_path(key: str) -> str | None:
    # "node_modules/a/node_modules/@modelcontextprotocol/sdk" -> "@modelcontextprotocol/sdk"
    if "node_modules/" not in key:
        return None
    name = key.rsplit("node_modules/", 1)[1]
    return name if name in NPM_PKGS else None


def parse_package_lock(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    out: list[Dep] = []
    for key, meta in (data.get("packages") or {}).items():
        name = _npm_name_from_path(key)
        if name and meta.get("version"):
            out.append(Dep("npm", name, meta["version"], rel, _line_of(text, f'"{key}"')))
    if not data.get("packages"):  # lockfileVersion 1

        def walk(deps: dict):
            for name, meta in (deps or {}).items():
                if name in NPM_PKGS and meta.get("version"):
                    out.append(Dep("npm", name, meta["version"], rel, _line_of(text, f'"{name}"')))
                walk(meta.get("dependencies"))

        walk(data.get("dependencies"))
    return out


_PNPM = re.compile(r"""^\s{0,4}['"]?/?(@modelcontextprotocol/[a-z0-9-]+)[@/](\d[^\s:'"()]*)""", re.M)
_YARN_HDR = re.compile(r'^"?(@modelcontextprotocol/[a-z0-9-]+)@', re.M)
_YARN_VER = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?', re.M)
_BUN = re.compile(r'"(@modelcontextprotocol/[a-z0-9-]+)@(\d[^"]*)"')


def parse_pnpm_lock(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8")
    out = []
    for m in _PNPM.finditer(text):
        if m.group(1) in NPM_PKGS:
            out.append(Dep("npm", m.group(1), m.group(2), rel, text.count("\n", 0, m.start()) + 1))
    return out


def parse_yarn_lock(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8")
    out = []
    for m in _YARN_HDR.finditer(text):
        if m.group(1) not in NPM_PKGS:
            continue
        block = text[m.end() : m.end() + 600]
        vm = _YARN_VER.search(block)
        if vm:
            out.append(Dep("npm", m.group(1), vm.group(1), rel, text.count("\n", 0, m.start()) + 1))
    return out


def parse_bun_lock(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8")
    return [
        Dep("npm", m.group(1), m.group(2), rel, text.count("\n", 0, m.start()) + 1)
        for m in _BUN.finditer(text)
        if m.group(1) in NPM_PKGS
    ]


_REQ = re.compile(r"^\s*mcp(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;#,]*)", re.M | re.I)


def parse_requirements(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return [Dep("pip", "mcp", m.group(1), rel, text.count("\n", 0, m.start()) + 1) for m in _REQ.finditer(text)]


def parse_toml_lock(path: Path, rel: str) -> list[Dep]:
    """poetry.lock, uv.lock, pdm.lock: [[package]] name/version tables."""
    text = path.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    out = []
    for pkg in data.get("package", []):
        if str(pkg.get("name", "")).lower() == "mcp" and pkg.get("version"):
            out.append(Dep("pip", "mcp", pkg["version"], rel, _line_of(text, 'name = "mcp"')))
    return out


def parse_pipfile_lock(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        meta = (data.get(section) or {}).get("mcp")
        if meta and str(meta.get("version", "")).startswith("=="):
            out.append(Dep("pip", "mcp", meta["version"][2:], rel, _line_of(text, '"mcp"')))
    return out


_GOMOD = re.compile(r"github\.com/modelcontextprotocol/go-sdk\s+(v[0-9][^\s/]*)")


def parse_go_mod(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8")
    return [Dep("go", GO_MOD, m.group(1).lstrip("v"), rel, text.count("\n", 0, m.start()) + 1) for m in _GOMOD.finditer(text)]


def parse_cargo_lock(path: Path, rel: str) -> list[Dep]:
    """Cargo.lock: [[package]] name/version tables (rmcp, the official Rust SDK)."""
    text = path.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    out = []
    for pkg in data.get("package", []):
        name = str(pkg.get("name", ""))
        if name in RUST_CRATES and pkg.get("version"):
            out.append(Dep("rust", name, pkg["version"], rel, _line_of(text, f'name = "{name}"\nversion = "{pkg["version"]}"')))
    return out


# Gemfile.lock specs are indented four spaces: "    mcp (0.4.0)". Platform suffixes ("-x86_64-linux") are dropped.
_GEM = re.compile(r"^ {4}([A-Za-z0-9_.\-]+) \(([0-9][^)\s-]*)[^)]*\)\s*$", re.M)


def parse_gemfile_lock(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8")
    return [
        Dep("rubygems", m.group(1), m.group(2), rel, text.count("\n", 0, m.start()) + 1)
        for m in _GEM.finditer(text)
        if m.group(1) in RUBY_GEMS
    ]


def parse_composer_lock(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    out = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            name, ver = pkg.get("name"), str(pkg.get("version", "")).removeprefix("v")
            # Skip branch installs such as "dev-main": there is no release version to match.
            if name in COMPOSER_PKGS and ver[:1].isdigit():
                out.append(Dep("composer", name, ver, rel, _line_of(text, f'"name": "{name}"')))
    return out


PARSERS = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "yarn.lock": parse_yarn_lock,
    "bun.lock": parse_bun_lock,
    "poetry.lock": parse_toml_lock,
    "uv.lock": parse_toml_lock,
    "pdm.lock": parse_toml_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "go.mod": parse_go_mod,
    "Cargo.lock": parse_cargo_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "gems.locked": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
}


def parser_for(name: str):
    if name in PARSERS:
        return PARSERS[name]
    if name.endswith(".txt") and ("requirements" in name or name == "constraints.txt"):
        return parse_requirements
    return None


def collect(path: Path, rel: str) -> list[Dep]:
    parser = parser_for(path.name)
    if not parser:
        return []
    try:
        return parser(path, rel)
    except (ValueError, OSError, tomllib.TOMLDecodeError):
        return []


def dedupe(deps: list[Dep]) -> list[Dep]:
    seen, out = set(), []
    for d in deps:
        k = (d.ecosystem, d.package, d.version, d.file)
        if k not in seen:
            seen.add(k)
            out.append(d)
    return out
