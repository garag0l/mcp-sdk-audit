"""Advisory data: load the bundled snapshot or refresh it from the GitHub Advisory Database."""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

# Packages published by the modelcontextprotocol org, per ecosystem.
TRACKED = {
    "npm": [
        "@modelcontextprotocol/sdk",
        "@modelcontextprotocol/client",
        "@modelcontextprotocol/server",
        "@modelcontextprotocol/server-legacy",
        "@modelcontextprotocol/core",
        "@modelcontextprotocol/node",
        "@modelcontextprotocol/express",
        "@modelcontextprotocol/hono",
        "@modelcontextprotocol/fastify",
        "@modelcontextprotocol/inspector",
    ],
    "pip": ["mcp"],
    "go": ["github.com/modelcontextprotocol/go-sdk"],
    "rust": ["rmcp"],
    "rubygems": ["mcp"],
    "composer": ["mcp/sdk"],
}

API = "https://api.github.com/advisories"


@dataclass(frozen=True)
class Affected:
    ghsa: str
    cve: str | None
    severity: str
    summary: str
    url: str
    ecosystem: str
    package: str
    vulnerable_range: str
    patched: str | None


def _get(url: str, token: str | None) -> list[dict]:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https URL
        return json.load(resp)


def fetch(token: str | None = None) -> list[dict]:
    """Fetch all reviewed advisories that affect a tracked package. Returns raw-ish records."""
    seen: dict[str, dict] = {}
    for eco, pkgs in TRACKED.items():
        for pkg in pkgs:
            page = 1
            while True:
                url = f"{API}?ecosystem={eco}&affects={pkg}&per_page=100&page={page}"
                batch = _get(url, token)
                for a in batch:
                    seen[a["ghsa_id"]] = {
                        "ghsa": a["ghsa_id"],
                        "cve": a.get("cve_id"),
                        "severity": a.get("severity") or "unknown",
                        "summary": a.get("summary", ""),
                        "url": a.get("html_url", ""),
                        "published": (a.get("published_at") or "")[:10],
                        "affected": [
                            {
                                "ecosystem": v["package"]["ecosystem"],
                                "package": v["package"]["name"],
                                "vulnerable_range": v.get("vulnerable_version_range") or "",
                                "patched": v.get("first_patched_version"),
                            }
                            for v in a.get("vulnerabilities", [])
                        ],
                    }
                if len(batch) < 100:
                    break
                page += 1
    return sorted(seen.values(), key=lambda r: (r["published"], r["ghsa"]), reverse=True)


def load(path: str | Path | None = None) -> list[dict]:
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))["advisories"]
    text = resources.files("mcp_sdk_audit.data").joinpath("advisories.json").read_text(encoding="utf-8")
    return json.loads(text)["advisories"]


def flatten(records: list[dict]) -> list[Affected]:
    out = []
    for r in records:
        for a in r["affected"]:
            out.append(
                Affected(
                    ghsa=r["ghsa"],
                    cve=r.get("cve"),
                    severity=r["severity"],
                    summary=r["summary"],
                    url=r["url"],
                    ecosystem=a["ecosystem"],
                    package=a["package"],
                    vulnerable_range=a["vulnerable_range"],
                    patched=a.get("patched"),
                )
            )
    return out
