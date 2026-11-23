import json
from pathlib import Path

import pytest

from mcp_sdk_audit import advisories
from mcp_sdk_audit.cli import main
from mcp_sdk_audit.rules import mask, scan_source
from mcp_sdk_audit.scanner import scan
from mcp_sdk_audit.versions import Version, in_range

FX = Path(__file__).parent / "fixtures"
RECORDS = advisories.load()


# ---------------------------------------------------------------- versions


@pytest.mark.parametrize(
    "a,b",
    [
        ("1.9.0", "1.10.0"),
        ("2.0.0a1", "2.0.0"),
        ("2.0.0a1", "2.0.0b1"),
        ("2.0.0rc1", "2.0.0"),
        ("1.2.0-beta.1", "1.2.0"),
        ("v1.3.0", "1.3.1"),
        ("1.27.1", "1.27.2"),
    ],
)
def test_version_order(a, b):
    assert Version(a) < Version(b)


def test_version_padding():
    assert Version("1.2") == Version("1.2.0")


@pytest.mark.parametrize(
    "v,spec,expected",
    [
        ("1.25.1", ">= 1.10.0, < 1.30.1", True),
        ("1.30.1", ">= 1.10.0, < 1.30.1", False),
        ("1.9.9", ">= 1.10.0, < 1.30.1", False),
        ("1.4.0", "<= 1.4.0", True),
        ("2.0.0a1", ">= 2.0.0a1, < 2.2.0", True),
        ("1.29.1", ">= 2.0.0a1, < 2.2.0", False),
        ("1.2.3", "= 1.2.3", True),
    ],
)
def test_in_range(v, spec, expected):
    assert in_range(v, spec) is expected


# ---------------------------------------------------------------- snapshot


def test_snapshot_shape():
    assert len(RECORDS) >= 20
    for r in RECORDS:
        assert r["ghsa"].startswith("GHSA-")
        assert r["affected"]
        for a in r["affected"]:
            assert a["ecosystem"] in {"npm", "pip", "go", "rust", "rubygems", "composer"}
            in_range("1.0.0", a["vulnerable_range"])  # every range must parse


# ---------------------------------------------------------------- lockfiles


def _deps(path):
    return {(d.package, d.version) for d in scan(path, RECORDS, source=False).deps}


def test_lockfiles_parsed():
    deps = _deps(FX / "locks")
    assert ("@modelcontextprotocol/sdk", "1.20.2") in deps  # pnpm v9 with peer suffix
    assert ("@modelcontextprotocol/client", "2.1.0") in deps  # pnpm
    assert ("@modelcontextprotocol/sdk", "1.11.0") in deps  # yarn v1 multi-spec header
    assert ("mcp", "2.1.0") in deps  # Pipfile.lock


def test_vulnerable_tree():
    r = scan(FX / "vulnerable", RECORDS)
    assert {(d.package, d.version) for d in r.deps} == {
        ("@modelcontextprotocol/sdk", "1.25.1"),
        ("mcp", "1.27.0"),
        ("github.com/modelcontextprotocol/go-sdk", "1.3.0"),
    }
    ghsas = {v.advisory.ghsa for v in r.vulnerable}
    assert {"GHSA-345p-7cg4-v4c7", "GHSA-qx49-fqc8-xw99", "GHSA-xw59-hvm2-8pj6"} <= ghsas
    rules = {f.rule.id for f in r.findings}
    assert rules == {"MCPA001", "MCPA002", "MCPA003", "MCPA004", "MCPA005", "MCPA101", "MCPA102", "MCPA103", "MCPA104"}


def test_fixed_tree_is_clean():
    r = scan(FX / "fixed", RECORDS)
    assert len(r.deps) == 2
    assert r.vulnerable == []
    assert r.findings == [], [(f.rule.id, f.file, f.line) for f in r.findings]


def test_patched_version_still_flags_code():
    """The point of the tool: a patched SDK with unpatched config is still reported."""
    src = 'const p = new ClientCredentialsProvider({ clientId: "a", clientSecret: s }); // mcp'
    assert [f.rule.id for f in scan_source("x.ts", src, ".ts")] == ["MCPA001"]


# ---------------------------------------------------------------- rule edge cases


def test_mask_keeps_offsets():
    src = 'a = "x(y)" # c(\nb = 1\n'
    m = mask(src, "py")
    assert len(m) == len(src)
    assert "(" not in m.split("\n")[0][4:]


def test_commented_code_ignored():
    src = "// const t = new StreamableHTTPServerTransport({});\napp.post('/mcp', h) // mcp\n"
    assert scan_source("a.ts", src, ".ts") == []


def test_spread_args_not_flagged():
    src = "const p = new PrivateKeyJwtProvider({ ...opts }); // mcp"
    assert scan_source("a.ts", src, ".ts") == []


def test_py_kwargs_not_flagged():
    src = "from mcp import x\np = ClientCredentialsOAuthProvider(**cfg)\n"
    assert scan_source("a.py", src, ".py") == []


def test_transport_in_handler_not_flagged():
    src = (
        "import { McpServer } from '@modelcontextprotocol/sdk';\n"
        "app.post('/mcp', async (req, res) => {\n"
        "  const t = new StreamableHTTPServerTransport({});\n"
        "});\n"
    )
    assert scan_source("a.ts", src, ".ts") == []


def test_top_level_server_connected_once_not_flagged():
    src = "const server = new McpServer({});\nawait server.connect(new StdioServerTransport()); // mcp\n"
    assert scan_source("a.ts", src, ".ts") == []


def test_express_without_rebinding_protection():
    src = (
        "import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk';\n"
        "const app = express();\n"
        "app.post('/mcp', async (req, res) => { const t = new StreamableHTTPServerTransport({}); });\n"
    )
    assert [f.rule.id for f in scan_source("a.ts", src, ".ts")] == ["MCPA007"]


def test_task_store():
    src = "const server = new McpServer({ name: 'x' }, { taskStore: new InMemoryTaskStore() });"
    assert [f.rule.id for f in scan_source("a.ts", src, ".ts")] == ["MCPA006"]


# ---------------------------------------------------------------- cli


def test_cli_exit_codes(capsys):
    assert main([str(FX / "vulnerable"), "--no-color"]) == 1
    assert main([str(FX / "fixed")]) == 0
    assert main([str(FX / "vulnerable"), "--fail-on", "none"]) == 0
    capsys.readouterr()


def test_cli_json(capsys):
    main([str(FX / "vulnerable"), "-f", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["tool"] == "mcp-sdk-audit"
    assert len(data["findings"]) == 9


def test_cli_sarif(tmp_path):
    out = tmp_path / "r.sarif"
    main([str(FX / "vulnerable"), "-f", "sarif", "-o", str(out)])
    sarif = json.loads(out.read_text())
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(res["ruleId"] in rule_ids for res in run["results"])
    assert all(res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for res in run["results"])


def test_cli_list_rules(capsys):
    assert main(["--list-rules"]) == 0
    assert "MCPA001" in capsys.readouterr().out


def test_cli_missing_path():
    assert main(["does/not/exist"]) == 2


# ---------------------------------------------------------------- false-positive regressions (from real repos)


def test_definitions_not_flagged():
    ts = "export function requireBearerAuth(options) { return verifyBearerToken(h, options); } // mcp"
    py = "from mcp import x\nclass AuthSettings(BaseModel):\n    pass\nclass ClientCredentialsOAuthProvider(Base):\n    pass\n"
    assert scan_source("a.ts", ts, ".ts") == []  # definition skipped; inner call passes opaque options
    assert scan_source("a.py", py, ".py") == []


def test_stateful_module_transport_not_flagged():
    src = (
        "import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';\n"
        "const transport = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });\n"
        "app.post('/mcp', (req, res) => transport.handleRequest(req, res));\n"
    )
    assert scan_source("a.ts", src, ".ts") == []


def test_in_memory_connect_not_flagged():
    src = (
        "const server = new McpServer({ name: 'x' }); // mcp\n"
        "app.get('/health', (q, r) => r.send('ok'));\n"
        "async function main() { await server.connect(serverTransport_InMemory); }\n"
        "await Promise.all([server.connect(new StdioServerTransport())]);\n"
    )
    assert scan_source("a.ts", src, ".ts") == []


def test_follow_redirects_outside_mcp_client_not_flagged():
    src = "from mcp.server.fastmcp import FastMCP\nhttpx.AsyncClient(follow_redirects=True)\n"
    assert scan_source("a.py", src, ".py") == []


def test_positional_security_settings():
    src = "from mcp.server.sse import SseServerTransport\nt = SseServerTransport('/messages/', security_settings)\n"
    assert scan_source("a.py", src, ".py") == []


def test_test_files_skipped_by_default(tmp_path):
    (tmp_path / "tests").mkdir()
    bad = "const p = new ClientCredentialsProvider({ clientId: 'a' }); // mcp\n"
    (tmp_path / "tests" / "x.ts").write_text(bad)
    (tmp_path / "auth.test.ts").write_text(bad)
    (tmp_path / "src.ts").write_text(bad)
    assert [f.file for f in scan(tmp_path, RECORDS).findings] == ["src.ts"]
    assert len(scan(tmp_path, RECORDS, include_tests=True).findings) == 3


def test_more_lockfiles(tmp_path):
    (tmp_path / "berry").mkdir()
    (tmp_path / "berry" / "yarn.lock").write_text(
        '__metadata:\n  version: 8\n\n"@modelcontextprotocol/sdk@npm:^1.20.0":\n  version: 1.24.3\n  resolution: "x"\n'
    )
    (tmp_path / "bun").mkdir()
    (tmp_path / "bun" / "bun.lock").write_text(
        '{\n  "packages": {\n    "@modelcontextprotocol/sdk": ["@modelcontextprotocol/sdk@1.31.0", "", {}, "sha512-x"]\n  }\n}\n'
    )
    (tmp_path / "poetry").mkdir()
    (tmp_path / "poetry" / "poetry.lock").write_text('[[package]]\nname = "mcp"\nversion = "1.29.1"\n')
    (tmp_path / "req").mkdir()
    (tmp_path / "req" / "requirements-dev.txt").write_text("mcp[cli]==1.22.0 ; python_version >= '3.11'\nmcpx==9.9.9\n")
    (tmp_path / "gomod").mkdir()
    (tmp_path / "gomod" / "go.mod").write_text("module x\n\nrequire github.com/modelcontextprotocol/go-sdk v1.4.1 // indirect\n")
    assert _deps(tmp_path) == {
        ("@modelcontextprotocol/sdk", "1.24.3"),
        ("@modelcontextprotocol/sdk", "1.31.0"),
        ("mcp", "1.29.1"),
        ("mcp", "1.22.0"),
        ("github.com/modelcontextprotocol/go-sdk", "1.4.1"),
    }


def test_rust_ruby_php_inspector_lockfiles(tmp_path):
    (tmp_path / "rs").mkdir()
    (tmp_path / "rs" / "Cargo.lock").write_text(
        'version = 4\n\n[[package]]\nname = "rmcp"\nversion = "0.8.5"\nsource = "registry+x"\n\n'
        '[[package]]\nname = "rmcp-macros"\nversion = "0.8.5"\n\n[[package]]\nname = "rmcpx"\nversion = "9.9.9"\n'
    )
    (tmp_path / "rb").mkdir()
    (tmp_path / "rb" / "Gemfile.lock").write_text(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    json-schema (5.1.0)\n    mcp (0.4.0)\n      json-schema (>= 4.1)\n"
        "    mcp-client (1.0.0)\n\nDEPENDENCIES\n  mcp (~> 0.4)\n"
    )
    (tmp_path / "php").mkdir()
    (tmp_path / "php" / "composer.lock").write_text(
        json.dumps(
            {
                "packages": [{"name": "mcp/sdk", "version": "v0.6.0"}, {"name": "acme/mcp", "version": "1.0.0"}],
                "packages-dev": [{"name": "mcp/sdk", "version": "dev-main"}],
            }
        )
    )
    (tmp_path / "js").mkdir()
    (tmp_path / "js" / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"node_modules/@modelcontextprotocol/inspector": {"version": "0.16.2"}}})
    )
    deps = scan(tmp_path, RECORDS, source=False).deps
    assert {(d.ecosystem, d.package, d.version) for d in deps} == {
        ("rust", "rmcp", "0.8.5"),
        ("rubygems", "mcp", "0.4.0"),
        ("composer", "mcp/sdk", "0.6.0"),
        ("npm", "@modelcontextprotocol/inspector", "0.16.2"),
    }
    rust = next(d for d in deps if d.ecosystem == "rust")
    assert (rust.file, rust.line) == ("rs/Cargo.lock", 4)


def test_new_ecosystems_match_advisories(tmp_path):
    # Ranges copied from the published advisories, so matching works before the snapshot refresh lands.
    def rec(ghsa, eco, pkg, rng):
        return {
            "ghsa": ghsa,
            "cve": None,
            "severity": "high",
            "summary": "",
            "url": "",
            "published": "2026-11-01",
            "affected": [{"ecosystem": eco, "package": pkg, "vulnerable_range": rng, "patched": None}],
        }

    records = [
        rec("GHSA-c9f9-cp8h-jcj5", "rust", "rmcp", ">= 0.2.0, < 3.9.0"),
        rec("GHSA-rjr6-rcgv-9m7m", "rubygems", "mcp", "< 0.23.0"),
        rec("GHSA-7m52-jw36-44r3", "composer", "mcp/sdk", ">= 0.5.0, < 0.7.1"),
        rec("GHSA-g9hg-qhmf-q45m", "npm", "@modelcontextprotocol/inspector", "< 0.16.6"),
        rec("GHSA-xxxx-wrong-eco", "pip", "mcp", "< 99.0.0"),  # gem "mcp" must not match the PyPI package
    ]
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "rmcp"\nversion = "3.8.0"\n')
    (tmp_path / "Gemfile.lock").write_text("GEM\n  specs:\n    mcp (0.22.1)\n")
    (tmp_path / "composer.lock").write_text(json.dumps({"packages": [{"name": "mcp/sdk", "version": "v0.7.1"}]}))
    hits = {v.advisory.ghsa for v in scan(tmp_path, records, source=False).vulnerable}
    assert hits == {"GHSA-c9f9-cp8h-jcj5", "GHSA-rjr6-rcgv-9m7m"}
