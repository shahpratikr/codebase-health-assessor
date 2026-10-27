import ast
import shutil
from pathlib import Path

import pytest

SRC = Path(__file__).parents[1] / "src"
GATEWAY = "assessor/llm.py"
BANNED_MODULES = ("subprocess", "_posixsubprocess", "claude_agent_sdk", "pty", "asyncio.subprocess")
OS_ALIASES = {"os", "posix", "nt"}
BANNED_OS_CALLS = {"system", "popen", "posix_spawn", "posix_spawnp"}
BANNED_OS_PREFIXES = ("exec", "spawn")
BANNED_ASYNCIO_CALLS = {"create_subprocess_exec", "create_subprocess_shell"}
BANNED_LOOP_CALLS = {"subprocess_exec", "subprocess_shell"}
DYNAMIC_IMPORTERS = {"__import__", "builtins.__import__", "importlib.__import__", "importlib.import_module"}
ATTRIBUTE_GETTERS = {"getattr", "builtins.getattr"}
PRESET_NAMES = (*OS_ALIASES, "asyncio", "builtins", "importlib", "__import__", "getattr")


def _modules(root):
    return sorted(root.rglob("*.py", recurse_symlinks=True))


def _is_banned(name):
    module, _, attr = name.rpartition(".")
    owner = module.rpartition(".")[2]
    return (
        any(name == banned or name.startswith(banned + ".") for banned in BANNED_MODULES)
        or (owner in OS_ALIASES and (attr in BANNED_OS_CALLS or attr.startswith(BANNED_OS_PREFIXES) or attr == "*"))
        or (owner == "asyncio" and attr in {*BANNED_ASYNCIO_CALLS, "*"})
        or attr in BANNED_LOOP_CALLS
    )


def _bindings(tree):
    """Map each imported name, and each of PRESET_NAMES, to the dotted module path it stands for.

    Bindings are per file, not per scope.
    """
    bound = {name: name for name in PRESET_NAMES}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bound[alias.asname] = alias.name
                else:
                    top = alias.name.partition(".")[0]
                    bound[top] = top
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                bound[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return bound


def _dotted(node, bound):
    """Resolve a bound name, an attribute chain on one, or a literal dynamic import to the module path it evaluates to.

    __import__ returns the top-level package of a dotted name, so __import__('os.path') resolves to os.
    """
    if isinstance(node, ast.Name):
        return bound.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value, bound)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Call) and (module := _imported_module(node, bound)):
        return module.partition(".")[0] if _dotted(node.func, bound).endswith("__import__") else module
    return None


def _imported_module(call, bound):
    if _dotted(call.func, bound) in DYNAMIC_IMPORTERS:
        return _text_arg(call, 0, "name")
    return None


def _text_arg(call, position, keyword=None):
    if len(call.args) > position:
        node = call.args[position]
    elif keyword:
        node = next((kw.value for kw in call.keywords if kw.arg == keyword), None)
    else:
        return None
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _referenced_names(tree):
    """Yield (line, dotted name) for imports, resolvable attributes and calls, and literal getattr lookups."""
    bound = _bindings(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.lineno, node.module
            for alias in node.names:
                yield node.lineno, f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Attribute):
            if name := _dotted(node, bound):
                yield node.lineno, name
            if node.attr in BANNED_LOOP_CALLS:
                yield node.lineno, f"loop.{node.attr}"
        elif isinstance(node, ast.Call):
            if module := _imported_module(node, bound):
                yield node.lineno, module
            if node.args and _dotted(node.func, bound) in ATTRIBUTE_GETTERS:
                base, attr = _dotted(node.args[0], bound), _text_arg(node, 1)
                if base and attr:
                    yield node.lineno, f"{base}.{attr}"


def _violations(root):
    """List "path:line: name" for each process-spawning or Agent SDK reference under root.

    Catches imports, attribute chains and literal-string lookups; rebinding (o = os, a walrus, or a nested import
    reusing a module's name), subscripts such as vars(os)['system'] or sys.modules['os'], star imports of importlib,
    eval, exec, compile, runpy and indirect library use are out of reach.
    """
    found = set()
    for path in _modules(root):
        rel = path.relative_to(root).as_posix()
        for line, name in _referenced_names(ast.parse(path.read_bytes(), filename=str(path))):
            if _is_banned(name):
                found.add((rel, line, name))
    return [f"{rel}:{line}: {name}" for rel, line, name in sorted(found)]


@pytest.fixture
def src_copy(tmp_path):
    copy = tmp_path / "src"
    shutil.copytree(SRC, copy, ignore=shutil.ignore_patterns("__pycache__"))
    return copy


def test_src_has_no_process_spawning():
    scanned = [path.relative_to(SRC).as_posix() for path in _modules(SRC)]
    assert "assessor/cli.py" in scanned
    assert _violations(SRC) == []


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        ("import subprocess", "1: subprocess"),
        ("import subprocess as sp", "1: subprocess"),
        ("from subprocess import run", "1: subprocess"),
        ("import claude_agent_sdk", "1: claude_agent_sdk"),
        ("import claude_agent_sdk.types", "1: claude_agent_sdk.types"),
        ("from claude_agent_sdk import query", "1: claude_agent_sdk"),
        ("import pty", "1: pty"),
        ("import asyncio.subprocess", "1: asyncio.subprocess"),
        ("def run():\n    import subprocess", "2: subprocess"),
        ("import importlib\nimportlib.import_module('subprocess')", "2: subprocess"),
        ("from importlib import import_module\nimport_module('claude_agent_sdk')", "2: claude_agent_sdk"),
        ("__import__('subprocess')", "1: subprocess"),
        ("import os\nos.system('claude -p hi')", "2: os.system"),
        ("import os\nos.popen('claude -p hi')", "2: os.popen"),
        ("import os\nos.execv('/bin/claude', ['claude'])", "2: os.execv"),
        ("import os\nos.execlp('claude', 'claude')", "2: os.execlp"),
        ("import os\nos.execvpe('claude', ['claude'], {})", "2: os.execvpe"),
        ("import os\nos.spawnlp(os.P_WAIT, 'claude', 'claude')", "2: os.spawnlp"),
        ("import os\nos.posix_spawn('/bin/claude', ['claude'], {})", "2: os.posix_spawn"),
        ("import os as o\no.system('claude')", "2: os.system"),
        ("import os.path\nos.system('claude')", "2: os.system"),
        ("from os import system", "1: os.system"),
        ("from os import execvp as launch", "1: os.execvp"),
        ("import os\nrun = os.popen", "2: os.popen"),
        ("import os\ngetattr(os, 'system')('claude')", "2: os.system"),
        ("import os\ngetattr(os, 'popen', None)", "2: os.popen"),
        ("__import__('subprocess', globals(), locals(), [], 0)", "1: subprocess"),
        ("import builtins\nbuiltins.__import__('pty')", "2: pty"),
        ("import importlib\nimportlib.__import__('subprocess')", "2: subprocess"),
        ("from os import *", "1: os.*"),
        ("from asyncio import *", "1: asyncio.*"),
        ("__import__('os').system('claude -p hi')", "1: os.system"),
        ("import importlib\nimportlib.import_module('os').system('claude')", "2: os.system"),
        ("getattr(__import__('os'), 'system')('claude')", "1: os.system"),
        ("__import__(name='subprocess')", "1: subprocess"),
        ("import importlib\nimportlib.import_module(name='subprocess')", "2: subprocess"),
        ("from importlib import import_module as load\nload('subprocess')", "2: subprocess"),
        ("os.system('claude')", "1: os.system"),
        ("nt.system('claude')", "1: nt.system"),
        ("posix.system('claude')", "1: posix.system"),
        ("asyncio.create_subprocess_exec('claude')", "1: asyncio.create_subprocess_exec"),
        ("builtins.__import__('pty')", "1: pty"),
        ("importlib.import_module('subprocess')", "1: subprocess"),
        ("__import__('os.path').system('claude')", "1: os.system"),
        ("getattr(__import__('os.path'), 'system')('claude')", "1: os.system"),
        ("__import__('asyncio.subprocess')", "1: asyncio.subprocess"),
        ("builtins.__import__('os.path').system('claude')", "1: os.system"),
        ("import importlib\nimportlib.__import__('os.path').system('claude')", "2: os.system"),
        ("import _posixsubprocess", "1: _posixsubprocess"),
        ("import builtins\nbuiltins.getattr(os, 'system')('claude')", "2: os.system"),
        ("from builtins import getattr as lookup\nlookup(os, 'popen')", "2: os.popen"),
        ("import shutil\nshutil.os.system('claude')", "2: shutil.os.system"),
        ("import os.path as p\np.os.execv('/bin/claude', ['claude'])", "2: os.path.os.execv"),
        ("import asyncio\nasyncio.get_event_loop().subprocess_exec(None, 'claude')", "2: loop.subprocess_exec"),
        ("async def run(loop):\n    await loop.subprocess_shell(None, 'claude')", "2: loop.subprocess_shell"),
        ("from .compat import os\nos.system('claude')", "2: os.system"),
        ("import nt\nnt.system('claude')", "2: nt.system"),
        ("import os\nos.posix_spawnp('claude', ['claude'], {})", "2: os.posix_spawnp"),
        ("import posix\nposix.system('claude')", "2: posix.system"),
        ("import asyncio\nasyncio.create_subprocess_exec('claude')", "2: asyncio.create_subprocess_exec"),
        ("from asyncio import create_subprocess_shell", "1: asyncio.create_subprocess_shell"),
        ("from asyncio import subprocess as aio_subprocess", "1: asyncio.subprocess"),
    ],
)
def test_detects_planted_violation(src_copy, planted, expected):
    (src_copy / "assessor" / "planted.py").write_text(planted + "\n")
    assert f"assessor/planted.py:{expected}" in _violations(src_copy)


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        ("import os\nimport subprocess\n\nos.system('claude')\n", ["2: subprocess", "4: os.system"]),
        (
            "import claude_agent_sdk.types\nclaude_agent_sdk.query()\n",
            ["1: claude_agent_sdk.types", "2: claude_agent_sdk.query"],
        ),
    ],
)
def test_reports_every_violation_in_a_module(src_copy, planted, expected):
    (src_copy / "assessor" / "planted.py").write_text(planted)
    assert _violations(src_copy) == [f"assessor/planted.py:{line}" for line in expected]


def test_scans_nested_packages(src_copy):
    nested = src_copy / "assessor" / "tools" / "deep"
    nested.mkdir(parents=True)
    (nested / "launcher.py").write_text("import subprocess\n")
    assert _violations(src_copy) == ["assessor/tools/deep/launcher.py:1: subprocess"]


def test_scans_symlinked_packages(src_copy, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "launcher.py").write_text("import subprocess\n")
    (src_copy / "assessor" / "linked").symlink_to(outside, target_is_directory=True)
    assert _violations(src_copy) == ["assessor/linked/launcher.py:1: subprocess"]


def test_ignores_lookalikes(src_copy):
    (src_copy / "assessor" / "lookalikes.py").write_text(
        '"""import subprocess; os.system("x")"""\n'
        "# import subprocess\n"
        "import asyncio\n"
        "import importlib\n"
        "import os\n"
        "import subprocess_tools\n"
        "from . import subprocess\n"
        "from .tools import pty\n"
        "from .os import system\n"
        "from ..subprocess import run\n"
        "def read(pty):\n"
        "    return pty.read()\n"
        "getattr(os, 'getcwd', None)\n"
        "class Holder:\n"
        "    def reach(self):\n"
        "        return self.os.system, self.asyncio.create_subprocess_exec\n"
        "importlib.import_module('os.path')\n"
        "os.path.join('a', 'b')\n"
        "os.environ.get('HOME')\n"
        "getattr(os, 'getcwd')()\n"
        "importlib.import_module('json')\n"
        "asyncio.run(None)\n"
        "label = 'subprocess'\n"
    )
    assert _violations(src_copy) == []


def _anthropic_references(root):
    """List "path:line: name" for each anthropic reference in a module other than assessor/llm.py."""
    found = set()
    for path in _modules(root):
        rel = path.relative_to(root).as_posix()
        for line, name in _referenced_names(ast.parse(path.read_bytes(), filename=str(path))):
            if rel != GATEWAY and (name == "anthropic" or name.startswith("anthropic.")):
                found.add((rel, line, name))
    return [f"{rel}:{line}: {name}" for rel, line, name in sorted(found)]


def test_only_the_gateway_imports_anthropic():
    gateway_names = {name for _, name in _referenced_names(ast.parse((SRC / GATEWAY).read_bytes()))}
    assert "anthropic" in gateway_names
    assert _anthropic_references(SRC) == []


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        ("import anthropic", "1: anthropic"),
        ("import anthropic as sdk", "1: anthropic"),
        ("import anthropic.types", "1: anthropic.types"),
        ("from anthropic import Anthropic", "1: anthropic"),
        ("from anthropic.types.beta import BetaMessage", "1: anthropic.types.beta"),
        ("def call():\n    import anthropic", "2: anthropic"),
        ("import importlib\nimportlib.import_module('anthropic')", "2: anthropic"),
        ("__import__('anthropic')", "1: anthropic"),
        ("import anthropic as sdk\nsdk.Anthropic()", "2: anthropic.Anthropic"),
    ],
)
def test_detects_planted_anthropic_import(src_copy, planted, expected):
    (src_copy / "assessor" / "planted.py").write_text(planted + "\n")
    assert f"assessor/planted.py:{expected}" in _anthropic_references(src_copy)


def test_only_the_top_level_gateway_is_exempt(src_copy):
    nested = src_copy / "assessor" / "agents"
    nested.mkdir(exist_ok=True)
    (nested / "llm.py").write_text("import anthropic\n")
    assert _anthropic_references(src_copy) == ["assessor/agents/llm.py:1: anthropic"]


def test_anthropic_lookalikes_are_not_imports(src_copy):
    (src_copy / "assessor" / "lookalikes.py").write_text(
        '"""import anthropic"""\n'
        "# import anthropic\n"
        "import anthropic_tools\n"
        "from . import anthropic\n"
        "from .llm import call\n"
        "label = 'anthropic'\n"
    )
    assert _anthropic_references(src_copy) == []


def test_unparsable_module_fails_scan(src_copy):
    (src_copy / "assessor" / "broken.py").write_text("def broken(:\n")
    with pytest.raises(SyntaxError):
        _violations(src_copy)
