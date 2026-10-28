"""Python side of the runtime-majority report.

Scope is a static import-graph closure (``ast``) from reviewed runtime root
modules.  Edges are classified ``eager`` (executed at import time) or ``lazy``
(inside a function/lambda, or an ``importlib.import_module`` call).  A
dynamic import resolves when its module argument is a string the source fixes:
a literal, a conditional between literals, a name bound to one of those, a loop
variable drawn from a module-level literal table, or the parameter of a
module-private helper every caller passes a literal to.  Anything else is
counted unresolved and must be declared in the scope contract.
Imports under ``if TYPE_CHECKING`` are not runtime edges.  Reviewed exclusions
prune a module and everything reachable only through it.  LOC counts physical
lines holding at least one non-comment token (docstrings count).
"""

from __future__ import annotations

import ast
import fnmatch
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.ci.runtime_majority_functions import ModulePlan, counted_lines, is_type_checking_test


@dataclass
class PythonModule:
    """One module file under the package root."""

    name: str
    path: str
    is_package: bool
    loc: int


@dataclass
class ImportGraph:
    """Dotted-name keyed module table and edge sets."""

    modules: dict[str, PythonModule]
    eager: dict[str, set[str]] = field(default_factory=dict)
    lazy: dict[str, set[str]] = field(default_factory=dict)
    dynamic_unresolved: dict[str, int] = field(default_factory=dict)


def count_python_loc(source: str) -> int:
    return len(counted_lines(source))


def discover_modules(
    repo: Path, package_root: str, plans: dict[str, ModulePlan] | None = None
) -> dict[str, PythonModule]:
    root = repo / package_root
    top = root.name
    modules: dict[str, PythonModule] = {}
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        parts = list(relative.with_suffix("").parts)
        is_package = parts[-1] == "__init__"
        if is_package:
            parts = parts[:-1]
        name = ".".join([top, *parts]) if parts else top
        relative_path = path.relative_to(repo).as_posix()
        plan = (plans or {}).get(relative_path)
        counted = counted_lines(path.read_text(encoding="utf-8"))
        modules[name] = PythonModule(
            name=name,
            path=relative_path,
            is_package=is_package,
            loc=len(counted - plan.removed_lines) if plan else len(counted),
        )
    return modules


def _literal_package(node: ast.expr, module: PythonModule) -> str | None:
    """Package anchor of a relative ``import_module`` call, when statically known."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id == "__package__":
        return module.name if module.is_package else module.name.rpartition(".")[0]
    if isinstance(node, ast.Name) and node.id == "__name__":
        return module.name
    return None


def _literal_strings(node: ast.expr, env: dict[str, set[str] | None]) -> set[str] | None:
    """Every string ``node`` can evaluate to, or ``None`` when the source leaves it open."""
    if isinstance(node, ast.Constant):
        return {node.value} if isinstance(node.value, str) else None
    if isinstance(node, ast.IfExp):
        body = _literal_strings(node.body, env)
        orelse = _literal_strings(node.orelse, env)
        return None if body is None or orelse is None else body | orelse
    if isinstance(node, ast.Name):
        return env.get(node.id)
    return None


def _literal_tables(tree: ast.Module) -> dict[str, list[ast.expr]]:
    """Module-level names bound exactly once to a literal tuple or list."""
    tables: dict[str, list[ast.expr]] = {}
    seen: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            name, value = stmt.targets[0].id, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            name, value = stmt.target.id, stmt.value
        else:
            continue
        if name in seen:
            tables.pop(name, None)
            continue
        seen.add(name)
        if isinstance(value, (ast.Tuple, ast.List)):
            tables[name] = list(value.elts)
    return tables


def _column_values(rows: list[set[str] | None]) -> set[str] | None:
    """Union of one column of candidate values, or ``None`` if any row is open."""
    if not rows or any(row is None for row in rows):
        return None
    result: set[str] = set()
    for row in rows:
        result |= row or set()
    return result


def _calls_by_name(tree: ast.Module) -> dict[str, list[tuple[ast.Call, bool]]]:
    """Every ``name(...)`` call in the module, paired with whether it runs at import time."""
    calls: dict[str, list[tuple[ast.Call, bool]]] = {}

    def walk(node: ast.AST, eager: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                calls.setdefault(child.func.id, []).append((child, eager))
            nested = eager and not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
            walk(child, nested)

    walk(tree, True)
    return calls


def _wrapper_literals(tree: ast.Module) -> dict[str, dict[str, Any]]:
    """Parameters of module-private helpers that every call site fixes to literals.

    A helper whose name appears only as the callee of a call in its own module
    cannot be reached with other arguments, so its parameters are known to be
    exactly the literals those call sites pass.  ``mode`` is ``eager`` when any
    call site runs at import time, because the helper's imports then run too.
    """
    functions = {
        stmt.name: stmt
        for stmt in tree.body
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name.startswith("_")
    }
    if not functions:
        return {}
    calls = _calls_by_name(tree)
    callee_ids = {id(call.func) for sites in calls.values() for call, _ in sites}
    escaped = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id in functions and id(node) not in callee_ids
    }
    bindings: dict[str, dict[str, Any]] = {}
    for name, function in functions.items():
        sites = calls.get(name, [])
        spec = function.args
        if name in escaped or not sites or spec.posonlyargs or spec.kwonlyargs or spec.vararg or spec.kwarg:
            continue
        params = [argument.arg for argument in spec.args]
        columns: list[list[set[str] | None]] = [[] for _ in params]
        if any(
            call.keywords or len(call.args) != len(params) or any(isinstance(item, ast.Starred) for item in call.args)
            for call, _ in sites
        ):
            continue
        for call, _ in sites:
            for index, argument in enumerate(call.args):
                columns[index].append(_literal_strings(argument, {}))
        resolved = {param: values for param, column in zip(params, columns) if (values := _column_values(column)) is not None}
        if resolved:
            bindings[name] = {"params": resolved, "mode": "eager" if any(eager for _, eager in sites) else "lazy"}
    return bindings


def _absolute_name(name: str, package: str | None) -> str | None:
    if not name.startswith("."):
        return name
    if not package:
        return None
    level = len(name) - len(name.lstrip("."))
    base = package.split(".")
    if level - 1 >= len(base):
        return None
    return ".".join([*base[: len(base) - (level - 1)], name.lstrip(".")]).rstrip(".")


class _ImportCollector(ast.NodeVisitor):
    def __init__(self, module: PythonModule, skip_linenos: set[int] | None = None) -> None:
        self.module = module
        self._skip_linenos = skip_linenos or set()
        self.found: list[tuple[str, str, int, tuple[str, ...]]] = []
        self.dynamic_unresolved = 0
        self._function_depth = 0
        self._tables: dict[str, list[ast.expr]] = {}
        self._wrappers: dict[str, dict[str, Any]] = {}
        self._env: list[dict[str, set[str] | None]] = [{}]
        self._assigned: list[set[str]] = [set()]
        self._modes: list[str | None] = [None]

    def _lookup(self) -> dict[str, set[str] | None]:
        merged: dict[str, set[str] | None] = {}
        for scope in self._env:
            merged.update(scope)
        return merged

    def _dynamic_mode(self) -> str:
        for mode in reversed(self._modes):
            if mode is not None:
                return mode
        return "lazy"

    def _push(self, scope: dict[str, set[str] | None], mode: str | None) -> None:
        self._env.append(scope)
        self._assigned.append(set())
        self._modes.append(mode)

    def _pop(self) -> None:
        self._env.pop()
        self._assigned.pop()
        self._modes.pop()

    def _mode(self) -> str:
        return "lazy" if self._function_depth else "eager"

    def visit(self, node: ast.AST) -> None:
        """Skip statements removed by a reviewed function-level exclusion."""
        if isinstance(node, ast.stmt) and node.lineno in self._skip_linenos:
            return
        super().visit(node)

    def visit_Module(self, node: ast.Module) -> None:
        self._tables = _literal_tables(node)
        self._wrappers = _wrapper_literals(node)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        if is_type_checking_test(node.test):
            for child in node.orelse:
                self.visit(child)
            return
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        wrapper = self._wrappers.get(getattr(node, "name", ""))
        self._function_depth += 1
        self._push(dict(wrapper["params"]) if wrapper else {}, wrapper["mode"] if wrapper else None)
        self.generic_visit(node)
        self._pop()
        self._function_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef  # noqa: N815
    visit_Lambda = visit_FunctionDef  # type: ignore[assignment]  # noqa: N815

    def _bind(self, target: ast.expr, value: ast.expr) -> None:
        """Record what a single-name assignment leaves the name holding."""
        if not isinstance(target, ast.Name):
            return
        scope, assigned = self._env[-1], self._assigned[-1]
        if target.id in assigned:
            scope[target.id] = None  # assigned more than once: no single static value
            return
        assigned.add(target.id)
        scope[target.id] = _literal_strings(value, self._lookup())

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        if len(node.targets) == 1:
            self._bind(node.targets[0], node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        if node.value is not None:
            self._bind(node.target, node.value)

    def _loop_bindings(self, node: ast.For | ast.AsyncFor) -> dict[str, set[str] | None]:
        """Loop variables drawn from a literal table, resolved by tuple position."""
        if isinstance(node.iter, ast.Name):
            elements = self._tables.get(node.iter.id)
        elif isinstance(node.iter, (ast.Tuple, ast.List)):
            elements = list(node.iter.elts)
        else:
            elements = None
        if not elements:
            return {}
        if isinstance(node.target, ast.Name):
            values = _column_values([_literal_strings(element, {}) for element in elements])
            return {node.target.id: values}
        if not isinstance(node.target, ast.Tuple) or not all(isinstance(item, ast.Name) for item in node.target.elts):
            return {}
        width = len(node.target.elts)
        columns: list[list[set[str] | None]] = [[] for _ in range(width)]
        for element in elements:
            if not isinstance(element, (ast.Tuple, ast.List)) or len(element.elts) != width:
                return {}
            for index, item in enumerate(element.elts):
                columns[index].append(_literal_strings(item, {}))
        return {name.id: _column_values(column) for name, column in zip(node.target.elts, columns)}

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._push(self._loop_bindings(node), None)
        for child in node.body:
            self.visit(child)
        self._pop()
        for child in node.orelse:
            self.visit(child)

    visit_AsyncFor = visit_For  # type: ignore[assignment]  # noqa: N815

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.found.append((self._mode(), alias.name, 0, ()))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.found.append((self._mode(), node.module or "", node.level, tuple(alias.name for alias in node.names)))

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name in {"import_module", "__import__"} and node.args:
            arg = node.args[0]
            package_node = node.args[1] if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg == "package":
                    package_node = keyword.value
            package = _literal_package(package_node, self.module) if package_node is not None else None
            names = _literal_strings(arg, self._lookup())
            targets = [_absolute_name(item, package) for item in sorted(names)] if names else []
            if targets and all(targets):
                mode = self._dynamic_mode()
                for target in targets:
                    self.found.append((mode, target or "", 0, ()))
            else:
                self.dynamic_unresolved += 1
        self.generic_visit(node)


def _expand(modules: dict[str, PythonModule], target: str) -> set[str]:
    """A module plus the parent packages whose ``__init__`` also executes."""
    result: set[str] = set()
    parts = target.split(".")
    for index in range(1, len(parts) + 1):
        candidate = ".".join(parts[:index])
        if candidate in modules:
            result.add(candidate)
    return result if target in modules else set()


def _resolve(module: PythonModule, mode_found: tuple[str, str, int, tuple[str, ...]], modules: dict[str, PythonModule]):
    mode, name, level, names = mode_found
    if level:
        package_parts = module.name.split(".")
        if not module.is_package:
            package_parts = package_parts[:-1]
        base = package_parts[: len(package_parts) - (level - 1)]
        full = ".".join([*base, *([name] if name else [])])
    else:
        full = name
    targets = set(_expand(modules, full))
    if names or level:
        for item in names:
            if item != "*":
                targets |= _expand(modules, f"{full}.{item}")
    return mode, targets


def build_graph(repo: Path, package_root: str, plans: dict[str, ModulePlan] | None = None) -> ImportGraph:
    modules = discover_modules(repo, package_root, plans)
    graph = ImportGraph(modules=modules)
    for name, module in modules.items():
        source = (repo / module.path).read_text(encoding="utf-8")
        plan = (plans or {}).get(module.path)
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        collector = _ImportCollector(module, plan.skip_linenos if plan else None)
        collector.visit(tree)
        graph.eager[name], graph.lazy[name] = set(), set()
        graph.dynamic_unresolved[name] = collector.dynamic_unresolved
        for found in collector.found:
            mode, targets = _resolve(module, found, modules)
            targets.discard(name)
            (graph.eager if mode == "eager" else graph.lazy)[name].update(targets)
        # A package's own __init__ executes before any submodule runs.
        if name.count("."):
            parent = name.rsplit(".", 1)[0]
            if parent in modules:
                graph.eager[name].add(parent)
    return graph


DYNAMIC_RESOLUTIONS = frozenset({"external", "follow", "unfollowed"})


def validate_dynamic_imports(entries: list[dict[str, Any]]) -> None:
    """Reject malformed ``dynamic_imports`` entries (raises ``ValueError``)."""
    seen: set[str] = set()
    for entry in entries:
        path = entry.get("path")
        if not isinstance(path, str) or not path or path in seen:
            raise ValueError(f"dynamic import entry needs one unique path string: {path!r}")
        seen.add(path)
        count = entry.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError(f"dynamic import entry {path!r} needs a positive integer count")
        if entry.get("resolution") not in DYNAMIC_RESOLUTIONS:
            raise ValueError(f"dynamic import entry {path!r} resolution must be one of {sorted(DYNAMIC_RESOLUTIONS)}")
        if not str(entry.get("evidence", "")).strip():
            raise ValueError(f"dynamic import entry {path!r} needs evidence")
        targets = entry.get("targets", [])
        if entry["resolution"] != "external" and not (
            isinstance(targets, list) and targets and all(isinstance(item, str) and item for item in targets)
        ):
            raise ValueError(f"dynamic import entry {path!r} needs a target module list")
        if entry.get("mode", "lazy") not in {"eager", "lazy"}:
            raise ValueError(f"dynamic import entry {path!r} mode must be eager or lazy")


def apply_dynamic_imports(graph: ImportGraph, entries: list[dict[str, Any]]) -> None:
    """Add the declared targets of ``follow`` entries as edges from the declaring module.

    ``external`` (stdlib or third-party) and ``unfollowed`` (reviewed decision
    not to count the targets) add nothing; an unfollowed target is in scope
    only if a static import reaches it. Every declared target must resolve to a
    module (raises ``ValueError``), so a misspelled target cannot shrink the scope.
    """
    by_path = {module.path: module for module in graph.modules.values()}
    for entry in entries:
        module = by_path.get(entry["path"])
        if module is None or entry["resolution"] not in {"follow", "unfollowed"}:
            continue
        package = module.name if module.is_package else module.name.rpartition(".")[0]
        edges = graph.eager if entry.get("mode") == "eager" else graph.lazy
        for target in entry["targets"]:
            name = _absolute_name(target, package)
            resolved = _expand(graph.modules, name) if name else set()
            if not resolved:
                raise ValueError(f"dynamic import entry {entry['path']!r}: target {target!r} resolves to no module")
            if entry["resolution"] == "follow":
                edges.setdefault(module.name, set()).update(resolved - {module.name})


def undeclared_dynamic_sites(graph: ImportGraph, in_scope: dict[str, str], entries: list[dict[str, Any]]) -> list[str]:
    """Declarations that disagree with the graph.

    An in-scope module's unresolved dynamic import count must equal its declared
    count, including zero, so a declaration cannot outlive its last import site.
    A declared path must name a module.
    """
    declared = {entry["path"]: entry["count"] for entry in entries}
    known = {module.path for module in graph.modules.values()}
    problems = [f"{path}: declared dynamic import entry names no module" for path in sorted(set(declared) - known)]
    for name in sorted(in_scope):
        found = graph.dynamic_unresolved.get(name, 0)
        path = graph.modules[name].path
        if found != declared.get(path, 0):
            problems.append(f"{path}: {found} non-literal import site(s), declared {declared.get(path, 0)}")
    return problems


def path_matches(path: str, entry: dict[str, Any]) -> bool:
    patterns = entry["path"] if isinstance(entry["path"], list) else [entry["path"]]
    return any(fnmatch.fnmatchcase(path, str(pattern)) for pattern in patterns)


def _walk(
    graph: ImportGraph, roots: list[str], exclusions: list[dict[str, Any]], *, use_lazy: bool
) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    parent: dict[str, str] = {root: "" for root in roots if root in graph.modules}
    excluded: dict[str, dict[str, Any]] = {}
    queue: deque[str] = deque(parent)
    while queue:
        current = queue.popleft()
        edges = set(graph.eager.get(current, ()))
        if use_lazy:
            edges |= graph.lazy.get(current, set())
        for target in sorted(edges):
            if target in parent:
                continue
            entry = next((item for item in exclusions if path_matches(graph.modules[target].path, item)), None)
            if entry is not None:
                excluded.setdefault(target, {"entry": entry, "via": current})
                continue
            parent[target] = current
            queue.append(target)
    return parent, excluded


def closure(
    graph: ImportGraph, roots: list[str], *, exclusions: list[dict[str, Any]]
) -> tuple[dict[str, str], dict[str, dict[str, Any]], dict[str, str]]:
    """Return ``(reached module -> first parent, excluded hits, reach kind)``.

    ``reach kind`` is ``eager`` when an import-time chain from a root reaches
    the module and ``lazy`` when only function-level imports do.
    """
    parent, excluded = _walk(graph, roots, exclusions, use_lazy=True)
    eager_parent, _ = _walk(graph, roots, exclusions, use_lazy=False)
    kind = {module: "eager" if module in eager_parent else "lazy" for module in parent}
    return parent, excluded, kind
