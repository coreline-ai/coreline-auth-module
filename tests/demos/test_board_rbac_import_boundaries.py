from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[2]
DEMO = ROOT / "demos" / "board_rbac"
SRC = ROOT / "src" / "coreline_auth"


def python_files(base: Path):
    return [path for path in base.rglob("*.py") if "__pycache__" not in path.parts]


def imports_in(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.append(node.module or "")
    return found


def test_demo_does_not_import_sibling_board_packages() -> None:
    offenders: list[str] = []
    for path in python_files(DEMO):
        for module in imports_in(path):
            root = module.split(".", 1)[0]
            if root in {"coreline_board", "coreline_board_saas"}:
                offenders.append(f"{path.relative_to(ROOT)}:{module}")
    assert offenders == []


def test_auth_core_does_not_import_board_demo() -> None:
    offenders: list[str] = []
    for path in python_files(SRC):
        for module in imports_in(path):
            if module.startswith("demos.board_rbac") or module.startswith("demos"):
                offenders.append(f"{path.relative_to(ROOT)}:{module}")
    assert offenders == []
