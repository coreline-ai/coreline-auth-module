from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]
SRC = ROOT / "src" / "coreline_auth"
TESTS = ROOT / "tests"


def _python_files(base: Path):
    return [path for path in base.rglob("*.py") if "__pycache__" not in path.parts]


def test_auth_source_has_no_host_or_board_imports() -> None:
    forbidden_roots = {"coremcp", "apps", "coreline_board", "coreline_board_saas"}
    offenders: list[str] = []
    for path in _python_files(SRC):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0]
                    if root in forbidden_roots or alias.name.startswith("coreline_auth.examples.board"):
                        offenders.append(f"{path.relative_to(ROOT)}:{alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                root = module.split(".", 1)[0]
                if root in forbidden_roots or module.startswith("coreline_auth.examples.board"):
                    offenders.append(f"{path.relative_to(ROOT)}:{module}")
    assert offenders == []


def test_auth_source_has_no_board_permission_vocabulary() -> None:
    offenders: list[str] = []
    test_files = [p for p in _python_files(TESTS) if p.name != "test_import_boundaries.py" and "demos" not in p.parts]
    for path in [*_python_files(SRC), *test_files]:
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.startswith(("board:", "post:", "comment:", "posts:", "comments:")) or node.value.startswith("coreline_auth.examples.board"):
                    offenders.append(f"{path.relative_to(ROOT)}:{node.value}")
    assert offenders == []


def test_auth_source_has_no_board_routes_or_modules() -> None:
    forbidden = ("/board", "coreline_board", "coreline_board_saas", "coreline-board", "권한별 게시판")
    offenders: list[str] = []
    for path in _python_files(SRC):
        text = path.read_text()
        for literal in forbidden:
            if literal in text:
                offenders.append(f"{path.relative_to(ROOT)}:{literal}")
    assert offenders == []


def test_auth_role_enum_is_auth_only() -> None:
    from coreline_auth import Role

    assert {role.value for role in Role} == {"owner", "admin", "viewer", "user"}


def test_readme_permission_model_uses_auth_only_vocabulary() -> None:
    readme = (ROOT / "README.md").read_text()
    forbidden = ("posts:", "comments:", "MODERATOR", "AUTHOR", "moderator/author")
    offenders = [literal for literal in forbidden if literal in readme]
    assert offenders == []


def test_auth_examples_have_no_board_modules() -> None:
    examples = SRC / "examples"
    assert list(examples.glob("board_*.py")) == []
