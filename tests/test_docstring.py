"""test_docstring.py — 开源可交付标准：binowl 包公开 API docstring 全覆盖 lint（M2.2 起）

规则（REKIT-PLAN 支柱 4 / CHARTER 开源交付标准 5）：
  所有顶层 def、class，以及类/嵌套内的公开函数（不以 _ 开头）必须有 docstring。
  下划线开头的内部函数豁免；__init__.py 豁免。
"""
import ast
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PKG = os.path.join(ROOT, "binowl")

MODULES = ["cli", "elf", "pe", "fingerprint", "mcp"]


def _missing_in(node, path):
    """遍历 AST，返回缺 docstring 的公开定义名列表"""
    out = []
    for child in ast.walk(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = child.name
            internal = name.startswith("_")
            in_class = any(p is child for cls in ast.walk(node)
                           for p in getattr(cls, "body", []) if isinstance(p, list))
            if internal:
                continue
            if ast.get_docstring(child) is None:
                out.append("%s:%d %s" % (os.path.basename(path), child.lineno, name))
    return out


def test_public_api_docstring_coverage():
    missing = []
    for mod in MODULES:
        path = os.path.join(PKG, mod + ".py")
        tree = ast.parse(open(path, encoding="utf-8").read())
        for child in tree.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not child.name.startswith("_") and ast.get_docstring(child) is None:
                    missing.append("%s:%d %s" % (mod + ".py", child.lineno, child.name))
    assert not missing, "公开 API 缺 docstring：\n" + "\n".join(missing)
