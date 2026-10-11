"""A small, local evaluator for the subset of Okta Expression Language used in
group rules.

This is an approximation written from Okta's public documentation, not Okta's
engine. Anything it does not understand raises UnsupportedExpression so the
caller can report "could not evaluate" instead of guessing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable


class OELError(Exception):
    pass


class UnsupportedExpression(OELError):
    pass


# --------------------------------------------------------------------- lexer
_TOKEN = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<number>\d+(?:\.\d+)?)
  | (?P<op>==|!=|>=|<=|&&|\|\||[<>!?:(),\[\]{}])
  | (?P<ident>[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)
    """,
    re.VERBOSE,
)


@dataclass
class Tok:
    kind: str
    value: Any
    pos: int


def tokenize(src: str) -> list[Tok]:
    out: list[Tok] = []
    i = 0
    while i < len(src):
        m = _TOKEN.match(src, i)
        if not m:
            raise OELError(f"unexpected character {src[i]!r} at {i}")
        kind = m.lastgroup
        text = m.group(kind)
        if kind == "string":
            body = text[1:-1]
            out.append(Tok("string", re.sub(r"\\(.)", r"\1", body), i))
        elif kind == "number":
            out.append(Tok("number", float(text) if "." in text else int(text), i))
        elif kind == "op":
            out.append(Tok("op", text, i))
        elif kind == "ident":
            upper = text.upper()
            if upper in ("AND", "OR"):
                out.append(Tok("op", "&&" if upper == "AND" else "||", i))
            elif upper == "TRUE":
                out.append(Tok("literal", True, i))
            elif upper == "FALSE":
                out.append(Tok("literal", False, i))
            elif upper == "NULL":
                out.append(Tok("literal", None, i))
            else:
                out.append(Tok("ident", text, i))
        i = m.end()
    out.append(Tok("eof", None, len(src)))
    return out


# -------------------------------------------------------------------- parser
# AST nodes are tuples: ("lit", v) ("attr", path) ("call", name, args)
# ("not", x) ("bin", op, a, b) ("tern", c, a, b) ("list", items)

class _Parser:
    def __init__(self, src: str):
        self.toks = tokenize(src)
        self.i = 0

    def peek(self) -> Tok:
        return self.toks[self.i]

    def next(self) -> Tok:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def expect(self, value: str) -> None:
        tok = self.next()
        if tok.kind != "op" or tok.value != value:
            raise OELError(f"expected {value!r} at {tok.pos}")

    def parse(self):
        node = self.ternary()
        if self.peek().kind != "eof":
            raise OELError(f"unexpected token {self.peek().value!r} at {self.peek().pos}")
        return node

    def ternary(self):
        cond = self.binary(0)
        if self.peek().kind == "op" and self.peek().value == "?":
            self.next()
            a = self.ternary()
            self.expect(":")
            b = self.ternary()
            return ("tern", cond, a, b)
        return cond

    _PREC = {"||": 1, "&&": 2, "==": 3, "!=": 3, "<": 4, ">": 4, "<=": 4, ">=": 4}

    def binary(self, min_prec: int):
        left = self.unary()
        while True:
            tok = self.peek()
            prec = self._PREC.get(tok.value) if tok.kind == "op" else None
            if prec is None or prec <= min_prec:
                return left
            self.next()
            right = self.binary(prec)
            left = ("bin", tok.value, left, right)

    def unary(self):
        tok = self.peek()
        if tok.kind == "op" and tok.value == "!":
            self.next()
            return ("not", self.unary())
        return self.primary()

    def primary(self):
        tok = self.next()
        if tok.kind in ("string", "number", "literal"):
            return ("lit", tok.value)
        if tok.kind == "op" and tok.value == "(":
            node = self.ternary()
            self.expect(")")
            return node
        if tok.kind == "op" and tok.value in ("[", "{"):
            close = "]" if tok.value == "[" else "}"
            items = []
            if not (self.peek().kind == "op" and self.peek().value == close):
                items.append(self.ternary())
                while self.peek().kind == "op" and self.peek().value == ",":
                    self.next()
                    items.append(self.ternary())
            self.expect(close)
            return ("list", items)
        if tok.kind == "ident":
            if self.peek().kind == "op" and self.peek().value == "(":
                self.next()
                args = []
                if not (self.peek().kind == "op" and self.peek().value == ")"):
                    args.append(self.ternary())
                    while self.peek().kind == "op" and self.peek().value == ",":
                        self.next()
                        args.append(self.ternary())
                self.expect(")")
                return ("call", tok.value, args)
            return ("attr", tok.value)
        raise OELError(f"unexpected token {tok.value!r} at {tok.pos}")


def parse(src: str):
    return _Parser(src).parse()


# ----------------------------------------------------------------- evaluator
@dataclass
class Context:
    """One user as the evaluator sees them.

    profile: Okta profile attributes (department, title, employeeType, ...)
    group_names: names of groups the user is in *outside* group rules
    group_ids: ids of those same groups, when known
    """
    profile: dict[str, Any]
    group_names: set[str]
    group_ids: set[str]
    status: str = "ACTIVE"


def _s(v: Any) -> str:
    if v is None:
        raise _NullArg()
    return str(v)


class _NullArg(Exception):
    pass


def _contains(arr: Any, v: Any) -> bool:
    return isinstance(arr, list) and v in arr


FUNCTIONS: dict[str, Callable[..., Any]] = {
    # String functions
    "String.stringContains": lambda s, sub: _s(sub) in _s(s),
    "String.startsWith": lambda s, p: _s(s).startswith(_s(p)),
    "String.endsWith": lambda s, p: _s(s).endswith(_s(p)),
    "String.toLowerCase": lambda s: _s(s).lower(),
    "String.toUpperCase": lambda s: _s(s).upper(),
    "String.len": lambda s: len(_s(s)),
    "String.substringBefore": lambda s, sep: _s(s).split(_s(sep), 1)[0],
    "String.substringAfter": lambda s, sep: _s(s).split(_s(sep), 1)[1] if _s(sep) in _s(s) else "",
    "String.removeSpaces": lambda s: _s(s).replace(" ", ""),
    # Array functions
    "Arrays.contains": _contains,
    "Arrays.isEmpty": lambda a: not a,
    "Arrays.size": lambda a: len(a or []),
}

GROUP_FUNCTIONS = {
    "isMemberOfGroupName",
    "isMemberOfGroup",
    "isMemberOfAnyGroup",
    "isMemberOfGroupNameStartsWith",
    "isMemberOfGroupNameContains",
    "isMemberOfGroupNameRegex",
}


def _truthy(v: Any) -> bool:
    return v is True


def _eval(node, ctx: Context) -> Any:
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "list":
        return [_eval(n, ctx) for n in node[1]]
    if kind == "attr":
        path = node[1]
        if path.startswith("user."):
            key = path[len("user."):]
            if key == "status":
                return ctx.status
            return ctx.profile.get(key)
        raise UnsupportedExpression(f"unsupported reference {path!r} (only user.* is modelled)")
    if kind == "not":
        return not _truthy(_eval(node[1], ctx))
    if kind == "tern":
        return _eval(node[2], ctx) if _truthy(_eval(node[1], ctx)) else _eval(node[3], ctx)
    if kind == "bin":
        op = node[1]
        if op == "&&":
            return _truthy(_eval(node[2], ctx)) and _truthy(_eval(node[3], ctx))
        if op == "||":
            return _truthy(_eval(node[2], ctx)) or _truthy(_eval(node[3], ctx))
        a, b = _eval(node[2], ctx), _eval(node[3], ctx)
        if op == "==":
            return a == b
        if op == "!=":
            return a != b
        if a is None or b is None:
            return False
        try:
            a_num, b_num = float(a), float(b)
        except (TypeError, ValueError):
            return False
        return {"<": a_num < b_num, ">": a_num > b_num, "<=": a_num <= b_num, ">=": a_num >= b_num}[op]
    if kind == "call":
        name, args = node[1], node[2]
        vals = [_eval(a, ctx) for a in args]
        if name in GROUP_FUNCTIONS:
            return _group_fn(name, vals, ctx)
        fn = FUNCTIONS.get(name)
        if fn is None:
            raise UnsupportedExpression(f"function {name}() is not modelled")
        try:
            return fn(*vals)
        except _NullArg:
            return None
        except TypeError as exc:
            raise OELError(f"bad arguments to {name}(): {exc}") from exc
    raise OELError(f"unknown node {kind}")


def _flatten(vals: list[Any]) -> list[Any]:
    out: list[Any] = []
    for v in vals:
        out.extend(v if isinstance(v, list) else [v])
    return out


def _group_fn(name: str, vals: list[Any], ctx: Context) -> bool:
    flat = [str(v) for v in _flatten(vals) if v is not None]
    if name == "isMemberOfGroupName":
        return bool(flat) and flat[0] in ctx.group_names
    if name == "isMemberOfGroup":
        return bool(flat) and flat[0] in ctx.group_ids
    if name == "isMemberOfAnyGroup":
        return any(g in ctx.group_ids for g in flat)
    if name == "isMemberOfGroupNameStartsWith":
        return bool(flat) and any(g.startswith(flat[0]) for g in ctx.group_names)
    if name == "isMemberOfGroupNameContains":
        return bool(flat) and any(flat[0] in g for g in ctx.group_names)
    if name == "isMemberOfGroupNameRegex":
        return bool(flat) and any(re.fullmatch(flat[0], g) for g in ctx.group_names)
    raise UnsupportedExpression(name)


class Expression:
    """A parsed group-rule expression, reusable across many users."""

    def __init__(self, src: str):
        self.src = src
        self.ast = parse(src)

    def matches(self, ctx: Context) -> bool:
        return _truthy(_eval(self.ast, ctx))


def evaluate(src: str, ctx: Context) -> Any:
    return _eval(parse(src), ctx)
