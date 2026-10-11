"""Read a Terraform JSON plan (`terraform show -json plan.bin`).

Only the parts of the plan format that okta-guardrails needs are modelled:
resource_changes, prior_state, planned_values and configuration (for
references whose values are not known until apply).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator


@dataclass
class Change:
    address: str
    type: str
    name: str
    actions: list[str]
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    after_unknown: dict[str, Any] = field(default_factory=dict)

    @property
    def is_create(self) -> bool:
        return self.actions == ["create"]

    @property
    def is_update(self) -> bool:
        return self.actions == ["update"]

    @property
    def is_replace(self) -> bool:
        return set(self.actions) == {"create", "delete"}

    @property
    def is_delete(self) -> bool:
        return self.actions == ["delete"]

    @property
    def is_noop(self) -> bool:
        return self.actions in (["no-op"], ["read"])

    @property
    def writes(self) -> bool:
        """True when the resource exists after apply with new values."""
        return self.is_create or self.is_update or self.is_replace

    def before_get(self, key: str, default: Any = None) -> Any:
        return (self.before or {}).get(key, default)

    def after_get(self, key: str, default: Any = None) -> Any:
        return (self.after or {}).get(key, default)

    def is_unknown(self, key: str) -> bool:
        value = (self.after_unknown or {}).get(key)
        if isinstance(value, list):
            return any(value)
        return bool(value)


def _walk_module(module: dict[str, Any] | None) -> Iterator[dict[str, Any]]:
    if not module:
        return
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from _walk_module(child)


def _walk_config(module: dict[str, Any] | None, prefix: str = "") -> Iterator[tuple[str, dict[str, Any]]]:
    if not module:
        return
    for res in module.get("resources", []):
        yield prefix, res
    for name, call in (module.get("module_calls") or {}).items():
        yield from _walk_config(call.get("module"), f"{prefix}module.{name}.")


class Plan:
    def __init__(self, data: dict[str, Any]):
        if "resource_changes" not in data and "planned_values" not in data:
            raise ValueError("not a Terraform JSON plan: run `terraform show -json plan.bin`")
        self.data = data
        self.changes: list[Change] = []
        for rc in data.get("resource_changes", []):
            if rc.get("mode", "managed") != "managed":
                continue
            ch = rc.get("change", {})
            self.changes.append(
                Change(
                    address=rc["address"],
                    type=rc["type"],
                    name=rc.get("name", ""),
                    actions=list(ch.get("actions", [])),
                    before=ch.get("before"),
                    after=ch.get("after"),
                    after_unknown=ch.get("after_unknown") or {},
                )
            )
        self._changes_by_addr = {c.address: c for c in self.changes}

        self._prior: dict[str, dict[str, Any]] = {}
        prior_root = ((data.get("prior_state") or {}).get("values") or {}).get("root_module")
        for res in _walk_module(prior_root):
            self._prior[res["address"]] = res

        self._config: dict[str, dict[str, Any]] = {}
        cfg_root = (data.get("configuration") or {}).get("root_module")
        for prefix, res in _walk_config(cfg_root):
            self._config[prefix + res["address"]] = {**res, "_prefix": prefix}

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, path: str | Path) -> "Plan":
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh))

    # --------------------------------------------------------------- queries
    def changes_of(self, *types: str) -> list[Change]:
        return [c for c in self.changes if c.type in types and not c.is_noop]

    def change(self, address: str) -> Change | None:
        return self._changes_by_addr.get(address)

    def prior_resources(self, *types: str) -> Iterable[dict[str, Any]]:
        return (r for r in self._prior.values() if r.get("type") in types)

    def values_before(self, address: str) -> dict[str, Any] | None:
        ch = self._changes_by_addr.get(address)
        if ch is not None:
            return ch.before
        res = self._prior.get(address)
        return res.get("values") if res else None

    def values_after(self, address: str) -> dict[str, Any] | None:
        ch = self._changes_by_addr.get(address)
        if ch is not None:
            return None if ch.is_delete else ch.after
        res = self._prior.get(address)
        return res.get("values") if res else None

    def resources_before(self, *types: str) -> list[tuple[str, dict[str, Any]]]:
        out = []
        for addr, res in self._prior.items():
            if res.get("type") in types and res.get("mode", "managed") == "managed":
                out.append((addr, res.get("values") or {}))
        for ch in self.changes:
            if ch.type in types and ch.before is not None and ch.address not in self._prior:
                out.append((ch.address, ch.before))
        return out

    def resources_after(self, *types: str) -> list[tuple[str, dict[str, Any]]]:
        out = []
        seen = set()
        for ch in self.changes:
            if ch.type in types:
                seen.add(ch.address)
                if not ch.is_delete and ch.after is not None:
                    out.append((ch.address, ch.after))
        for addr, res in self._prior.items():
            if res.get("type") in types and addr not in seen and res.get("mode", "managed") == "managed":
                out.append((addr, res.get("values") or {}))
        return out

    def references(self, address: str, attribute: str) -> list[str]:
        """Resource addresses that `attribute` of `address` refers to in config."""
        base = address.split("[", 1)[0]
        cfg = self._config.get(base)
        if not cfg:
            return []
        expr = (cfg.get("expressions") or {}).get(attribute)
        refs: list[str] = []

        def collect(e: Any) -> None:
            if isinstance(e, dict):
                for r in e.get("references", []) or []:
                    refs.append(r)
            elif isinstance(e, list):
                for item in e:
                    collect(item)

        collect(expr)
        prefix = cfg.get("_prefix", "")
        out: list[str] = []
        for r in refs:
            parts = r.split(".")
            if parts[0] == "data" and len(parts) >= 3:
                addr = ".".join(parts[:3])
            elif len(parts) >= 2 and not parts[0] in ("var", "local", "each", "count", "module"):
                addr = ".".join(parts[:2])
            else:
                continue
            addr = prefix + addr
            if addr not in out:
                out.append(addr)
        return out

    def id_index(self) -> dict[str, list[tuple[str, dict[str, Any]]]]:
        """Map known Okta object ids to every (address, values) carrying that id.

        Several resources can share an id (okta_app_oauth_api_scope uses its
        app's id), so callers pick the entry that has the attribute they need.
        """
        idx: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for addr, res in self._prior.items():
            vals = res.get("values") or {}
            if vals.get("id"):
                idx.setdefault(vals["id"], []).append((addr, vals))
        for ch in self.changes:
            for vals in (ch.before, ch.after):
                if vals and vals.get("id"):
                    idx.setdefault(vals["id"], []).append((ch.address, vals))
        return idx

    def resolve(self, address: str, attribute: str, ids: Iterable[Any], name_attr: str,
                side: str = "after") -> list[str]:
        """Turn ids held in `attribute` into display names.

        Known ids are looked up in state; ids not known until apply are resolved
        through the configuration's references (after side only).
        """
        idx = self.id_index()
        names: list[str] = []
        unknown = False
        for i in ids or []:
            if i is None:
                unknown = True
                continue
            name = next((v.get(name_attr) for _a, v in idx.get(i, []) if v.get(name_attr)), None) or i
            if name not in names:
                names.append(name)
        if side == "after":
            ch = self._changes_by_addr.get(address)
            if unknown or not ids or (ch is not None and ch.is_unknown(attribute)):
                for ref in self.references(address, attribute):
                    vals = self.values_after(ref) or self.values_before(ref) or {}
                    name = vals.get(name_attr)
                    if name and name not in names:
                        names.append(name)
        return names
