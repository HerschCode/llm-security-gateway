"""
Tool-level capability policy: default-deny, first-matching-rule, strict arguments.

Why a small purpose-built YAML evaluator instead of OPA/Rego or Cedar (decision in docs/decisions.md):
OPA needs a separate server or binary; Cedar's Python bindings add a native dependency. This project's
constraint is a torch-free, dependency-light 512 MB free tier, and the policy surface here is small
(role x tool x argument constraints). The evaluator is ~150 lines, fully unit-tested, and the file
format is deliberately close to what a Cedar migration would need. What it does NOT have: policy
composition, entity hierarchies, or formal analysis; a real deployment with many policies should use Cedar or OPA.

The policy file is validated on load and unknown keys are errors: a typo silently weakening a security
policy is worse than a startup failure.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "config" / "tool_policies.yaml"

_TOOL_KEYS = {"kind", "output_trust", "rules", "taint", "max_per_session", "description"}
_RULE_KEYS = {"name", "roles", "args", "approval"}
_ARG_KEYS = {"in", "pattern", "not_pattern", "max_length", "min", "max", "type", "required", "equals"}
_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool}


class PolicyError(ValueError):
    """The policy file is malformed. Raised at load time, never at decision time."""


@dataclass(frozen=True)
class Principal:
    role: str
    user_id: str = "unknown"


@dataclass
class PolicyResult:
    allowed: bool
    approval: str = "none"           # "none" | "required" (only meaningful when allowed)
    rule: str | None = None
    reasons: list[str] = field(default_factory=list)


class Policy:
    def __init__(self, data: dict):
        self.default_effect = data.get("default_effect", "deny")
        if self.default_effect != "deny":
            raise PolicyError("default_effect must be 'deny'; an allow-by-default action policy is not supported")
        self.strict_args = bool(data.get("strict_args", True))
        self.tools: dict[str, dict] = data.get("tools") or {}
        self._validate()

    @classmethod
    def load(cls, path: Path | str = DEFAULT_POLICY_PATH) -> "Policy":
        with open(path, encoding="utf-8") as f:
            return cls(yaml.safe_load(f) or {})

    def _validate(self):
        for name, spec in self.tools.items():
            unknown = set(spec) - _TOOL_KEYS
            if unknown:
                raise PolicyError(f"tool {name!r}: unknown keys {sorted(unknown)}")
            if spec.get("kind") not in ("read", "write"):
                raise PolicyError(f"tool {name!r}: kind must be 'read' or 'write'")
            if spec.get("output_trust", "untrusted") not in ("trusted", "untrusted"):
                raise PolicyError(f"tool {name!r}: output_trust must be 'trusted' or 'untrusted'")
            for field_name, reaction in (spec.get("taint") or {}).items():
                if reaction not in ("deny", "flag"):
                    raise PolicyError(f"tool {name!r}: taint[{field_name!r}] must be 'deny' or 'flag'")
            if spec["kind"] == "write" and not all(r.get("approval") == "required" for r in spec.get("rules", [])):
                raise PolicyError(f"tool {name!r}: every rule of a write tool must set approval: required")
            for i, rule in enumerate(spec.get("rules", [])):
                unknown = set(rule) - _RULE_KEYS
                if unknown:
                    raise PolicyError(f"tool {name!r} rule {i}: unknown keys {sorted(unknown)}")
                if not rule.get("roles"):
                    raise PolicyError(f"tool {name!r} rule {i}: roles must be a non-empty list")
                for arg, constraint in (rule.get("args") or {}).items():
                    unknown = set(constraint) - _ARG_KEYS
                    if unknown:
                        raise PolicyError(f"tool {name!r} rule {i} arg {arg!r}: unknown keys {sorted(unknown)}")
                    if constraint.get("type", "string") not in _TYPES:
                        raise PolicyError(f"tool {name!r} rule {i} arg {arg!r}: bad type")
                    for rx in ("pattern", "not_pattern"):
                        if rx in constraint:
                            re.compile(constraint[rx])

    # ---- queries ---------------------------------------------------------------------------

    def tool(self, name: str) -> dict | None:
        return self.tools.get(name)

    def output_trust(self, tool: str) -> str:
        """Unknown tools' outputs are untrusted: fail toward suspicion."""
        return (self.tools.get(tool) or {}).get("output_trust", "untrusted")

    def visible_to(self, role: str, tool: str) -> bool:
        """True if some rule of `tool` names `role`; used to hide tools from tools/list."""
        spec = self.tools.get(tool)
        return bool(spec) and any(role in r["roles"] for r in spec.get("rules", []))

    # ---- evaluation ------------------------------------------------------------------------

    def evaluate(self, principal: Principal, tool: str, args: dict) -> PolicyResult:
        spec = self.tools.get(tool)
        if spec is None:
            return PolicyResult(False, reasons=[f"tool {tool!r} is not in the policy (default deny)"])
        if not isinstance(args, dict):
            return PolicyResult(False, reasons=["arguments must be an object"])
        role_rules = [(i, r) for i, r in enumerate(spec.get("rules", [])) if principal.role in r["roles"]]
        if not role_rules:
            return PolicyResult(False, reasons=[f"role {principal.role!r} may not call {tool!r}"])
        failures_by_rule = []
        for i, rule in role_rules:
            failures = self._check_args(rule, args, principal)
            if not failures:
                return PolicyResult(True, approval=rule.get("approval", "none"), rule=rule.get("name", f"rule-{i}"))
            failures_by_rule.append((rule.get("name", f"rule-{i}"), failures))
        # report the failures of the first role-matching rule: the closest thing to what the caller meant
        name, failures = failures_by_rule[0]
        return PolicyResult(False, rule=name, reasons=failures)

    def _check_args(self, rule: dict, args: dict, principal: Principal) -> list[str]:
        constraints = rule.get("args") or {}
        failures = []
        if self.strict_args:
            for extra in sorted(set(args) - set(constraints)):
                failures.append(f"argument {extra!r} is not permitted (strict_args)")
        for name, c in constraints.items():
            if name not in args:
                if c.get("required"):
                    failures.append(f"argument {name!r} is required")
                continue
            failures.extend(self._check_value(name, args[name], c, principal))
        return failures

    @staticmethod
    def _check_value(name: str, value, c: dict, principal: Principal) -> list[str]:
        type_name = c.get("type") or ("string" if any(k in c for k in ("pattern", "not_pattern", "max_length")) else None)
        if type_name:
            # bool is a subclass of int in Python: never accept True/False as a number or string
            if isinstance(value, bool) and type_name != "boolean":
                return [f"argument {name!r} has the wrong type (bool)"]
            if not isinstance(value, _TYPES[type_name]):
                return [f"argument {name!r} must be {type_name}, got {type(value).__name__}"]
        out = []
        if "in" in c and value not in c["in"]:
            out.append(f"argument {name!r}={value!r} is not one of {c['in']}")
        if "equals" in c:
            want = c["equals"]
            if want == "$principal.user_id":
                want = principal.user_id
            elif want == "$principal.role":
                want = principal.role
            if value != want:
                out.append(f"argument {name!r} must equal the caller's own value (own records only)")
        if isinstance(value, str):
            if "max_length" in c and len(value) > c["max_length"]:
                out.append(f"argument {name!r} is longer than {c['max_length']} characters")
            if "pattern" in c and not re.fullmatch(c["pattern"], value):
                out.append(f"argument {name!r} does not match the allowed pattern")
            if "not_pattern" in c and re.search(c["not_pattern"], value):
                out.append(f"argument {name!r} contains a forbidden pattern (possible exfiltration or secret)")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "min" in c and value < c["min"]:
                out.append(f"argument {name!r} is below the minimum {c['min']}")
            if "max" in c and value > c["max"]:
                out.append(f"argument {name!r} is above the maximum {c['max']}")
        return out
