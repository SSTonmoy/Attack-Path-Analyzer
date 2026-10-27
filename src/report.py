"""report.py
===========

Utility for producing a simple human‑readable report from the analysis
results produced by the other modules.  The public signature is frozen in
``INTERFACES.md`` and must match exactly:

```python
build_report(results: dict, out_path: str) -> None
```

* ``results`` – a dictionary that may contain arbitrary keys produced by the
  pipeline (e.g. risk scores, hardening plan, segments, etc.).
* ``out_path`` – full file path where the report will be written.  The function
  creates any missing parent directories.

The implementation writes a **Markdown** file because it is easy to read in a
terminal and can be rendered to HTML or PDF later if desired.  Each top‑level
key in ``results`` becomes a heading; its value is formatted based on type:

* ``dict`` – formatted as a bullet list of ``key: value`` pairs.
* ``list`` – each element rendered as a bullet.  Nested structures are handled
  recursively.
* other types – converted to ``repr``.

The function is deliberately lightweight and has no external dependencies beyond
the Python standard library and ``networkx`` (which is already used elsewhere).
"""

from __future__ import annotations

import pathlib
from typing import Any, Mapping, Sequence, Set


def _format_value(value: Any, indent: int = 0) -> str:
    """Return a Markdown representation of *value* with *indent* spaces.

    Handles nested mappings, sequences, sets, edge tuples, and scalar values cleanly.
    """
    prefix = " " * indent + "- "
    if isinstance(value, Mapping):
        lines = []
        for k, v in value.items():
            if isinstance(v, (Mapping, Sequence, set, frozenset)) and not isinstance(v, (str, bytes)):
                lines.append(f"{prefix}**{k}**:")
                lines.append(_format_value(v, indent + 2))
            else:
                lines.append(f"{prefix}**{k}**: {v}")
        return "\n".join(lines)
    if isinstance(value, (set, frozenset)):
        nodes = sorted(str(x) for x in value)
        return f"{prefix}" + ", ".join(f"`{n}`" for n in nodes)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        lines = []
        for item in value:
            if isinstance(item, (tuple, list)) and len(item) == 2 and all(isinstance(x, (str, int)) for x in item):
                lines.append(f"{prefix}`{item[0]}` ➔ `{item[1]}`")
            elif isinstance(item, (Mapping, Sequence, set, frozenset)) and not isinstance(item, (str, bytes)):
                lines.append(_format_value(item, indent))
            else:
                lines.append(f"{prefix}{item}")
        return "\n".join(lines)
    return f"{prefix}{value}"


def build_report(results: dict, out_path: str) -> None:
    """Write a Markdown report summarising *results* to ``out_path``.

    Parameters
    ----------
    results: dict
        The analysis output dictionary.
    out_path: str
        Destination file (e.g. ``"reports/summary.md"``).  Parent directories are
        created automatically.
    """
    out_path_obj = pathlib.Path(out_path)
    out_path_obj.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = ["# Attack‑Path Analysis Report", ""]

    for section, content in results.items():
        # Section heading – use title‑case for readability.
        lines.append(f"## {section.replace('_', ' ').title()}")
        lines.append("")
        lines.append(_format_value(content))
        lines.append("")

    report_text = "\n".join(lines).strip() + "\n"
    out_path_obj.write_text(report_text, encoding="utf-8")


__all__ = ["build_report"]
