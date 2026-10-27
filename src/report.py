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
from typing import Any, Mapping, Sequence


def _format_value(value: Any, indent: int = 0) -> str:
    """Return a Markdown representation of *value* with *indent* spaces.

    This helper is recursive so that nested dictionaries/lists are rendered as
    indented bullet lists.
    """
    prefix = " " * indent + "- "
    if isinstance(value, Mapping):
        lines = []
        for k, v in value.items():
            lines.append(f"{prefix}{k}:")
            lines.append(_format_value(v, indent + 2))
        return "\n".join(lines)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        lines = []
        for item in value:
            lines.append(f"{prefix}{_format_value(item, indent + 2).lstrip()}".strip())
        return "\n".join(lines)
    # Fallback – use ``repr`` for deterministic output.
    return f"{prefix}{repr(value)}"


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
