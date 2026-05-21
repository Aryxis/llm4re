"""Compact extractor for Slither baseline JSON.

Usage:
  from slither_summary import summarize
  findings = summarize("results/baseline/baseline_02_reentrancy.json")
"""

import json
from pathlib import Path


def summarize(baseline_path: str | Path) -> list[dict]:
    """Return one dict per Slither finding, suitable for prompt context.

    Each dict has: check, impact, confidence, signature, lines, description.
    Returns [] if file is missing, empty, or has no detectors.
    """
    path = Path(baseline_path)
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    detectors = (data.get("results") or {}).get("detectors") or []
    out = []
    for d in detectors:
        signature = ""
        lines: list[int] = []
        for el in d.get("elements", []):
            if el.get("type") == "function":
                signature = (
                    el.get("type_specific_fields", {}).get("signature")
                    or el.get("name")
                    or ""
                )
                lines = el.get("source_mapping", {}).get("lines") or []
                break
        out.append(
            {
                "check": d.get("check"),
                "impact": d.get("impact"),
                "confidence": d.get("confidence"),
                "signature": signature,
                "lines": lines,
                "description": (d.get("description") or "").strip(),
            }
        )
    return out


def format_for_prompt(findings: list[dict]) -> str:
    """Render findings as a human-readable block for the LLM prompt."""
    if not findings:
        return "(Slither reported no reentrancy findings for this target.)"
    parts = []
    for i, f in enumerate(findings, 1):
        line_range = (
            f"lines {f['lines'][0]}-{f['lines'][-1]}" if f["lines"] else "lines ?"
        )
        parts.append(
            f"[{i}] {f['check']} (impact={f['impact']}, confidence={f['confidence']})\n"
            f"    function: {f['signature']} @ {line_range}\n"
            f"    detail: {f['description']}"
        )
    return "\n".join(parts)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python slither_summary.py [path_to_slither_json]")
        sys.exit(1)

    print(format_for_prompt(summarize(sys.argv[1])))
