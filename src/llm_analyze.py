"""LLM-based reentrancy analyser.

Iterates over a hardcoded list of Solidity targets, asks gpt-5.4-mini to judge
whether each one is vulnerable to reentrancy, and writes one JSON verdict per
(target, mode) to results/llm/.

Two modes:
  - baseline:     prompt with source code only.
  - with_slither: prompt with source code + condensed Slither findings.

Usage (run from repo root, venv activated):
  python src/llm_analyze.py                                  # all targets, both modes
  python src/llm_analyze.py --mode baseline
  python src/llm_analyze.py --target 02_reentrancy --mode with_slither
"""

import argparse
import json
import os
import sys
import time
from collections import deque
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI, RateLimitError, APIError

sys.path.insert(0, str(Path(__file__).parent))
from slither_summary import summarize, format_for_prompt


TARGETS: dict[str, dict] = {
    "02_reentrancy": {
        "dir": "contracts/serial_coder/02_reentrancy",
        "files": ["InsecureEtherVault.sol"],
        "baseline": "results/baseline/baseline_02_reentrancy.json",
    },
    "02_reentrancy_fixed": {
        "dir": "contracts/serial_coder/02_reentrancy",
        "files": ["FixedEtherVault.sol"],
        "baseline": "results/baseline/baseline_02_reentrancy_fixed.json",
    },
    "03_reentrancy_via_modifier": {
        "dir": "contracts/serial_coder/03_reentrancy_via_modifier",
        "files": ["InsecureAirdrop.sol", "Dependencies.sol"],
        "baseline": "results/baseline/baseline_03_reentrancy_via_modifier.json",
    },
    "03_reentrancy_via_modifier_fixed": {
        "dir": "contracts/serial_coder/03_reentrancy_via_modifier",
        "files": ["FixedAirdrop.sol", "Dependencies.sol"],
        "baseline": "results/baseline/baseline_03_reentrancy_via_modifier_fixed.json",
    },
    "04_cross_function": {
        "dir": "contracts/serial_coder/04_cross_function_reentrancy",
        "files": ["InsecureEtherVault.sol", "Dependencies.sol"],
        "baseline": "results/baseline/baseline_04_cross_function_reentrancy.json",
    },
    "04_cross_function_fixed": {
        "dir": "contracts/serial_coder/04_cross_function_reentrancy",
        "files": ["FixedEtherVault.sol", "Dependencies.sol"],
        "baseline": "results/baseline/baseline_04_cross_function_reentrancy_fixed.json",
    },
    "05_cross_contract": {
        "dir": "contracts/serial_coder/05_cross_contract_reentrancy",
        "files": ["InsecureMoonVault.sol", "Dependencies.sol"],
        "baseline": "results/baseline/baseline_05_cross_contract_reentrancy.json",
    },
    "05_cross_contract_fixed": {
        "dir": "contracts/serial_coder/05_cross_contract_reentrancy",
        "files": ["FixedMoonVault.sol", "Dependencies.sol"],
        "baseline": "results/baseline/baseline_05_cross_contract_reentrancy_fixed.json",
    },
    "mainnet_MoneyMarket": {
        "dir": "contracts/mainnet/MoneyMarket",
        "files": ["MoneyMarket.sol"],
        "baseline": "results/baseline/baseline_LedgerChannel.json",
    },
    "mainnet_LedgerChannel": {
        "dir": "contracts/mainnet/LedgerChannel",
        "files": ["LedgerChannel.sol"],
        "baseline": "results/baseline/baseline_MoneyMarket.json",
    },
    "mainnet_DAO": {
        "dir": "contracts/mainnet/DAO",
        "files": ["DAO.sol"],
        "baseline": None,  # Baseline not available now since the required Slither version is too old (0.3.1)
    },
}

PROMPTS_DIR = Path("prompts")
OUT_DIR = Path("results/llm")


_call_times: deque[float] = deque()
RPM_DEFAULT = 5


def rate_limit(rpm: int) -> None:
    """Block until making a new call would keep us under `rpm` per 60s.

    rpm <= 0 disables the limiter.
    """
    if rpm <= 0:
        _call_times.append(time.monotonic())
        return
    now = time.monotonic()
    while _call_times and now - _call_times[0] >= 60:
        _call_times.popleft()
    if len(_call_times) >= rpm:
        sleep_for = 60 - (now - _call_times[0]) + 0.05
        if sleep_for > 0:
            print(f"    rpm={rpm} reached, sleeping {sleep_for:.1f}s")
            time.sleep(sleep_for)
        now = time.monotonic()
        while _call_times and now - _call_times[0] >= 60:
            _call_times.popleft()
    _call_times.append(time.monotonic())


def load_sources(target_dir: Path, files: list[str]) -> str:
    """Return all source files concatenated as fenced solidity blocks."""
    blocks = []
    for fname in files:
        path = target_dir / fname
        code = path.read_text(encoding="utf-8")
        blocks.append(f"### {fname}\n```solidity\n{code}\n```")
    return "\n\n".join(blocks)


def build_user_message(target_id: str, target: dict, mode: str) -> str:
    template = (PROMPTS_DIR / "user.md").read_text(encoding="utf-8")
    sources = load_sources(Path(target["dir"]), target["files"])

    slither_block = ""
    if mode == "with_slither":
        baseline_path = target.get("baseline")
        if baseline_path:
            findings = summarize(baseline_path)
            slither_block = "\nSlither findings:\n" + format_for_prompt(findings) + "\n"
        else:
            slither_block = "\nSlither findings: (no static-analysis baseline available for this target)\n"

    return template.format(
        target=target_id, sources=sources, slither_block=slither_block
    )


def call_llm(client: OpenAI, model: str, system: str, user: str, rpm: int = 0) -> dict:
    last_exc = None
    for attempt in range(5):
        try:
            rate_limit(rpm)
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                response_format={"type": "json_object"},
            )
            content = resp.choices[0].message.content or "{}"
            return json.loads(content)
        except (RateLimitError, APIError) as exc:
            last_exc = exc
            wait = 5 * (attempt + 1)
            print(f"    rate-limited, retrying in {wait}s ({attempt + 1}/5)")
            time.sleep(wait)
    raise RuntimeError(f"giving up after retries: {last_exc}")


def analyse(
    client: OpenAI,
    model: str,
    system: str,
    target_id: str,
    target: dict,
    mode: str,
    rpm: int = 0,
) -> Path:
    user = build_user_message(target_id, target, mode)

    verdict = call_llm(client, model, system, user, rpm=rpm)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / f"llm_{target_id}_{mode}.json"
    out_path.write_text(
        json.dumps(
            {"target": target_id, "mode": mode, "model": model, "verdict": verdict},
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target", choices=list(TARGETS), help="run a single target (default: all)"
    )
    parser.add_argument(
        "--mode", choices=["baseline", "with_slither", "both"], default="both"
    )
    parser.add_argument(
        "--rpm",
        type=int,
        default=RPM_DEFAULT,
        help="max requests per minute (0 = unlimited, default)",
    )
    args = parser.parse_args()

    load_dotenv()
    model = os.environ["LLM_MODEL"]
    client = OpenAI(
        api_key=os.environ["OPENAI_API_KEY"],
        base_url=os.environ.get("OPENAI_BASE_URL"),
    )

    system = (PROMPTS_DIR / "system.md").read_text(encoding="utf-8")
    targets = {args.target: TARGETS[args.target]} if args.target else TARGETS
    modes = ["baseline", "with_slither"] if args.mode == "both" else [args.mode]

    failed = 0
    for target_id, target in targets.items():
        for mode in modes:
            out_path = OUT_DIR / f"llm_{target_id}_{mode}.json"
            if out_path.exists():
                print(f"  {target_id} [{mode}]: skipped (already exists)")
                continue
            try:
                out = analyse(
                    client, model, system, target_id, target, mode, rpm=args.rpm
                )
                v = json.loads(out.read_text(encoding="utf-8"))["verdict"]
                print(
                    f"  {target_id} [{mode}]: vulnerable={v.get('vulnerable')} type={v.get('vulnerability_type')} -> {out.name}"
                )
            except Exception as exc:
                failed += 1
                print(f"  {target_id} [{mode}]: FAILED: {exc}")
            # time.sleep(2)

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
