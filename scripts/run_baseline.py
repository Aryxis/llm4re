#!/usr/bin/env python3

"""Run Slither's reentrancy detectors against the serial-coder examples.

Activate the project venv first so `slither` is on PATH, then run from the
repo root:
  python3 scripts/run_baseline.py

Writes one baseline_<target>.json file per target into the repo root.
"""

import json
import re
import subprocess
from pathlib import Path


TARGETS = [
    "02_reentrancy/InsecureEtherVault.sol",
    "04_cross_function_reentrancy/InsecureEtherVault.sol",
    "03_reentrancy_via_modifier/InsecureAirdrop.sol",
    "05_cross_contract_reentrancy/InsecureMoonVault.sol",
]

CONTRACTS_DIR = Path("contracts/serial_coder")
OUT_DIR = Path("results/baseline")
DETECTORS = ",".join(
    [
        "reentrancy-eth",
        "reentrancy-no-eth",
        "reentrancy-benign",
        "reentrancy-events",
        "reentrancy-unlimited-gas",
    ]
)
SLITHER_TIMEOUT = 180


def extract_solidity_version(target: Path) -> str | None:
    """Extract Solidity version from pragma statement."""
    try:
        content = target.read_text(encoding="utf-8")
        match = re.search(r"pragma\s+solidity\s+(0\.\d+\.\d+)", content)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None


def select_solc_version(version: str) -> bool:
    """Use solc-select to switch to the specified version."""
    try:
        proc = subprocess.run(
            ["solc-select", "use", version],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def run_slither(target: Path) -> dict:
    proc = subprocess.run(
        [
            "slither",
            str(target),
            "--detect",
            DETECTORS,
            "--json",
            "-",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=SLITHER_TIMEOUT,
    )
    stdout = proc.stdout.strip()
    if not stdout:
        raise RuntimeError(proc.stderr.strip() or "slither produced no JSON output")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON from slither: {exc}") from exc


def write_baseline(name: str, data: dict) -> Path:
    out_path = OUT_DIR / f"baseline_{name}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return out_path


def main() -> int:
    if not CONTRACTS_DIR.is_dir():
        print(f"Missing {CONTRACTS_DIR} (run from repo root)")
        return 1

    failed = 0
    for name in TARGETS:
        target = CONTRACTS_DIR / name
        print(f"Running slither on {target}")

        # Extract and select Solidity version
        version = extract_solidity_version(target)
        if version:
            print(f"  detected solidity version: {version}")
            if not select_solc_version(version):
                failed += 1
                print(f"  failed: solc {version} not installed")
                continue
        else:
            print("  warning: could not detect solidity version")

        try:
            data = run_slither(target)
            out_path = write_baseline(name[: name.find("/")], data)
            count = len((data.get("results") or {}).get("detectors") or [])
            print(f"  wrote {out_path.name} ({count} findings)")
        except Exception as exc:
            failed += 1
            print(f"  failed: {exc}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
