#!/usr/bin/env python3

"""Fetch three verified Ethereum mainnet contract sources from Etherscan.

Put your key in .env:
  ETHERSCAN_API_KEY=...

Run:
  python3 fetch_etherscan_sources.py
"""

import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path


TARGETS = [
    "0xf91546835f756DA0c10cFa0CDA95b15577b84aA7",
    "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
    "0x0eee3e3828a45f7601d5f54bf49bb01d1a9df5ea",
]

CHAIN_ID = "1"
API_URL = "https://api.etherscan.io/v2/api"
OUT_DIR = Path("contracts/mainnet")


def load_env_key() -> str:
    env_path = Path(".env")
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() == "ETHERSCAN_API_KEY":
                return value.strip().strip("'\"")
    return os.environ.get("ETHERSCAN_API_KEY", "")


def etherscan_get(params: dict[str, str]) -> dict:
    query = urllib.parse.urlencode(params)
    req = urllib.request.Request(
        f"{API_URL}?{query}",
        headers={"User-Agent": "llm4re-fetch-etherscan/1.0"},
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_contract(address: str, api_key: str) -> dict:
    data = etherscan_get(
        {
            "chainid": CHAIN_ID,
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key,
        }
    )
    if data.get("status") != "1":
        raise RuntimeError(data.get("result") or data.get("message") or data)

    result = data["result"][0]
    if not result.get("SourceCode"):
        raise RuntimeError("no verified source code on Etherscan")
    return result


def safe_name(name: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name).strip("._-")
    return name or "Contract"


def parse_standard_json(source_code: str) -> dict | None:
    source_code = source_code.strip()
    candidates = [source_code]
    if source_code.startswith("{{") and source_code.endswith("}}"):
        candidates.append(source_code[1:-1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and isinstance(parsed.get("sources"), dict):
            return parsed
    return None


def write_sources(address: str, info: dict) -> None:
    name = safe_name(info.get("ContractName", "Contract"))
    target_dir = OUT_DIR / name
    target_dir.mkdir(parents=True, exist_ok=True)

    source_code = info["SourceCode"]
    standard_json = parse_standard_json(source_code)

    if standard_json:
        for file_name, file_info in standard_json["sources"].items():
            content = file_info.get("content", "")
            if not content:
                continue
            path = Path(file_name)
            if path.is_absolute() or ".." in path.parts:
                path = Path(safe_name(file_name) + ".sol")
            out_file = target_dir / path
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(content, encoding="utf-8")
        (target_dir / "standard-json-input.json").write_text(
            json.dumps(standard_json, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    else:
        (target_dir / f"{name}.sol").write_text(source_code, encoding="utf-8")

    metadata = {
        "address": address,
        "contract_name": info.get("ContractName"),
        "compiler_version": info.get("CompilerVersion"),
        "optimization_used": info.get("OptimizationUsed"),
        "runs": info.get("Runs"),
        "proxy": info.get("Proxy"),
        "implementation": info.get("Implementation"),
    }
    (target_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    api_key = load_env_key()
    if not api_key:
        print("Missing ETHERSCAN_API_KEY in .env or environment")
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    failed = 0
    for address in TARGETS:
        print(f"Fetching {address}")
        try:
            info = fetch_contract(address, api_key)
            write_sources(address, info)
            print(f"  saved {info.get('ContractName') or 'Contract'}")
        except Exception as exc:
            failed += 1
            print(f"  failed: {exc}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
