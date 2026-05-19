# LLM 辅助 Solidity 重入漏洞检测

基于 gpt-5.4-mini 的检测 Solidity 智能合约中的重入漏洞（reentrancy）方法。

## Contracts

1. 从 [serial-coder](https://github.com/serial-coder/solidity-security-by-example/) 上获取示例合约，仅保留和 reentrancy 相关的合约 (02~05)。
2. 用 [Python 脚本](scripts/fetch_etherscan_sources.py)调用 etherscan API 获取以太坊主网合约。
