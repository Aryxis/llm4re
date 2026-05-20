# LLM 辅助 Solidity 重入漏洞检测

基于 **gpt-5.4-mini** 的检测 Solidity 智能合约中的**重入漏洞** (reentrancy) 方法。

## 任务理解

### 1.1 任务要点

LLM4Re 要求设计一个**基础的智能合约安全分析流程**，检测 Solidity 智能合约的**重入漏洞 (Reentrancy)** ，并探索如何利用大语言模型 (LLM) 完成或辅助这一分析。PDF 中提到的思路包括：

1. 对源码进行代码裁剪，只保留与漏洞相关的片段，节省 LLM 上下文
2. 引入静态分析工具 (Slither Python API)
3. 通过 Prompt Engineering / RAG / few-shot 等手段提升 LLM 判别质量
4. 设计多合约系统下的重入检测方案

### 1.2 任务边界

- baseline: 纯静态分析工具 slither 的结果。任何引入 LLM 的方案必须有非 LLM 版本的对照，我们的方案必须在准确率上显著优于纯静态分析，才能证明 LLM 的价值
- LLM method: 以 gpt-5.4-mini 为基础，设计方案利用 LLM 来辅助或替代纯静态分析工具的某些步骤，如使用 Slither 提供针对性上下文、做代码裁剪、覆盖多种重入变体

### 1.3 自选测试集

| 来源 | 内容 | 用途 |
|---|---|---|
| [serial-coder/solidity-security-by-example](https://github.com/serial-coder/solidity-security-by-example) | 四个典型的重入漏洞示例 | 有 ground truth，包含 4 种典型变体，作为评估主集 |
| 3 个以太坊主网合约 | SpankChain `LedgerChannel` (2018 重入受害合约)、TheDAO (2016 重入受害合约)、Compound `MoneyMarket` | 真实世界场景验证 |

其中，serial-coder 的示例直接从 GitHub 上获取，以太坊主网合约通过 [Python 脚本](scripts/fetch_etherscan_sources.py)调用 etherscan API 获取源码。

## 背景知识

### 2.1 Solidity 和 EVM 的基本特性

- Solidity 是面向 EVM 的合约语言；合约部署后不可变，调用入口为 public/external 函数。
- 合约持有 storage（持久化键值）、memory（调用期）、stack/calldata 等多层存储。
- 合约之间的调用是同步的：A 调 B 时 A 的栈帧保留，等 B 返回。这导致：当 A 把 ETH 通过 `call` 转给 B 时，B 的 `receive()` / `fallback()` 会立即被触发，B 可以在 A 还没结束之前回调 A 自己。
- 这就是"重入 (reentrancy)"的本质——同步调用 + 攻击者可控的回调点。

### 2.2 重入漏洞的原理

Checks-Effects-Interactions (CEI) 是 Solidity 安全的经典模式：先检查条件 (Checks)，再修改状态 (Effects)，最后与外部交互 (Interactions)。重入漏洞通常发生在 CEI 违反时（以 [02_reentrancy](contracts/serial_coder/02_reentrancy/InsecureEtherVault.sol) 为例）：

```solidity
function withdrawAll() external {
    uint256 balance = getUserBalance(msg.sender);
    require(balance > 0, "Insufficient balance");
    (bool success, ) = msg.sender.call{value: balance}("");  // ← Interactions 先发生
    require(success, "Failed to send Ether");
    userBalances[msg.sender] = 0;                            // ← Effects 后发生 (BUG)
}
```

攻击方法：通过 `receive()` 回调里再次调用 `withdrawAll`，`require(balance > 0)` 每次都可以满足（因为 `userBalances` 还没被清零），递归把整个金库抽干。

### 2.3 四种典型的重入变体

| # | 变体 | 触发条件 | 单文件 Slither 能否捕获？ |
|---|---|---|---|
| 02 | **Classic / Single-function** | 同函数内 `call → state write` | ✅ `reentrancy-eth` 命中 |
| 03 | **Via Modifier** | 锁标志设置时机错误，或 modifier 未覆盖所有共享 state 的函数 | ✅ `reentrancy-benign` / `reentrancy-no-eth` 命中 |
| 04 | **Cross-function** | 函数 A 有外部调用并改 state X，攻击者在回调中调用同合约函数 B 利用未及时更新的 X | ✅ `reentrancy-eth` 命中（且报告 cross-function 函数列表） |
| 05 | **Cross-contract** | 合约 X 的状态被合约 Y 读取作为决策依据，X 在外部调用之前未及时更新该状态 | ❌ Slither 默认 **漏报**（不做跨合约状态分析） |

`results/serial_coder/baseline_*.json` 里是 Slither 对这四个示例的检测结果，可以看到，02/03/04 都能被捕获，05 漏报。

## 方法设计

TODO

## 实验结果

TODO

## 讨论与局限

TODO

## 参考资料

- [crytic/slither Wiki — Detector Documentation](https://github.com/crytic/slither/wiki/Detector-Documentation)
- [Slither 论文 (arXiv 1908.09878)](https://arxiv.org/pdf/1908.09878)
- [Solidity 官方文档 — Security Considerations](https://docs.soliditylang.org/en/latest/security-considerations.html)
- [Serial Coder's Posts on Reentrancy](https://www.serial-coder.com/posts/)
- [GPTScan (ICSE'24, arXiv 2308.03314)](https://arxiv.org/abs/2308.03314) — LLM + 静态分析混合范式参考
- [LLM4Vuln (arXiv 2401.16185)](https://arxiv.org/pdf/2401.16185) — prompt 工程消融对比
