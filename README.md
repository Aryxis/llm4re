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

### 3.1 流程总览

```
                   +--> slither baseline --> slither summary --+
                   |                                           |
contracts/*.sol  --+                                           +--> prompt --> gpt-5.4-mini --> JSON
                   |                                           |
                   +--> Source code only ----------------------+
```

`src/llm_analyze.py` 对所有目标各跑两次：

- `baseline` 模式 (LLM-only): 只把源码喂给 LLM，作为对照
- `with_slither` 模式 (LLM + 静态分析): 在源码之外附上 Slither 的精简 findings 作为上下文提示，让 LLM 验证或反驳

### 3.2 关键组件

| 文件 | 作用 |
|---|---|
| [`prompts/system.md`](prompts/system.md) | System prompt：定义"重入审计员"角色、覆盖 4 种变体的定义、强制 JSON 输出 schema |
| [`prompts/user.md`](prompts/user.md) | User prompt 模板：注入目标 ID、源码块、可选的 Slither findings 块 |
| [`src/slither_summary.py`](src/slither_summary.py) | 把 `results/baseline/baseline_*.json` 压缩成 `[{check, impact, confidence, signature, lines, description}]` 列表，供 LLM 参考 |
| [`src/llm_analyze.py`](src/llm_analyze.py) | 主流程：硬编码 `TARGETS` dict，逐目标 × 模式调用 LLM，已有结果自动跳过 |

### 3.3 输出 schema

每次 LLM 调用都被要求返回严格 JSON：

```json
{
  "vulnerable": true,
  "vulnerability_type": "classic-reentrancy | reentrancy-via-modifier | cross-function | cross-contract | none",
  "vulnerable_functions": ["Contract.func()"],
  "vulnerable_lines": [{"file": "X.sol", "lines": [24, 27]}],
  "severity": "high | medium | low | none",
  "reasoning": "2-6 句解释"
}
```

被包装进顶层 `{target, mode, model, verdict}` 后写入 `results/llm/llm_<target>_<mode>.json`。

### 3.4 运行方式

```fish
source llm4re/bin/activate.fish

# 1. Slither baseline
python scripts/run_baseline.py

# 2. 跑 LLM 流程（默认所有目标 × 两种模式，已有结果会被跳过）
python src/llm_analyze.py

# 3. 局部重跑
python src/llm_analyze.py --target 02_reentrancy --mode with_slither
```

## 实验结果

### 4.1 检测结果总览

| 目标 | Ground truth | Slither baseline | LLM-only | LLM + Slither |
|---|---|---|---|---|
| `02_reentrancy` | ✅ 易受攻击 | ✅ 1 detector | ✅ classic | ✅ classic |
| `02_reentrancy_fixed` | ✅ 安全 | ✅ 0 detector | ✅ none | ✅ none |
| `03_reentrancy_via_modifier` | ✅ 易受攻击 | ✅ 2 detectors | ❌ none (漏报) | ✅ via-modifier |
| `03_reentrancy_via_modifier_fixed` | ✅ 安全 | ⚠️ 1 detector (误报) | ✅ none | ✅ none |
| `04_cross_function` | ✅ 易受攻击 | ✅ 1 detector | ✅ cross-function | ✅ cross-function |
| `04_cross_function_fixed` | ✅ 安全 | ✅ 0 detector | ✅ none | ✅ none |
| `05_cross_contract` | ✅ 易受攻击 | ❌ 0 detector (漏报) | ✅ cross-contract | ✅ cross-contract |
| `05_cross_contract_fixed` | ✅ 安全 | ✅ 0 detector | ✅ none | ✅ none |
| `mainnet_DAO` (TheDAO 2016) | ✅ 历史已被攻击 | — (未跑) | ✅ classic | ✅ classic |
| `mainnet_LedgerChannel` (SpankChain 2018) | ✅ 历史已被攻击 | ✅ 18 detectors | ✅ classic | ✅ classic |
| `mainnet_MoneyMarket` (Compound v1) | ✅ 一般认为安全 | ⚠️ 43 detectors (误报) | ❌ classic (误报) | ❌ classic (误报) |

详细判定见 `results/llm/llm_<target>_<mode>.json`，Slither baseline 见 `results/baseline/baseline_*.json`。

### 4.2 准确率统计

**教学集 (serial-coder 8 个目标)**:

| 方法 | TP | TN | FP | FN | 准确率 |
|---|---|---|---|---|---|
| Slither baseline | 3 | 3 | 1 | 1 | 6/8 = **75%** |
| LLM-only | 3 | 4 | 0 | 1 | 7/8 = **87.5%** |
| LLM + Slither | 4 | 4 | 0 | 0 | 8/8 = **100%** |

**主网合约 (3 个目标)**:

| 方法 | TP | TN | FP | FN | 准确率 |
|---|---|---|---|---|---|
| Slither baseline | 1 | 0 | 1 | — | 1/2 = **50%** (DAO 未跑) |
| LLM-only | 2 | 0 | 1 | 0 | 2/3 = **66.7%** |
| LLM + Slither | 2 | 0 | 1 | 0 | 2/3 = **66.7%** |

### 4.3 关键发现

1. LLM + Slither 在教学集上达到了完美准确率，纠正了 LLM-only 的漏报和 Slither 的误报
2. 跨合约重入 (05) 是 Slither 的盲点，但 LLM 能正确识别，证明了 LLM 在静态工具覆盖盲区的互补价值
3. 主网大合约 (MoneyMarket) 的误报暴露了 LLM 在复杂代码和状态依赖下的过度推测倾向，说明需要更精细的上下文提示或分层分析
4. 历史漏洞合约 (DAO、LedgerChannel) 都被两种模式准确判定为易受攻击，验证了方法在真实场景中的有效性

## 局限与未来工作

### 5.1 主要局限

1. 样本量小：11 个目标 × 2 个模式 = 22 次判定，教学集仅 8 个样本，离统计显著性还差得远，需要扩展到更大数据集
2. 大合约误报率高：MoneyMarket 误报说明 LLM 在 ~2700 行代码 + 复杂状态依赖下难以完整追踪 CEI 模式，倾向于保守判定。可能需要：
   - 代码裁剪 (只保留与外部调用相关的函数)
   - 分层分析 (先识别外部调用点，再局部验证 CEI)
   - Few-shot 示例 (提供正确遵循 CEI 的大合约案例)
3. 行号精度不稳定：LLM 给出的 `vulnerable_lines` 偶尔与源码实际行号差 1–2 行，大合约上更明显 (MoneyMarket 给出数十个行号)，对接下游工具需要容错 (You may want Hash-Anchored Edit Tool!)
4. Slither baseline 覆盖不全：mainnet_DAO 因 Solidity 0.3.1 版本过旧未跑 Slither，导致无法对比 Slither 增益

### 5.2 未来工作

1. 扩展数据集：SWC-107 (Reentrancy) 相关合约、DeFi 协议历史漏洞、Etherscan 随机采样
2. 代码裁剪：基于 Slither 的调用图 + 数据流分析，只保留与外部调用相关的函数和状态变量，减少 LLM 上下文负担
3. 分层检测：
   - Phase 1: LLM 识别所有外部调用点 (call/delegatecall/transfer/ERC-20 等)
   - Phase 2: 对每个调用点，LLM 验证前后的状态更新是否遵循 CEI
   - Phase 3: Slither 提供跨函数/跨合约的数据流分析作为补充
4. Prompt 工程消融：对比 zero-shot、few-shot (2-3 个 CEI 正反例)、chain-of-thought (要求 LLM 先列出外部调用，再逐个检查) 的效果
5. 多模型对比：gpt-4-turbo、claude-3.5-sonnet、deepseek-coder 等模型在重入检测上的准确率和推理质量差异
6. 统计分析：随着样本量增加，进行统计显著性检验，批量标记 ground_truth，编写自动化评估脚本，量化 LLM 的增益和误报率


## 参考资料

- [crytic/slither Wiki — Detector Documentation](https://github.com/crytic/slither/wiki/Detector-Documentation)
- [Slither 论文 (arXiv 1908.09878)](https://arxiv.org/pdf/1908.09878)
- [Solidity 官方文档 — Security Considerations](https://docs.soliditylang.org/en/latest/security-considerations.html)
- [Serial Coder's Posts on Reentrancy](https://www.serial-coder.com/posts/)
- [GPTScan (ICSE'24, arXiv 2308.03314)](https://arxiv.org/abs/2308.03314) — LLM + 静态分析混合范式参考
- [LLM4Vuln (arXiv 2401.16185)](https://arxiv.org/pdf/2401.16185) — prompt 工程消融对比
