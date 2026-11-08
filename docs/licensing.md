# 第三方许可与再分发边界（法务修正版）

> 这份文件**不是法律意见**，只把「哪种包能发给谁、包里到底装了什么、哪一步需要你自己拍板」
> 写清楚。涉及商业使用 / 对外分发时，请以各项目官方许可原文为准，必要时咨询法务。
>
> **2026-11-07 修正**：公开 Release 曾误带 `tools/npcap-1.79.exe`，已撤下。现在
> **公开件只发 lite 代码包；第三方二进制只出现在内部离线包里**。本文所有结论按此写死。

---

## 0. 结论（三句话，不再“选一个”）

1. **公开仓库 / 公开 Release 只发 lite 包**：源码 + 文档 + 测试 + `自检.bat` + `README.txt`，
   **不含** Wireshark、Npcap、Python 等任何第三方二进制。用户自己安装，
   本项目不构成对第三方组件的再分发。
2. **内部离线包 `--with-tools`**：带便携 Python + Wireshark（GPL），**不带 Npcap 安装器**；
   只在本组织内部 / 离线机器使用，**不要外传**。Wireshark 的 `COPYING.txt` 必须随包保留。
3. **内部离线包 `--with-npcap`**：在 `--with-tools` 基础上再带 `npcap-1.79.exe`，
   **只能在组织内部使用**；**不得**上传公开仓库、公开 Release、网盘或外网。
   把这个包发给相关方 = 在你们组织内部分发，是否合规由你们与 IT / 法务确认。
   **公开 repo 的 Release 永远不带 Npcap。**

> 一句话：**公开件只发代码，内部件才带 tools。**

---

## 1. 三种包分别装了什么

| 包 | 构建命令 | 便携 Python | Wireshark / tshark | Npcap 安装器 | 能发给谁 |
|---|---|---|---|---|---|
| **lite（默认）** | `python scripts\build_release.py` | ❌ 用户自装 3.11+ | ❌ 用户自装 Wireshark | ❌ 用户从 npcap.com 自装 | **任何人 / 公开 Release** |
| **内部离线** | `... --with-tools` | ✅ 包内 | ✅ 包内（GPL，保留许可） | ❌ 用户自装 | 本组织内部，**不外传** |
| **内部离线 + Npcap** | `... --with-npcap` | ✅ 包内 | ✅ 包内（GPL，保留许可） | ✅ 包内 | **仅限组织内部使用**，禁止公开 |

产物名、体积与用途对照见 [`build.md`](build.md) §1。三者的**构建自检**都会真解压、
真跑 235 条测试 + 启动器契约；`--with-npcap` 构建时会打印醒目警告。

---

## 2. Npcap（重点，结论已写死）

### 2.1 官方条款（截至 2026-11）

- Npcap 版权归 **Nmap Software LLC（The Nmap Project）**，**不是开源软件**；
  源码可下载供审查，但未经特别许可不得再分发、不得嵌入其他软件。
- 免费版通常**最多安装在 5 台系统**上；官方原文：
  *“The free version of Npcap may be used (but not externally redistributed) on up to 5 systems.”*
- 免费版**可以**在「只配合 Nmap / Wireshark / Microsoft Defender for Identity 使用」时不受 5 台上限。
- 商业再分发 / 大批量内部部署需要 **Npcap OEM**（Redistribution 或 Internal-Use 许可）。

来源：

- <https://npcap.com/>
- <https://github.com/nmap/npcap/blob/master/LICENSE>
- <https://npcap.com/oem/redist.html>

### 2.2 本项目已落地的处置（不再提供可选项）

| 场景 | 本项目怎么做 | 谁承担合规责任 |
|---|---|---|
| **公开 GitHub Release** | **只上传 `NetDiag-<VERSION>-lite.zip` + `SHA256SUMS.txt`**；包里没有 Npcap，也没有 Wireshark | 用户自行到官网下载安装，许可关系在用户与 Nmap / Wireshark 之间 |
| **组织内部离线使用** | 用 `--with-tools`（不含 Npcap，用户自装）或 `--with-npcap`（含安装器，仅内部分发） | 使用组织；对外传播前必须自行评估 Npcap 条款 |
| **商业产品内置 / 大批量部署** | 本项目不提供这种包；请购买 Npcap OEM 或只依赖用户机器上已装的 Npcap | 公司 / 法务 |

- **公开 repo 的 Release 永远不带 Npcap**。公开资产清单里出现 `npcap` 即视为发版错误，
  按 [`build.md`](build.md) §8 的检查清单拦住。
- `--with-npcap` 构建会在开始和结束各打印一次
  `Npcap free edition may NOT be externally redistributed` 警告；
  包内 `README.txt` 也写明「禁止上传公开仓库 / 网盘 / 外网」。
- `自检.bat` 在缺少 Npcap 时只给 **WARN**（分析抓包文件不需要它），并且：
  - lite / `--with-tools` 包：提示去 <https://npcap.com/#download> 安装；
  - `--with-npcap` 包：探测到 `tools\npcap-*.exe` 才提示运行包内安装器。
- 本项目**不在 Python 代码里**做提权 / Npcap 静默安装；`start.bat` 的自动安装只对
  **带安装器的内部包**生效，不改变许可责任归属。

### 2.3 把 `--with-npcap` 包发给相关方，算什么？

- 那是**你们组织内部的分发**，不是「公开再分发」；但 Npcap 免费版条款、公司软件资产制度、
  以及你所在组织与 Nmap 的许可关系仍然适用。
- **是否合规由你们与 IT / 法务确认**，本项目不替你做这个决定。
- **不要**把它上传到公开 GitHub 仓库 / 公开 Release / 公开网盘 / 任何外网可下载的位置。
- 如果只是给组织内使用，优先选 `--with-tools`（不带 Npcap），让使用方自己从官网装；
  这样连「内部再分发」都不涉及。

### 2.4 不想碰 Npcap 时

- **分析抓包文件不需要 Npcap**：tshark 读 pcap 只依赖 Wireshark / 系统安装，
  `自检.bat` 会明确区分「tshark 缺失（WARN）」与「Npcap 缺失（WARN）」。
- 全网体检 / 单目标诊断 / 通信观察才需要 Npcap + 管理员。缺 Npcap 时 `start.bat` 会降级提示，
  不会崩。

---

## 3. Wireshark（GPL-2.0-or-later）

- **lite 包不携带 Wireshark**：用户自己安装，本项目不承担 GPL 再分发义务。
- **内部离线包携带 Wireshark 4.7.4 官方 Portable 包，未做任何修改**：
  - GPL 允许再分发（包括商业再分发），前提是附许可文本、保留版权声明，并能提供**对应源码**；
  - 许可文本在 `tools\WiresharkPortable\App\Wireshark\COPYING.txt`，**不能删**；
  - 对应源码从 <https://www.wireshark.org/download/src/> 下载 4.7.4 版本；
    如果公司合规要求随包附源码归档，请把源码 zip 放到包旁或在内部说明里给固定链接；
  - **内部包不要外传**：一旦对外分发，GPL 的源码提供义务就落到分发者头上。
- 本项目没有修改 Wireshark，因此不需要提供修改后的源码。

---

## 4. Python（PSF-2.0）

- **lite 包不携带 Python**：要求系统 Python 3.11+（<https://www.python.org/downloads/windows/>）。
- **内部离线包携带便携 Python 3.11.9**：`tools\python\LICENSE.txt` 已随包保留。
- PSF 许可允许再分发（含商业用途），不要求公开你自己的代码。
- 不要把 `tools\python\LICENSE.txt` 删掉来「减小体积」——省不了多少空间，还会违反许可。

---

## 5. Scapy（GPL-2.0）

- 通信观察（被动监听）用的 Scapy 2.8.0 只存在于内部离线包的
  `tools\python\Lib\site-packages\scapy\`，许可文本在
  `scapy-2.8.0.dist-info\licenses\LICENSE`。
- 与 Wireshark 一样是 GPL：再分发需附许可文本；源码可从 <https://scapy.net/> 获取。
- lite 包不含 Scapy；通信观察（被动监听）在 lite 下需要用户自装（或不可用），不影响分析抓包文件。

---

## 6. 本项目自身

- 本项目源代码采用 **MIT License**：见仓库根目录 [`LICENSE`](../LICENSE)，
  Copyright (c) 2026 **NetDiag contributors**。
- MIT 只覆盖本项目自己编写的代码与文档；`tools/` 内的 Python、Wireshark、Npcap、Scapy
  仍按各自许可（见上文 §2~§5），不受 MIT 影响。
- 本文档、`scripts\build_release.py`、`自检.bat` 随项目 MIT 许可发布；第三方组件的
  再分发边界仍以各项目官方许可原文为准。

---

## 7. 发布前检查清单（发公开 Release 时逐条过）

- [ ] 上传的附件**只有** `NetDiag-<VERSION>-lite.zip` 和 `SHA256SUMS.txt`。
- [ ] `gh release view` / `gh api .../releases/tags/vX.Y.Z` 的资产列表里**没有** `npcap`、
      **没有** `Wireshark`、**没有** `tools`。
- [ ] lite 包解压后**没有** `tools/` 目录（构建脚本的 `assert_manifest` 会断言）。
- [ ] Release notes 写明「Python / Wireshark / Npcap 需自行安装」及官网链接。
- [ ] 没有把 `config\ai-config.json`（可能含 API Key）打进包。
- [ ] 没有在包里放 `harness\`。
- [ ] 内部包（`--with-tools` / `--with-npcap`）**没有**被上传到公开仓库或公开网盘。
- [ ] 内部包保留 `WiresharkPortable\App\Wireshark\COPYING.txt`、`python\LICENSE.txt`、
      `scapy-2.8.0.dist-info\licenses\LICENSE`。

---

*最后更新：2026-11-08（R 轮补充项目自身 MIT 许可）。许可条款可能变化，以官方原文为准。*
