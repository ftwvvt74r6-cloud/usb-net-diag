# 第三方许可与再分发提醒

> 这份文件**不是法律意见**，只把「包里到底装了什么、各自什么许可、哪一步需要你自己拍板」
> 写清楚。涉及商业使用 / 对外分发时，请以各项目官方许可原文为准，必要时咨询法务。

---

## 0. 三句话结论

1. `tools\` 里是三个**独立第三方组件**：Npcap、Wireshark（含 tshark）、Python（含 Scapy）。
   它们不是本项目代码，各自许可不同，不能用一个 LICENSE 概括。
2. **Npcap 免费版不允许对外再分发**。官方原文：free edition *may be used (but not externally
   redistributed) on up to 5 systems*。把 `npcap-1.79.exe` 放进 zip 并公开下载，属于「对外分发」，
   需要 Nmap Project 的 OEM 再分发许可 —— **这一条必须由维护者/用户决定**，本工具不替你决定。
3. Wireshark 是 GPL-2.0-or-later、Python 是 PSF-2.0、Scapy 是 GPL-2.0；许可文本已随包保留。
   本仓库自身**还没有 LICENSE 文件**（默认保留所有权利），对外开源前要先补。

---

## 1. 组件清单

| 组件 | 版本 | 许可 | 包内位置 | 许可文本 |
|---|---|---|---|---|
| **Npcap** | 1.79（安装包） | 专有免费软件（非开源） | `tools\npcap-1.79.exe` | 安装器内 EULA；[官方 LICENSE](https://github.com/nmap/npcap/blob/master/LICENSE) |
| **Wireshark / tshark** | 4.7.4 | GPL-2.0-or-later | `tools\WiresharkPortable\` | `App\Wireshark\COPYING.txt` |
| **Python** | 3.11.9（Embedded） | PSF-2.0 | `tools\python\` | `LICENSE.txt` |
| **Scapy** | 2.8.0 | GPL-2.0 | `tools\python\Lib\site-packages\scapy\` | `scapy-2.8.0.dist-info\licenses\LICENSE` |
| **本项目代码** | 0.2.0 | 未声明（仓库无 LICENSE） | 仓库其余文件 | 无 |

> WiresharkPortable 是 PortableApps.com 格式的官方便携包（`AppInfo\appinfo.ini` 标注
> `Shareable=true / OpenSource=true / CommercialUse=true`），本仓库只原样携带，**未修改**。

---

## 2. Npcap（重点，必须自己拍板）

### 2.1 官方条款（截至 2026-11 抓取）

- Npcap 版权归 **Nmap Software LLC（The Nmap Project）**，**不是开源软件**；源码可下载供审查，
  但未经特别许可不得再分发、不得嵌入其他软件。
- 免费版通常**最多安装在 5 台系统**上。
- 免费版**可以**在「只配合 Nmap / Wireshark / Microsoft Defender for Identity 使用」时不受 5 台上限。
- 商业再分发 / 大批量内部部署需要买 **Npcap OEM**（Redistribution 或 Internal-Use 许可）。

来源：

- <https://npcap.com/>（"The free version of Npcap may be used (but not externally redistributed) on up to 5 systems"）
- <https://github.com/nmap/npcap/blob/master/LICENSE>
- <https://npcap.com/oem/redist.html>（OEM 再分发许可）

### 2.2 对本项目的三种处理方式（选一个，不要默认）

| 场景 | 建议 | 谁来决定 |
|---|---|---|
| **A. 自己/团队内部用**（≤5 台，或只配合 Wireshark/Nmap） | 保留 `tools\npcap-1.79.exe`，按免费许可使用；注意不要再把 zip 转给别人 | 使用者 |
| **B. 公开 GitHub Release / 对外分发 zip** | 需要 **Npcap OEM Redistribution License**；否则从公开发布件里**剔除** `tools\npcap-*.exe`，改为让用户自己到 <https://npcap.com/#download> 下载安装 | 维护者 + 法务 |
| **C. 商业产品内置** | 买 OEM 许可；或只依赖用户机器上已装的 Npcap | 公司 |

> 本项目**不在 Python 代码里**做提权/Npcap 静默安装；`start.bat` 的自动安装与
> `自检.bat` 的「缺 Npcap → 提示运行 `tools\npcap-*.exe`」都只是给使用者的便利，
> 不改变许可责任归属。

### 2.3 不想碰 Npcap 时

- **离线分析不需要 Npcap**：tshark 读 pcap 只依赖内置的 WiresharkPortable，
  `自检.bat` 会明确区分「tshark 缺失（FAIL）」与「Npcap 缺失（WARN）」。
- 实时抓包 / 被动监听才需要 Npcap + 管理员。缺 Npcap 时 `start.bat` 会降级提示，
  不会崩。

---

## 3. Wireshark（GPL-2.0-or-later）

- 本包携带的是 **Wireshark 4.7.4 官方 Portable 包，未做任何修改**。
- GPL 允许再分发（包括商业再分发），前提是：附许可文本、保留版权声明、
  并能提供**对应源码**。许可文本已在 `tools\WiresharkPortable\App\Wireshark\COPYING.txt`。
- 对应源码从 <https://www.wireshark.org/download/src/> 下载 4.7.4 版本；
  如果公司合规要求「随包附带源码归档」，请把源码 zip 放到 `tools\WiresharkPortable\` 旁边或
  在 Release 说明里给出固定链接。
- 本仓库没有修改 Wireshark，因此不需要提供修改后的源码；但**不能**去掉 `COPYING.txt`。

---

## 4. Python（PSF-2.0）

- 便携 Python 3.11.9 的 `tools\python\LICENSE.txt` 已随包保留。
- PSF 许可允许再分发（含商业用途），不要求公开你自己的代码。
- 不要把 `tools\python\LICENSE.txt` 删掉来「减小体积」——省不了多少空间，还会违反许可。

---

## 5. Scapy（GPL-2.0）

- 被动监听的 Scapy 2.8.0 在 `tools\python\Lib\site-packages\scapy\`，
  许可文本在 `scapy-2.8.0.dist-info\licenses\LICENSE`。
- 与 Wireshark 一样是 GPL：再分发需附许可文本；源码可从 <https://scapy.net/> 获取。

---

## 6. 本项目自身

- 仓库当前**没有 `LICENSE` 文件**，按著作权法默认「保留所有权利」。
  这不影响你自用，但**对外分发代码/二进制前**需要维护者先决定用哪个许可并补上 `LICENSE`。
- 本文档、`scripts\build_release.py`、`自检.bat` 随仓库现有政策走，不单独授权。

---

## 7. 发布前检查清单

- [ ] 已确认 Npcap 的再分发权限（或已从公开资产中剔除 `npcap-*.exe`，并在 README 写明让用户自装）。
- [ ] 包内保留 `WiresharkPortable\App\Wireshark\COPYING.txt`、`python\LICENSE.txt`、
      `scapy-2.8.0.dist-info\licenses\LICENSE`。
- [ ] Release notes 里列出第三方组件、版本与许可链接（本文件可整体附上）。
- [ ] 没有把 `config\ai-config.json`（可能含 API Key）打进包。
- [ ] 没有在包里放 `harness\`（DeepSeek Harness 与本工具许可无关，且体积 540 MB）。
- [ ] 如果公司要求「源码随包」，已附 Wireshark 4.7.4 源码归档或固定下载链接。

---

*最后更新：2026-11-07（v0.2.0 打包轮）。许可条款可能变化，以官方原文为准。*
