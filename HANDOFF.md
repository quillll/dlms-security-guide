# Handoff · DLMS/COSEM 安全套件教学空间

> 生成时间：2026-10-07 11:59 (+08:00)
> **更新：2026-10-08 00:xx (+08:00)** —— 第 4/5/6 课已完成交付（见 §2、§3）。
> 保存位置：**工作区目录**（`D:\project\personal\teach-me\dlms\HANDOFF.md`）。
> 说明：`handoff` skill 默认写到系统临时目录，本次按用户的要求（"交接到工作区目录"）改为写入工作区。
>
> **接手前先读这三份，不要重新发明**：
> 1. [MISSION.md](MISSION.md) — 学习目标与边界（每课取舍依据）
> 2. [NOTES.md](NOTES.md) — 核实台账、自我纠错、待办与悬而未决项（**最重要的上下文**）
> 3. [RESOURCES.md](RESOURCES.md) — 本地规范/实现/社区资源的位置与用途

---

## 1. 这是什么

用户用 `/teach` 启动的**长期教学空间**：主题是 **DLMS/COSEM 安全套件（Suite 0/1/2）与报文级加解密**。
用户目标（已确认）：在**实现/对接 DLMS 客户端或服务端**（电表通信）、**读懂绿皮书/蓝皮书原文**、先建立整体认知。
起点：**DLMS 基础已具备**（OBIS、COSEM 对象、HDLC/wrapper），**密码学是初学**。授课语言中文，术语保留英文。

工作区已在 [index.html](index.html) 建成课程首页；**课程产物是 HTML 课 + 参考文档 + 可复用组件 + 对拍脚本**。

## 2. 已交付（内容不要重写，直接引用）

| 类型 | 文件 | 一句话 |
|---|---|---|
| 课 1 | [lessons/0001-security-suites-overview.html](lessons/0001-security-suites-overview.html) | Suite 0/1/2 对照（Table 27）、SC 字节位图、SC 解码器、4 道检索练习 |
| 课 2 | [lessons/0002-apdu-byte-level-crypto.html](lessons/0002-apdu-byte-level-crypto.html) | `Tag‖Len‖SH‖内容‖tag`、Table 48 三条报文、P/AAD/IV、报文拆分器、对拍脚本 |
| 课 3 | [lessons/0003-general-ciphering-key-info.html](lessons/0003-general-ciphering-key-info.html) | general-* 两层结构、key-info 三种 CHOICE、三种密钥协商方案 |
| 课 4 | [lessons/0004-association-authentication-hls-gmac.html](lessons/0004-association-authentication-hls-gmac.html) | 三种认证等级、四趟 HLS、Table 50 七种 mechanism（3/4 不推荐）、Table 51 GMAC 向量实测 |
| 课 5 | [lessons/0005-keys-overview-and-kek-rotation.html](lessons/0005-keys-overview-and-kek-rotation.html) | Table 28 六把对称密钥、三条建立路径、`key_transfer` 参数、KEK 轮换五步 |
| 课 6 | [lessons/0006-security-setup-object-in-practice.html](lessons/0006-security-setup-object-in-practice.html) | OBIS 与"一个 AA 一个"、`security_policy` 位图、`security_suite` 枚举、方法 1–8、对接清单 |
| 参考 | [reference/security-suites.html](reference/security-suites.html) | Table 27 逐字、尺寸表、SC 位图、P/AAD、**套件与计数器对象配在哪里**（含 OBIS）、四个常见混淆 |
| 参考 | [reference/crypto-primer.html](reference/crypto-primer.html) | AES-GCM / key wrap / ECDH / ECDSA / SHA 的最小直觉（给密码学初学用） |
| 组件 | [assets/course.css](assets/course.css) · [assets/quiz.js](assets/quiz.js) · [assets/sc-decoder.js](assets/sc-decoder.js) · [assets/frame-splitter.js](assets/frame-splitter.js) | 共享样式、测验组件、SC 解码器、报文拆分器（已支持 general-* 两层） |
| 脚本 | [assets/verify-dlms-gcm.py](assets/verify-dlms-gcm.py) | **10 组规范测试向量自动对拍**（Table 48 三条 + Annex C.1 KDF + C.2/C.3 四方向 + **Table 51 两条 HLS GMAC**） |
| 脚本 | [assets/check-workspace.py](assets/check-workspace.py) | **（新增）工作区 HTML 校验**：标签闭合 / 内部链接 / 跨文件锚点 / 组件引用完整性。改完 HTML 跑一次 |
| 学习记录 | [learning-records/0001-starting-point-dlms-basics-crypto-beginner.md](learning-records/0001-starting-point-dlms-basics-crypto-beginner.md) | 起点与已披露的先验知识 |
| 素材库 | `.research/green-book-security-extract.md` · `.research/green-book-annex-extract.md` · `.research/gurux-implementation-extract.md` | 从绿皮书/蓝皮书/Gurux 三语言实现抽取的**带章节号与行号引证**的原始事实。**备课时先查这里；不要整份读进上下文（贵）** |

## 3. 本轮完成的工作与下一步

### 3.1 本轮（2026-10-07）完成了什么

用户在交接后给出指令 **"了解交接文档继续完成剩余所有课程"**。按原计划完成了**剩余全部三课（第 4/5/6 课）**，用户目标文档 MISSION.md 的六条"Success looks like"现在都有对应课程与可验证产物。

1. **先把 Table 51 的两条 GMAC 向量加进对拍脚本并跑通**（这是交接文档指定的"接手第一件事"）。
   - 结果：**全部一致**；脚本现为 4 部分 · 10 组向量。
   - ⚠️ **过程中发现一个规范未明写的点**：GMAC 的 IV 用的是"**计算方自己**"的 `Sys-T ‖ IC`，而不是"挑战发起方"的。
     我最初的假设被向量驳回，枚举 16 种组合后确认。判定证据：Table 51 印出的 `f(StoC) = 10 00000001 …`（客户端 IC）、`f(CtoS) = 10 01234567 …`（服务端 IC）。
     **已按"反推、非规范明文、对接需实测"三层标注写进第 4 课与 NOTES。**
2. **第 4 课** `lessons/0004-association-authentication-hls-gmac.html`（约 18 分钟）。
3. **第 5 课** `lessons/0005-keys-overview-and-kek-rotation.html`（约 17 分钟）。
4. **第 6 课** `lessons/0006-security-setup-object-in-practice.html`（约 16 分钟）。
5. **新增 `assets/check-workspace.py`**（落实原 §5 的建议）：HTML 标签闭合 / 内部链接 / 跨文件锚点 / 组件引用一次校验。**9 个 HTML 全部通过。**
6. 更新 `index.html`（三课由"计划中"转为正式卡片）与 `NOTES.md`。

### 3.2 下一步的候选（用户尚未选，**建议先问**）

用户是"实现/对接"取向，以下按"离实际设备由近到远"排序：

- **数字签名与证书**（缺口最明确）：绿皮书 §9.5 / Annex B；**且必须处理 NOTES 里记的那处规范内部冲突**——§9.2.3.4.5 要求 ECDSA 签名用 plain format（R‖S），而附录 B 的证书示例用 DER SEQUENCE。第 4 课的 mechanism 7 已点到但未展开。
- **Data protection 对象**（蓝皮书 §4.4.9）：第 5/6 课多处引用"protection parameters"但没讲这个对象本身。若用户要保护的是某几个数据点而非整条链路，这一课很实用。
- **抓包实战**：用本地 Gurux Translator（见 RESOURCES.md）解析用户真实 hex 帧；**这是把六课内容收口的最好方式**，且完全依赖用户提供素材。
- **参考文档补全**：`reference/glossary.html`（术语表，**尚未创建**，index.html 里仍标为"计划中"）。

### 3.3 若用户继续给"继续"

默认动作：按 3.2 第一条做"数字签名与证书"，因为它是当前唯一有**明确规范冲突待处理**的缺口。但**最好还是用一句话让用户选**（用户在意成本，一次选错方向比多问一句更贵）。

## 4. 教学约定（必须延续，否则产物会退化）

1. **一课一件事**，10–20 分钟可完成；宁少勿多（工作记忆优先）。
2. **一切事实都要给出处**：`文件名 + §章节号 + Table 号`（必要时页码 `<!-- p.xxx -->`）。规范原文在 `D:\project\personal\dlms\GreenBook\output\book\ai\...` 与 `...\blue-book-v2\ai\...`。
3. **必须区分"规范原文"与"我推导的"**——例如 `Len` 语义是从 Table 48 反推的，课内与 NOTES 都明确标注。凡推导，都要能被用户验伪。
4. **自带标准答案的练习优先**：规范测试向量 → 脚本对拍 → 让用户"先预测再验证"。已建立的模式见第 2 课。
5. **组件复用**：新课先读 `assets/`，能复用就不新写；新组件写成文件并让课内 link，禁止课内内联可复用代码。
6. 每课必备：目标/产出标头、mission 行、关键结论 callout、等字数的选择题、`details` 检索练习、一手来源、"卡住就问"块、与 index 及相邻课的互链、打印友好（`@media print` 已覆盖）。
7. **中文授课**；术语保留英文并给中文解释。
8. **学习记录只在有证据时写**（LR-0002 **仍未写**：用户已连续推进了 6 课，但**还没交过练习答案、预测、报错或抓包**。等他跑脚本、报预测、贴抓包或代码，再把证据写进 `learning-records/0002-*.md`）。
   - **接手时的一个建议**：现在课程已自成体系，**最值得邀请用户做的动作是"跑一次脚本、回一个预测"**——这既是检索练习，也是我们唯一能拿到学习证据的渠道。

## 5. 环境与坑（省时间用）

- **工作区权限曾被 Windows ACL 挡住**（DSH sandbox 无法 grantWrite）。已修好；改动有备份与一键回滚：`D:\project\personal\teach-me\dlms-acl-recovery\`（`acl-backup-*.json.ps1`）。若再出现 `SetNamedSecurityInfoW failed` / `file access denied`，加载 `diagnose-windows-sandbox-acl` skill，按它的一条命令流程处理。
- **Python**：系统 `python` = 3.14，**已装 `cryptography` 49.0.0**（本工作区唯一需要的外部依赖）。脚本会 `sys.stdout.reconfigure(encoding="utf-8")`；命令行跑之前建议 `chcp 65001` + `$env:PYTHONIOENCODING='utf-8'`，否则中文输出乱码。
  - ⚠️ **注意**：`~/.workbuddy/binaries/python/...` 那个"托管"解释器**没有** `cryptography`；本工作区要用**系统** Python（`C:\Users\quill\AppData\Local\Microsoft\WindowsApps\python.exe`）。直接 `python xxx.py` 即可（PATH 指向系统版）。
- **PowerShell 是 5.1**（不是 pwsh 7）：`Get-Content -Encoding 1252` 不被接受，要 `-Encoding Default` 或 `[System.IO.File]::ReadAllLines($f, [System.Text.Encoding]::GetEncoding(1252))`。
- **`Gurux.DLMS.Net\Development\Secure\GXSecure.cs` 不是合法 UTF-8**（含一个非 ASCII 字节）→ `read` 工具会报 `invalid UTF-8 text`，必须用上面的 ANSI 读法。其他文件正常。
- **Node 可用**：`node --check` 用来验 JS 语法；也可用一小段 node 脚本独立复算 JS 里的字节切分逻辑（第 3 课就是这么验的）。
- **HTML 校验**：已固化为 **`assets/check-workspace.py`**（本轮新增）。每次改完 HTML 跑一次，检查「标签闭合 / 内部链接存在性 / 跨文件锚点存在性 / 组件引用完整性」。它能立刻发现坏链接/假锚点——第 2 课就抓到过 3 个指向不存在锚点的卡片。
- **长 hex 的处理纪律**（血泪教训，详见 NOTES）：从转换稿里抄长 hex 必须**用规范标注的总长度校验**；规范表格的注释格式是「`<hex> // <字段名>`」，且长 hex 会在换行处被空格切断（切断点可能是半个字节），**不要按"偶数长度"过滤片段**。第 3 课我一度引用了少两个 `00` 的拼接串，就是靠"必须等于 401 字节"发现的。

## 6. 成本约束（用户明确问过）

模型是 `deepseek-flash`，官方价（[价目页](https://api-docs.deepseek.com/zh-cn/quick_start/pricing/)）：输入缓存命中 ¥0.02/百万（空闲）· 未命中 ¥1/百万 · 输出 ¥4/百万；**高峰为周一至周五 09:00–12:00、14:00–18:00（北京时间），其余时段减半**。
用户在意花费。**最省的做法**：不要整份读 `.research/` 里的大文件（3 份共 256 KB，已在历史里付过费）；需要事实时用 `grep` 定位后只读相关行；尽量不开子代理（一次大规模抽取约 ¥0.5–1.5）。单课（含验证）实测量级 **¥0.2–0.5（夜间）**。

## 7. 未决 / 需要问用户的

1. **用户偏好的实现语言未知**：本地同时有 C#（Gurux.DLMS.Net）、Java、ANSI-C、Rust 参考。做代码级练习前先问。
2. 是否有真实设备/型号/项目规范可以对接（用户首次回答是"暂无，先讲通用知识"）——可以再确认一次。
3. **下一课方向**：见 §3.2 的四个候选（数字签名与证书 / Data protection 对象 / 抓包实战 / 术语表）。用户在意成本，**建议一句话让其选**，不要默认连做多课。
4. **`reference/glossary.html` 仍未创建**（index.html 里标为"计划中"）——若用户想要一份可打印的统一口径，这是低成本高价值的一项。

## 8. Suggested skills

- **`teach`（必载）** —— 本工作区的核心 skill：课程/参考/学习记录/资产的结构与哲学（fluency vs storage strength、ZPD、检索练习、组件复用）。**每轮开始先加载它**，否则产物结构会走样。
- **`research`** —— 需要补规范之外的高可信来源（NIST、DLMS UA、论文）时用；产出仍应落在 `reference/` 或 `RESOURCES.md`，不要散落。
- **`diagnose-windows-sandbox-acl`** —— 一旦再遇到工作区文件权限拒绝（本会话发生过一次）。
- **`domain-modeling`** —— 可选：当要正式建立**计划中的** `reference/glossary.html`（术语表；**该文件尚未创建**）时，用它来统一口径。
- **`office-docx` / `office-xlsx` / `office-pptx`** —— 仅当用户要"可交付文档"（例如把三课整理成一份报告/PPT）时使用；课程本身是 HTML，不要主动转格式。

## 9. 30 秒上手清单

```powershell
cd D:\project\personal\teach-me\dlms
# 1) 读上下文（按顺序）
#    MISSION.md → NOTES.md → RESOURCES.md → index.html
# 2) 跑一遍对拍脚本，确认环境没坏（应打印 4 部分全 ✓ + "全部对上"）
chcp 65001; $env:PYTHONIOENCODING='utf-8'; python assets\verify-dlms-gcm.py
# 3) 跑一遍 HTML 校验（应 9 个文件全 ✓）
python assets\check-workspace.py
# 4) 打开当前进度
Start-Process lessons\0006-security-setup-object-in-practice.html
# 5) 续做下一课：先看 §3.2 的候选并**让用户选一个**，再按既有模式（备课 → 对拍 → 写课 → 校验 → 更新 index/NOTES）推进
```

规范原文检索入口（grep 用）：

```
D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md
D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-4-dlms-cosem-application-layer-protocol-specificat.md
D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md
D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch6\markdown\ch6-6-2-abstract-cosem-objects.md
D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\
```
