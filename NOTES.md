# Working notes

## 用户偏好

- 授课语言：中文（术语保留英文原文，中文解释）。
- 起点（2026 首次会话自述）：DLMS/COSEM 基本概念已具备（OBIS、COSEM 对象、HDLC/wrapper）；**密码学是初学**。
  → 涉及 AES-GCM / ECDH / ECDSA 时，先给最小必要直觉（一两句话 + 一张图），再进规范条款。
- 目的（多选）：实现/对接 DLMS 客户端或服务端；读懂规范原文；先建立整体认知。
- 现场信息：暂无具体设备/型号 → 以规范原文 + 本地 Gurux 实现作为可验证的锚点。
- 明确想要的第一个主题：Suite 0/1/2 的详细区别与加解密算法。

## 工作区约定

- 本地资料根目录：`D:\project\personal\dlms\`
  - 规范 Markdown（由 PDF 转换）：`GreenBook\output\book\ai\...`（绿皮书 Ed.11）、`GreenBook\output\blue-book-v2\ai\...`（蓝皮书 Ed.17 part 2）
  - 原始 PDF：`GreenBook\..\Green-Book-Ed-11-V1-0.pdf`、`Blue-Book-Ed-17-part-2-V1.0.pdf`
  - 参考实现：`Gurux.DLMS.Net\Development`（C#）、`gurux.dlms.java-master\development`（Java）、`GuruxDLMS.c\development`（C）
  - 工具：`GuruxDLMSTranslatorStandalone\...\GuruxDLMSTranslatorStandalone.exe`（可粘贴 hex 解析 DLMS 帧，含安全层——后续做"动手验证"练习的候选工具）
- 引文约定：引用规范必须给出**文件名 + 章节号**（例如 `ch9-9-2-...md §9.2.4.x`），并在 `RESOURCES.md` 中登记。
- `.research/` 存放子代理从规范/代码中抽取的原始事实（带行号/章节号的引证），供后续课程复用；不属于课程产物，可随时重建。

## 待办与悬而未决

- **`.research/gurux-implementation-extract.md` 尚在生成中**（从 Gurux C#/Java/C 抽取套件与加解密的实现级事实）。它落地后应做的事：把"规范怎么说"与"实现怎么做"对照一遍，挑 3–5 处做第 2 课的验证练习（尤其是 IV/AAD 构造、tag 长度、计数器处理）。
  → **注：该文件已在 `RESOURCES.md` 中记为"已完成（约 2300 行）"，与这里的描述不一致；下次核实时以 RESOURCES.md 为准。**
- **已核实（原疑点已解决）**：Security setup 实例 OBIS 为 `0-0:43.0.e.255`（IC 64），Invocation counter 实例为 `0-b:43.1.e.255`（IC = Data，旧称 frame counter object；B = 通信通道，E 与对应 Security setup 的 E 相同）——出处 `blue-book-v2\ai\ch6\markdown\ch6-6-2-abstract-cosem-objects.md` §6.2.36, p.656。两者已写入 `reference/security-suites.html` §6 与第 6 课。之前搜不到是因为 OBIS 在这份转换稿里是"按列拆开"的表格（A/B/C/D/E/F 各一格），不是连写的字符串。
- **用户偏好的实现语言未知**（本地同时有 C#、Java、C、Rust）。第一次做代码级练习前先问。
- 绿皮书 §9.2 文本中**没有**"从主密钥派生 EK/AK"的公式（子代理逐节确认）。若后续在别处（蓝皮书 Security setup / 某客户规范）看到该做法，需明确标注依据来源，避免把实现惯例当成规范要求。
- 证书签名格式存在一处**规范内部未解决的冲突**：§9.2.3.4.5 要求 ECDSA 签名用 plain format（R ‖ S 定长），而附录 B 的证书示例中 signatureValue 是 DER SEQUENCE of two INTEGERs。第 4 课已上线，但**这一冲突尚未讲**（第 4 课聚焦认证机制与 GMAC，未展开证书签名格式）——留给后续"数字签名与证书"课。
- **（2026-10-07 新增）HLS GMAC 的 IV 构造规范未明写**：Table 50 只给 f 的输出形式 `SC ‖ IC ‖ T`，**不说** IC 取自哪一端、IV 怎么拼、IC 何时递增。已从 Table 51 两条向量**反推**并枚举验证：**IV 用"算这一趟的那一方"（本端）的 `Sys-T ‖ IC`**（客户端算 f(StoC) 用客户端 SysT‖IC；服务端算 f(CtoS) 用服务端 SysT‖IC）。第 4 课已明确标注"反推、非规范明文"，并提示 Gurux 的 `IncreaseInvocationCounterForGMacAuthentication` 默认 true 是实现侧变量。**对接真实设备必须实测。**

## 已交付

- **第 4 / 5 / 6 课已完成并实测通过**（2026-10-07，本轮）：
  - **第 4 课 `lessons/0004-association-authentication-hls-gmac.html`**：三种认证等级（no security / LLS / HLS）、四趟 HLS（Pass1 CtoS in AARQ、Pass2 StoC in AARE、Pass3 f(StoC)、Pass4 f(CtoS)）、Table 50 七种 mechanism（含 3/4 不推荐的原文脚注）、Table 83 的 mechanism_id、AARQ/AARE 的 `calling-AP-title`/`calling-AE-qualifier`。
    - **对拍脚本新增第 4 部分**：Table 51 的 mechanism 5（GMAC）两条向量（`1A52FE7DD3E72748973C1E28` / `FE1466AFB3DBCD4F9389E2B7`），**实测一致**。脚本现为 **4 部分 · 10 组向量**。
    - **本轮最重要的发现**：HLS GMAC 的 IV 用的是"**计算方自己**"的 `Sys-T ‖ IC`（我最初的"挑战发起方"假设被向量驳回，枚举后确认）。规范未明写，已按"反推 + 需实测"标注（见上面待办）。
  - **第 5 课 `lessons/0005-keys-overview-and-kek-rotation.html`**：Table 28 六把对称密钥（master key/KEK、GUEK、GBEK、GAK、dedicated key、ephemeral key）的用途与三条建立路径（Out of band / key wrapping / key agreement）；`key_transfer` 参数结构（蓝皮书 §4.4.7.3.2）与 `key_id` 0–3；**KEK 轮换五步**（用旧 KEK 包新 KEK、成功后立即生效）、两类典型事故、"失败即全不变"的原子性。
  - **第 6 课 `lessons/0006-security-setup-object-in-practice.html`**：OBIS `0-0:43.0.e.255` 与"一个 AA 一个"、Invocation counter 的**通道语义**（B 段；远程口/本地口 IC 可能不同）；属性 1–6（含 `security_policy` 位图逐 bit 与 `security_suite` 0/1/2 枚举逐字）、方法 1–8、`security_activate` 的"单向棘轮"规则；附"新接手一台表读什么"的 6 步对接清单与排障三连。
- **新增 `assets/check-workspace.py`**（落实 HANDOFF §5 的建议）：一次校验全部 HTML 的「标签闭合 / 内部链接存在性 / 跨文件锚点存在性 / 组件引用完整性（quiz 选项数、脚本是否 link）」。**本轮 9 个 HTML 全部通过。** 用法：`python assets/check-workspace.py`。
- **`index.html` 已更新**：第 4/5/6 课从"计划中"改为正式卡片；对拍脚本说明更新为"10 组向量"。

- **第 3 课已完成并实测通过**（`lessons/0003-general-ciphering-key-info.html`）：
  - 新验证：从规范原文（Annex C.2）**逐字节重拼** general-ciphering 的请求/响应报文，并用"总长必须等于规范标注的 401 / 226 字节"校验通过；字段推进到最后一字节<b>剩余为 0</b>，全部自洽。
  - 对拍脚本增至 8 组向量：Table 48 三条报文 + Annex C.1 的 KDF + Annex C.2/C.3 两个方向共 4 组（`59A71FD8…`、`F0184BDA…`、`56C46B57…`、`FC1314F7…`），**全部与规范一致**。
  - 组件升级：`assets/frame-splitter.js` 现在支持 general-glo/ded 与 general-ciphering 的**两层结构**（外层按「长度+值」逐字段推进、key-info 三种 CHOICE、ciphered-content 内层复用第 2 课逻辑）。
- **一条重要的自我纠错（值得记住的教训）**：上一轮我从子代理消息里复制的 general-ciphering 拼接串**少了 date-time 与 other-information 的两个 `00`**。
  只因为它"看起来像"对的，我的拆分器预设一度是错的。教训：**凡拼接的长 hex，必须用规范标注的总长度（或字段自洽、剩余为 0）验证过才可引用**；
  而正确做法是从规范原文里按「纯十六进制 token」重拼、再去掉注释——注意规范表格的注释格式是「<hex> // <字段名>」，且长 hex 会在换行处被空格切断（切断处可能是半个字节），所以不能按"偶数长度"过滤 fragment。
- **第 2 课已完成并实测通过**（`lessons/0002-apdu-byte-level-crypto.html`）：
  - 对拍脚本 `assets/verify-dlms-gcm.py`（依赖 `cryptography`，本机已装 49.0.0）：Table 48 的仅认证 tag `06725D910F9221D263877516`、仅加密密文 `411312FF935A47566827C467BC`、认证+加密的 tag `7D825C3BE4A77C3FCC056B6B` 与完整报文，以及 Annex C.1 的 KDF 输出 `C5F45128…49712F46` 与前 16 字节 GUEK——**全部字节级对上**，所以课内"我实测过"是有据的。
  - 新组件 `assets/frame-splitter.js`（报文拆分器，支持 `<0x80` 与 `0x81/0x82` 长度形式）。其字段切分逻辑我用独立复算脚本验证过三条 Table 48 报文。
  - 课内明确标注：**Len 语义（从 SC 起算、含 tag）是从示例反推、非规范原文**。
  - 顺带记一个只有自己算过才知道的细节：**"仅加密"那一档，通用 GCM 库内部仍会算出一个 tag**（本例 `0387BA79BDB9DF0E1349AE2A`），但 DLMS 既不携带也不校验它（§9.2.3.3.7.1）。脚本会打印该值并注明"不要照抄进实现"。

## 规范 vs 本地 Gurux 实现：已核实的差异（第 2 课素材，附我自己的核实结论）

- **Suite 2 的派生密钥被截成 16 字节（我已亲自核实代码行）**：`p.BlockCipherKey = kdf.SubArray(0, 16)` 出现在
  - `Gurux.DLMS.Net\Development\Secure\GXSecure.cs:855`（One-Pass DH 路径）
  - `…\GXSecure.cs:874`（Static Unified Model 路径）
  - `…\GXDLMS.cs:1123`（protected APDU 的 dedicated/global 密钥路径）
  - `…\Objects\GXDLMSSecuritySetup.cs:690`（global key 传输路径）
  而绿皮书 §9.2.3.3.7.4 规定 Suite 2 的 EK 是 **256 bit（32 octets）**。
  **核实姿势**：这四处只看代码确实写死 16 字节；AES-GCM 变换本身在 `GXSecure.cs` 内，会依密钥长度选 AES-128/256，所以 Suite 2 下很可能实际只用到 128 位强度。
  **教学用途**：不必先断言"这是 bug"——正好用它教"规范说多少字节，代码给了多少字节，自己去数"。第 2 课让学员用绿皮书 Annex C 的测试向量对拍，就能自己发现长度不符。
- **`GXSecure.cs` 不是合法 UTF-8**（有一个非 ASCII 字节，read 工具会报 `invalid UTF-8 text`）。读它要用 ANSI 码页：
  `[System.IO.File]::ReadAllLines($f, [System.Text.Encoding]::GetEncoding(1252))`（本机 PowerShell 是 5.1，`-Encoding 1252` 不被接受，要用 `Default` 或上面的 .NET 写法）。
- 子代理报告的其他差异（**尚未逐条核实**，第 2 课会挑几条验证）：.NET 的 KDF 无 key-length 参数、单块输出；Java 把临时密钥对与 SHA256withECDSA 写死成 P-256/SHA-256（Suite 2 也如此）；C 版本编译期就关闭 Suite 1/2；tag 比较是 12 字节提前退出的循环（非常量时间）；接收侧对套件不匹配有一处是"静默采纳"。
- **代码里找不到 `ENC`/`AUT`/`MAC` 这类 KDF 上下文串**（全树 ripgrep 只命中蓝皮书正文）——与"绿皮书 §9.2 未给出 EK/AK 派生公式"一致。这条要谨慎：不要把自己实现的惯例当成规范要求，也不要把某库的做法当成标准。

## 第 2 课可以直接用的两样东西（备课线索）

- **绿皮书 Table 48 的示例密钥，正好是 Gurux 库的默认值**：EK = `000102030405060708090A0B0C0D0E0F`、AK = `D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF`（`Gurux.DLMS.Net\Development\Secure\GXCiphering.cs:100-101` 构造函数里硬编码，注释来源即绿皮书）。示例的服务端还把 KEK 设成 ASCII `1111111111111111`（`Gurux.DLMS.Server.Example.Net\...\GXDLMSBase.cs:691`），默认 system title 是 ASCII `ABCDEFGH`。
  → **练习设计**：把 system title 改成 Table 48 的 `4D4D4D0000BC614E`、IC = `01234567`、用上面两把默认密钥，让学员自己算/验 GF(2) 认证报文的 tag；规范的期望值是 `06725D910F9222…` 系列（Table 48：`T = 06725D910F9221D263877516`）。**这是自带标准答案的自检练习，待第 2 课实际跑一遍确认可复现。**
- **HLS ECDSA 的输入串是不对称的，必须记准**（子代理已给行号，我尚未逐条核实）：
  - 客户端签 / 服务端验（CtoS）：`clientST ‖ serverST ‖ StoC ‖ CtoS`
  - 服务端签 / 客户端验（StoC）：`serverST ‖ clientST ‖ CtoS ‖ StoC`
  即"先自己后对方"，且被签名的是 StoC/CtoS 的**原始字节**；服务端验证时还会前置 Association 的 `Secret`（用 ECDSA 时必须为空）。写错顺序是最常见的"签名验不过"原因。

## 教学策略备忘

- 密码学初学者最容易被"套件编号"迷惑：Suite 0/1/2 不是"安全等级"，而是"算法组合 + 允许的安全等级"。第一课必须先立这个坐标系。
- **规范里没有"安全等级"这个枚举**（已核实）：只有 SC 字节的 A/E 两位、security policy / access rights 的位图，以及"三种认证安全等级（no security / LLS / HLS）"。教学时要说清"行业口语"与"规范字段"的差别，这正是第 1 课的混淆点 3。
- 动手反馈闭环候选：Gurux Translator 解析真实 hex 帧；Gurux C# 单元测试；按规范手算 IV/AAD；绿皮书 Table 48 的 32 字节示例可直接当练习答案。
