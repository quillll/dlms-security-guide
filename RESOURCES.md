# DLMS/COSEM 安全套件 Resources

按「知识 / 智慧（社区）」分组。教学中的每一条事实性主张都必须能落到下面某个知识源，并给出文件 + 章节号。

## Knowledge（规范原文 · 本地）

- **绿皮书 Green Book Ed.11（DLMS/COSEM 架构与协议）— 本地**
  - Markdown（由官方 PDF 转换，带章节号，检索方便）：`D:\project\personal\dlms\GreenBook\output\book\ai\`，安全章节为 `ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`
  - 原始 PDF：`D:\project\personal\dlms\Green-Book-Ed-11-V1-0.pdf`（分卷版在 `D:\project\personal\dlms\绿皮书\`）
  - **用途：安全套件、安全等级、安全策略、AES-GCM 报文结构、KDF、HLS/GMAC 的权威定义。本课程的第一手依据。**
- **蓝皮书 Blue Book Ed.17 Part 2（COSEM 接口类与 OBIS）— 本地**
  - Markdown：`D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\`（第 4 章为接口类，含 `ch4-4-4-interface-classes-for-access-control-and-managem.md`）
  - 原始 PDF：`D:\project\personal\dlms\Blue-Book-Ed-17-part-2-V1.0.pdf`
  - 用途：安全相关接口类的属性/方法/数据类型，Security Setup、Association LN、证书与密钥属性的准确定义。
- **绿皮书附录 A / B / C — 本地**
  - `GreenBook\output\book\ai\channex-a-normative-nsa-suite-b-elliptic-curves-an\`（Suite B 椭圆曲线）
  - `...\channex-b-informative-example-of-an-root-ca-and-en\`（根 CA 与终端实体证书示例字段）
  - `...\channex-c-normative-use-of-key-agreement-schemes-i\`（三种密钥协商：ephemeral unified / one-pass DH / static unified）
  - 用途：曲线与密钥协商方案的规范级细节，Suite 1/2 的非对称部分。
- **IEC 62056-21（中文版）— 本地** `D:\project\personal\dlms\IEC62056-212002中文.pdf`
  - 用途：仅作背景（早期抄表协议与 DLMS 的衔接）；与安全套件无关，不要用它回答安全问题。
- **[DLMS User Association 官网](https://www.dlms.com/)**
  - 标准的所有者与发布者。用途：确认规范版本/勘误/白皮书；正式文本需购买或会员权限，本地已有 Ed.11 / Ed.17 文本，优先用本地。

## Knowledge（本工作区自建的研究素材）

- **`assets/verify-dlms-gcm.py`**（工作区脚本，非素材）
  - **10 组规范测试向量的独立复算**：Table 48 三条报文（仅认证 / 仅加密 / 认证+加密）、Annex C.1 的 KDF、Annex C.2 + C.3 共四个方向的派生密钥、Table 51 的 HLS mechanism 5（GMAC）两条认证值。**全部与规范一致。**
  - 用途：让学员"先预测再验证"；也是检验自己实现的最快入口。只用 `cryptography` 的 AES-GCM 原语，不依赖任何 DLMS 库。
- **`assets/check-workspace.py`**（工作区脚本）
  - 一次校验全部 HTML：标签闭合 / 内部链接存在性 / 跨文件锚点存在性 / 组件引用完整性。改完 HTML 跑一次。
- **`.research/green-book-security-extract.md`**（约 61 KB / 445 行）
  - 从本地绿皮书 Ed.11 抽取的带引证事实集：Table 27、Table 42/43、Table 45/46、Table 48 完整 hex 示例、Table 50/51（HLS 机制与 GMAC 测试向量）、Table 21/26、Annex C 的 KDF 调用形式与测试向量、以及 8 条明确的“文件里找不到”的缺口清单。
  - 用途：备课时先查这里，再回到规范核对；**它本身不是权威来源**，每条都附了文件 + 章节号，可追溯。
- **`.research/gurux-implementation-extract.md`**（已完成，约 2300 行）
  - 从 Gurux C#/Java/C 抽取的实现级事实：`SecuritySuite`/`SecurityPolicy`/`Security`（安全等级）枚举、SC 字节构造、GCM 的 IV 与 AAD 装配、GMAC、KDF、密钥包装（RFC 3394）、密钥协商、ECDSA 签名与 association 认证输入串、Security setup 对象读写、以及 18 条"实现陷阱"。
  - **用途：第 2 课起做"规范 vs 实现"对照练习的素材。** 注意其中若干处与规范不一致（例如 Suite 2 的派生密钥被写成 16 字节，我已核实代码行，见 [NOTES.md](NOTES.md)），教学时以规范为准、把实现差异当成练习题。
  - ⚠️ `Gurux.DLMS.Net\Development\Secure\GXSecure.cs` 不是合法 UTF-8，读取需用 ANSI 码页（详见 NOTES.md）。
- **`.research/green-book-annex-extract.md`**（已完成，约 99 KB）
  - 后者含：Annex A 的 P-256/P-384 域参数全文、Annex C 三种密钥协商的步骤与**完整测试向量**（Z、KDF 输出、GUEK/EK）、证书字段与 OID 清单、HLS 各 mechanism 的计算式与测试向量、Security setup / Association LN / SN / Data protection 的属性方法表、以及一份明确的“文件里找不到”清单（含一处规范内部未调和的冲突：证书签名用 DER，而 §9.2.3.4.5 要求 plain format R‖S）。
  - 用途：后续课程做“规范 vs 实现”对照练习时的素材；测试向量可直接用来验证自己的加解密实现。

## Knowledge（参考实现 · 本地，用于事实校验）

- **Gurux.DLMS.Net（C#）** `D:\project\personal\dlms\Gurux.DLMS.Net\Development`
  - 用途：把规范条款对应到可读代码（`SecuritySuite`/`SecurityPolicy` 枚举、GCM 加解密、KDF、GMAC）。当规范文字含糊时，用这里的实现交叉验证——但记住实现可能有 bug，规范优先。
- **gurux.dlms.java（Java）** `D:\project\personal\dlms\gurux.dlms.java-master\development`
- **GuruxDLMS.c（ANSI-C）** `D:\project\personal\dlms\GuruxDLMS.c\development`
  - 用途：嵌入式受限环境下的实现取舍；C 版对内存/字节布局的处理最贴近报文。
- **GuruxDLMSTranslatorStandalone（本地 GUI 工具）** `D:\project\personal\dlms\GuruxDLMSTranslatorStandalone\GuruxDLMSTranslatorStandalone-v1.1\GuruxDLMSTranslatorStandalone.exe`
  - 用途：粘贴 hex 报文 → 解析成 XML。可设置 `Security`、`SecuritySuite`、`BlockCipherKey`、`AuthenticationKey`、`InvocationCounter`，用来验证"我对某段报文属于哪个字段"的判断。**课程"动手验证"环节的主力工具。**

## Knowledge（密码学基础 · 权威 & 可读）

- **[NIST SP 800-38D — GCM 模式](https://csrc.nist.gov/pubs/sp/800/38d/final)**
  - GCM 的权威定义（IV/nonce、AAD、tag 长度、认证解密）。用途：当绿皮书只说"AES-GCM"时，回到这里理解机制。密码学初学者按需查阅，不必通读。
- **[NIST FIPS 186-5 — 数字签名标准](https://csrc.nist.gov/pubs/fips/186-5/final)** 与 **[NIST SP 800-56A — 密钥协商](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final)**
  - ECDSA 与 ECDH 的权威定义（P-256/P-384）。用途：Suite 1/2 非对称部分的机制依据。
- **[Crypto 101 — lvh（免费在线书）](https://www.crypto101.io/)**
  - 面向开发者的密码学入门，讲清"为什么这样设计"。用途：密码学直觉的第一个去处（本课程定位为初学）。
- **[A Graduate Course in Applied Cryptography — Boneh & Shoup（免费草稿）](https://toc.cryptobook.us/)**
  - 严谨但可读的教材。用途：想深挖 GCM/ECDH 安全性证明时。
- **[论文：Secure Deployment of Smart Meters（IET，含三套安全套件对比表）](https://ietresearch.onlinelibrary.wiley.com/doi/10.1049/gtd2.70292)**
  - 第三方学术视角对 DLMS 三套套件与部署风险的评估。用途：理解"为什么现实中很多表只用 Suite 0/仅认证"。

## Knowledge（第三方实现 · 交叉核对，非权威）

- **[dlms-cosem-rs（Rust，docs.rs）](https://docs.rs/dlms-cosem-rs/latest/dlms_cosem_rs/security/enum.SecuritySuite.html)**
  - 用途：看另一种语言如何建模 `SecuritySuite`（`TAG_LEN=12`、`NONCE_LEN=12`、suite id 在 security control byte 低半字节）。**注意：其文档注释是作者对规范的理解，出现过与规范用词不一致的表述（例如把 Suite 0 描述为"AES-GCM-128 with AES-128 key wrap"）；引用前必须与绿皮书原文核对。**
  - 源码：<https://github.com/hupe1980/dlms-cosem-rs>

## Wisdom (Communities)

- **[Gurux 官方论坛](https://www.gurux.fi/index.php/forum)**
  - 库作者 Mikko Kurunsaari 亲自回复，问题密度高、噪声低。用途：实现细节、抓包疑难、"我的 tag 校验失败为什么"这类只有实践者能回答的问题。示例帖：[Decoding a Ciphered frame](https://www.gurux.fi/index.php/node/25668)。
- **[Gurux GitHub 组织](https://github.com/Gurux)（各语言仓库的 Issues）**
  - 用途：搜"别人踩过的坑"；提 issue 时给出 hex 报文 + 参数，容易被作者直接定位。
- **[Stack Overflow · dlms 标签](https://stackoverflow.com/questions/tagged/dlms)**
  - 用途：通用实现问题；信号比论坛弱，先搜再问。
- **本地/线下：暂无验证过的中文社区**
  - 见到过若干中文 DLMS 博客，但质量与时效无法背书；若用户找到高质量的中文群组，应记入此处。

## Gaps

- **中文的高质量、报文级 DLMS 安全套件讲解几乎不存在**（中文资料多停留在"Suite 0/1/2 算法对照表"的复制粘贴层面）。本课程的中文 reference 文档因此有额外价值。
- **Suite 2（AES-256-GCM + P-384）的公开抓包样例极少**，网络上绝大多数示例是 Suite 0/1。练习多需自行构造或用本地 Gurux 服务器生成。
- **暂无面向"仅认证（GMAC）"模式的端到端公开教程**，需以规范 + Gurux 代码为准。
