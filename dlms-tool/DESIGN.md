# DLMS/COSEM 安全算法工作台 · 设计方案 v1

> 状态：**已确认并实现 v1**（2026-10-21；用户确认“全按推荐”，算法与 UI 已落地）  
> 日期：2026-10-21  
> 规范基线：Green Book Ed.11 / Blue Book Ed.17 Part 2，Security Suite 0/1/2  
> 目录：`dlms-tool/`（新目录，不改动现有课程、教程、组件与脚本）  
> 实际入口：`index.html`  
> 历史设计稿：`design-preview.html`（静态版式，不含算法逻辑）

---

## 0. 结论先行

做一个**离线、零依赖、单页**的 DLMS 安全算法工作台。它不是“填个框、出个结果”的黑盒，而是把 DLMS 的五个旋钮（Suite / SC / ST / IC / Key）和三层报文（security header / ciphertext / tag）在界面上摊开：

- **每个输入**都有 HEX / ASCII / Base64 格式转换、逐字段长度校验、随机生成与清空；
- **每个输出**都有字节着色、字段表、偏移量与计算轨迹（K → IV → AAD → P → T）；
- **每个算法**都能用规范测试向量一键载入、逐字节对比、自动自检。

v1 覆盖 8 个能力域：**报文保护、GMAC、HLS、密钥工具、哈希/校验、数字签名、证书、报文解析**。Suite 3–15、V.44 压缩、证书签发作为“规划中”入口保留，不伪装成已实现。

### 0.1 实现状态（2026-10-21）

- **实际入口**：`index.html`（多文件、无构建、经典脚本，可直接双击或本地 HTTP 打开）。
- **已实现**：AES-GCM 加密/解密（Suite 0/1/2，C8–CF、D0–D7、DB/DC）、GMAC（报文 + HLS-5）、HLS 3/4/5/6/7、AES-KW、KDF、ECDH、ECDSA（P-256/P-384，raw↔DER，原始私钥 d）、X.509 解析/验签/链/公钥提取、SHA/MD5/HMAC、CRC/FCS、HDLC/wrapper/APDU 解析、general-ciphering 解析、general-signing 解析。
- **未实现（保留入口）**：V.44 压缩、general-ciphering 构建、general-signing 构建、证书签发/CSR、CRL/OCSP、信任锚判断、Suite 3–15。
- **验收**：Node 核心测试 **44 项通过**；浏览器 UI 冒烟 **21 项通过**；内置测试向量页 **13/13 通过**。详见 §4.3 与 `tests/`。

---

## 1. 调研：DLMS 安全算法全景

### 1.1 三个安全套件（Table 27）

| Suite | 认证加密 | 数字签名 | 密钥协商 | 哈希 | 密钥包装 | 压缩 |
|---|---|---|---|---|---|---|
| **0** | AES-GCM-128 | — | — | — | AES-128 Key Wrap | — |
| **1** | AES-GCM-128 | ECDSA P-256 | ECDH P-256 | SHA-256 | AES-128 Key Wrap | V.44 |
| **2** | AES-GCM-256 | ECDSA P-384 | ECDH P-384 | SHA-384 | AES-256 Key Wrap | V.44 |
| 3–15 | 保留 | | | | | |

关键结论：

- **Suite 0 ≠ 无安全**。它照样能加密、能认证，短板是没有 ECC、没有哈希，不能做协议内密钥协商与数字签名。
- **Suite 不是安全等级**，而是“算法工具箱”；实际强度取决于 SC 的 A/E 位、security policy、密钥管理与认证机制的组合。
- 三个套件的 **tag 长度都是 96 bit（12 字节）**；Suite 2 的 EK/AK/KEK 是 32 字节，但 tag 不变。

### 1.2 五个核心参数

| 参数 | 长度 | 作用 | 本工具中的输入方式 |
|---|---|---|---|
| System Title (ST) | 8 B | 设备标识；参与 IV、KDF、HLS 签名 | HEX / ASCII；8 B 强校验 |
| Invocation Counter (IC) | 4 B | 抗重放；参与 IV | HEX / 十进制；`+1` 按钮 |
| Security Control (SC) | 1 B | suite + A/E + Key_Set + Compression | 由套件与保护模式自动生成，也可手改 |
| EK / AK | 16 或 32 B | AES 分组密钥 / 认证密钥 | HEX / Base64；按套件校验长度 |
| Tag | 12 B | GCM 认证标签 | 输出；解密时可粘贴期望值对比 |

**IV = ST(8) ‖ IC(4)**，共 12 字节。加密用发送方 ST；解密用报文里的 IC + **发送方** ST，不是接收方自己的 ST。

### 1.3 三种保护模式的 P 与 AAD（Table 46）

SC 的低 4 位是 suite，bit 4 = A（认证），bit 5 = E（加密）。

| A | E | SC 形态 | 明文 P | AAD | 报文里的 tag |
|---|---|---|---|---|---|
| 1 | 0 | `0x10` | 空 | `SC ‖ AK ‖ 原 APDU` | 12 B |
| 0 | 1 | `0x20` | 原 APDU | 空 | 不携带、不校验 |
| 1 | 1 | `0x30` | 原 APDU | `SC ‖ AK` | 12 B |
| 0 | 0 | `0x00` | 原 APDU | — | — |

两个容易踩的点：

1. **仅认证（GMAC）时，原 APDU 进 AAD，不进 P**；P 为空。
2. **仅加密时，GCM 库内部仍会算一个 tag，但 DLMS 不携带也不校验**；不要把它写进报文。

### 1.4 报文封装家族

| 家族 | 标签 | 外层布局 | 密钥来源 | 长度语义 |
|---|---|---|---|---|
| service-specific glo-ciphering | `C8–CF` | `Tag ‖ Len ‖ SC ‖ IC ‖ C ‖ T` | GUEK / GBEK | **Len 从 SC 起算**，含 C 与 T |
| service-specific ded-ciphering | `D0–D7` | 同上 | dedicated key | 同上 |
| general-glo-ciphering | `DB` | `DB ‖ L(ST)‖ST ‖ L(SH‖C‖T)‖…` | GUEK / GBEK | 无总 Len；两个 A-XDR OCTET STRING |
| general-ded-ciphering | `DC` | 同上 | dedicated key | 同上 |
| general-ciphering | `DD` | `DD ‖ tx ‖ orgST ‖ recST ‖ datetime ‖ other ‖ key-info? ‖ ciphered-content` | identified / wrapped / agreed | 无总 Len；逐字段读 |
| general-signing | `DF` | `DF ‖ tx ‖ orgST ‖ recST ‖ datetime ‖ other ‖ content ‖ signature` | ECDSA 签名私钥 | 无总 Len；签名覆盖 content |

> **UI 下拉简写**：`glo-ciphering` / `ded-ciphering` 指 service-specific（C8–CF / D0–D7）；`general-glo-ciphering` / `general-ded-ciphering` 指通用封装（DB / DC）。标签旁的 tag 范围已足够区分，英文保留规范写法。

> **标注**：`C8` 家族的 Len 语义（从 SC 起算、含 tag）是从 Table 48 三条报文反推并用总长自洽验证的，规范没有一句话明写。工具会在字段表里直接写“Len = 5 + len(C) + 12”，避免用户误算。

### 1.5 HLS 认证机制（Table 50 / 51 / 52）

| id | 名称 | f(x) 公式 | 输出 |
|---|---|---|---|
| 0 | No security | — | — |
| 1 | LLS | 口令明文比较 | 口令长度 |
| 2 | HLS manufacturer specific | 厂商定义 | 厂商定义 |
| 3 | HLS MD5 | `MD5(challenge ‖ secret)` | 16 B |
| 4 | HLS SHA-1 | `SHA-1(challenge ‖ secret)` | 20 B |
| 5 | HLS GMAC | `SC ‖ IC ‖ GMAC_EK(SC ‖ AK ‖ challenge)` | **17 B** |
| 6 | HLS SHA-256 | `SHA-256(secret ‖ 己方ST ‖ 对方ST ‖ 己方质询值 ‖ 对方质询值)` | 32 B |
| 7 | HLS ECDSA | `ECDSA(己方ST ‖ 对方ST ‖ 己方质询值 ‖ 对方质询值)` | 64 / 96 B |

已用规范向量复算确认的两个细节：

- **HLS-5 的 GMAC 密钥是 EK，不是 AK**；AK 进 AAD。IV 用**计算方自己**的 `ST ‖ IC`。Table 51 的 `f(StoC)` 期望 tag 为 `1A52FE7DD3E72748973C1E28`。
- **DLMS 的 tag 是 GCM 16 B tag 的前 12 B**，不是后 12 B。Table 48 三条报文与 Table 51 两条向量均按此复算一致。

> 标注：HLS-5 的 IV 取“计算方自己”的 ST，是 Table 51 反推结论，规范未明写；对接真机仍需实测。工具会在该字段旁标注“反推，非规范明文”。

### 1.6 密钥派生与密钥包装

- **KDF**：NIST SP 800-56A Concatenation KDF，`K(i) = Hash(counter(4B BE) ‖ Z ‖ OtherInfo)`，Suite 1 用 SHA-256 / 128 bit，Suite 2 用 SHA-384 / 256 bit。
- **OtherInfo**：`AlgID(7B) ‖ PartyU(8B) ‖ PartyV(8B)`；`C(0e,2s)` 在中间多一个 `NonceU`（1 B 长度 + transaction-id）。
- **不是 AES-CMAC**。DLMS 的 KDF 是哈希拼接，不是 CMAC-based KDF；不要把两套实现混用。
- **AES Key Wrap**：RFC 3394，KEK 16/32 B，默认 IV `A6A6A6A6A6A6A6A6`；16 B 密钥包成 24 B，32 B 包成 40 B。

### 1.7 非对称与证书

| 项目 | Suite 1 | Suite 2 |
|---|---|---|
| 曲线 | P-256 | P-384 |
| 私钥 d | 32 B | 48 B |
| 公钥 Q（DLMS key_data） | `X‖Y` = 64 B | `X‖Y` = 96 B |
| 公钥 Q（X.509 SPKI） | `04‖X‖Y` = 65 B | `04‖X‖Y` = 97 B |
| ECDSA 签名（DLMS 报文） | `R‖S` = 64 B | `R‖S` = 96 B |
| ECDSA 签名（X.509 证书内） | DER `ECDSA-Sig-Value` | DER |

- **DLMS 报文签名用 plain `R‖S`**；**X.509 的 `signatureValue` 用 DER**。这是两层编码，不能混。
- 证书里 `keyUsage` 必须匹配：`digitalSignature` 用于 HLS-7 / general-signing；`keyAgreement` 用于 ECDH。
- 从证书取公钥去拼 DLMS `key_data` 时，要先去掉 `04` 前缀（65→64、97→96）。
- 本工具做**密码学校验**（签名、有效期、keyUsage、链式签名），不做信任锚判断、不做 CRL/OCSP。

### 1.8 校验和

| 算法 | 参数 | Check(`"123456789"`) | 用途 |
|---|---|---|---|
| CRC-16/X.25（HDLC FCS） | poly `0x1021`, init `0xFFFF`, refin/refout, xorout `0xFFFF` | `0x906E` | DLMS HDLC 帧尾；线上低字节在前 |
| CRC-16/CCITT-FALSE | poly `0x1021`, init `0xFFFF`, 不反转 | `0x29B1` | 通用对照 |
| CRC-16/ARC | poly `0x8005`, init `0x0000`, 反转 | `0xBB3D` | 通用对照 |
| CRC-32/ISO-HDLC | poly `0x04C11DB7`, init/xorout `0xFFFFFFFF`, 反转 | `0xCBF43926` | 通用校验 |

### 1.9 算法输入/输出规格（设计 UI 的直接依据）

| # | 算法 / 功能 | 输入 | 输出 | 关键约束 |
|---|---|---|---|---|
| 1 | AES-GCM 加密 | suite, A/E, ST(8), IC(4), EK, AK, P(n) | C(n), T(12), 完整 APDU | EK/AK 16 或 32 B；IV=ST‖IC |
| 2 | AES-GCM 解密 | 完整 APDU 或 `SH‖C‖T`, EK, AK, 发送方 ST | P(n), 校验结果 | 先验 tag 再解密；A=1 必须有 12 B tag |
| 3 | GMAC 报文认证 | EK, AK, ST(8), IC(4), content(n) | T(12), 可选 `SC‖IC‖T`(17) | P 为空；content 进 AAD |
| 4 | AES Key Wrap / Unwrap | KEK, key 或 wrapped | wrapped(n+8) / key | KEK 16/32 B；key ≥16 B 且 8 B 对齐 |
| 5 | KDF | Z, hash, keydatalen, AlgID, PartyU, PartyV, 可选 NonceU | 派生密钥, K(i) 轨迹 | counter 4 B BE 从 1 开始 |
| 6 | ECDH | curve, 私钥 d, 对方公钥 Q | Z(32/48 B) | 再送 KDF 才能当密钥 |
| 7 | ECDSA 签名 | curve, hash, 私钥, message | `R‖S`(64/96), DER | DLMS 要 plain；证书要 DER |
| 8 | ECDSA 验签 | curve, hash, 公钥/证书, message, signature | 通过/失败 + 原因 | 自动识别 raw/DER；曲线要匹配 |
| 9 | HLS-3 / HLS-4 | 质询值 (challenge, 8–64 B), secret | 16 / 20 B | `hash(challenge‖secret)` |
| 10 | HLS-5 | 质询值 (challenge), EK, AK, ST, IC | 17 B | 密钥=EK；AAD=SC‖AK‖challenge |
| 11 | HLS-6 | 己方/对方质询值 (challenge), secret, 己方/对方 ST | 32 B | secret 永远在最前；己方在前 |
| 12 | HLS-7 | 己方/对方质询值 (challenge), 己方/对方 ST, 签名私钥 | 64/96 B | 己方 ST 在前；质询值顺序跟着换 |
| 13 | X.509 解析 | DER / PEM（可多张） | 主题、签发者、序列号、有效期、公钥、扩展、指纹 | 支持 P-256/P-384；RSA 可选 |
| 14 | X.509 验签 | 证书, 签发者证书或公钥 | 通过/失败 + 原因 | 证书内签名是 DER，先转 raw |
| 15 | CRC / FCS | bytes, 算法参数 | 数值, 线上字节 | HDLC FCS 低字节在前 |
| 16 | SC 编解码 | suite, A, E, Key_Set, Compression | 1 B + 逐位解释 | bit4=A, bit5=E，别记反 |
| 17 | APDU 封装/解析 | family, inner APDU, SC, IC, keys, ST(s) | 完整 APDU / 字段表 | C8 家族 Len 从 SC 起算 |
| 18 | 哈希 | 算法, message / file | digest | MD5/SHA-1 仅历史兼容 |

### 1.10 v1 明确不做

- **V.44 压缩**：算法复杂、与密码学无关；只保留入口说明。
- **Suite 3–15**：规范保留，可能是后量子方向；不猜算法。
- **证书签发 / CSR 生成**：v1 只做解析、验签、公钥提取；签发放 v2。
- **完整 COSEM 服务解析**：v1 只解析安全层；内层 APDU 显示标签与原始字节，不做 OBIS/属性级解码。
- **生产级密钥管理 / HSM / 侧信道防护**：这是诊断与教学工具，不是生产密码机。

---

## 2. 信息架构

### 2.1 一级导航（9 个入口）

| 入口 | 一句话 | v1 状态 |
|---|---|---|
| 报文保护 | AES-GCM 加密/解密，C8 / DB / DC 封装 | 可用 |
| GMAC 认证 | 仅认证报文 + HLS-5 质询-应答 | 可用 |
| HLS 双向认证 | mechanism 3/4/5/6/7，双向 | 可用 |
| 密钥工具 | AES-KW、ECDH、KDF、随机密钥 | 可用 |
| 哈希与校验 | SHA/MD5、HMAC、CRC/FCS | 可用 |
| 数字签名 | ECDSA 签名/验签、raw↔DER | 可用 |
| 证书 | X.509 解析、验签、链、公钥提取 | 可用 |
| 报文解析 | 整帧/APDU 安全层拆分、FCS 校验 | 可用 |
| 算法总览 | 算法注册表 + 规划中入口 | 可用 |

底部两个次级入口：**测试向量**（自检）、**使用说明 / 规范出处**。

### 2.2 三条核心用户流程

1. **加密一条 GET 请求**
   `报文保护 → 选 Suite 0 → 认证+加密 → 填 ST/IC/EK/AK → 粘贴 C0… → 计算 → 看 C/T/完整 C8 报文 → 复制`
2. **解密抓包**
   `报文保护 → 解密 → 粘贴完整 C8 报文 → 自动识别 SC/IC/Len → 填发送方 ST 与密钥 → 先验 tag → 看明文与字段表`
3. **验证自己的实现**
   `测试向量 → 选 Table 48 / 51 / 52 → 一键载入 → 对比期望值 → 逐字节 diff → 通过/失败`

### 2.3 导航与响应式

- **桌面 ≥1180 px**：左侧固定 248 px 导航 + 主工作区；主工作区两栏（左参数 / 右结果栈：结果 → 计算轨迹 → 测试向量）。
- **平板 760–1179 px**：导航收为 72 px 图标栏或抽屉；两栏降为单栏，结果在参数下方。
- **移动 <760 px**：顶部 56 px 应用栏 + 横向算法 chips；表单/结果单栏；底部固定操作条（主按钮 + 状态）；字节视图可横向滚动（实现时窄屏按 8 B/行重排）。
- 深层链接：`#/aes-gcm`、`#/gmac`、`#/cert`，刷新后保持当前页。

---

## 3. UI 设计

### 3.1 设计语言：Paper Instrument

现有课程是“纸张 + 墨色”的阅读风格；工具则在此基础上加一层“仪器感”：

- 暖白纸底 + 深墨色文字，长时间看十六进制不刺眼；
- 深色导航栏作为“仪器面板”，与内容区形成清晰边界；
- 字节用低饱和色块区分角色（长度/SC/IC/密文/tag），颜色只做辅助，字段表与图例同时给出文字；
- 1 px 细边框、10 px 圆角、极少阴影；不用渐变、不用大圆角、不用装饰性插画；
- 数字与十六进制一律等宽字体，中文用系统字体。

**颜色 token（浅色）**

| token | 值 | 用途 |
|---|---|---|
| `--bg` | `#F4F2EC` | 页面底色 |
| `--surface` | `#FFFEFB` | 卡片 |
| `--ink` | `#17181C` | 主文字 |
| `--muted` | `#5F6470` | 说明文字 |
| `--line` | `#DDD7C9` | 分隔线 |
| `--brand` | `#145C63` | 主色（深青） |
| `--brand-2` | `#1A5C8A` | 次色（DLMS 蓝） |
| `--accent` | `#B5762A` | 警告/规划中 |
| `--ok` | `#1F7A4D` | 校验通过 |
| `--danger` | `#B23A3A` | 校验失败 |
| `--purple` | `#6B4C9A` | SC 字节 |
| `--ct` | `#A34A3A` | 密文 |
| `--tag` | `#2F7D5B` | 认证标签 |

**字体**

- 正文：`"Inter", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif`（不加载外部字体）
- 等宽：`"JetBrains Mono", "Cascadia Code", "SFMono-Regular", Consolas, monospace`
- 字号：正文 14 px；标签 12 px；表格 12.5 px；代码/字节 12.5 px；页面标题 24 px。

**间距 / 圆角 / 动效**

- 4 px 网格；卡片内边距 18–20 px；栏间距 20 px。
- 圆角：卡片 10 px；输入框 8 px；按钮 7 px；字节格 4 px。
- 动效 120–180 ms；尊重 `prefers-reduced-motion`。

### 3.2 桌面布局（核心页）

```
┌──────────────────────┬──────────────────────────────────────────────────────────────┐
│ DLMS 工作台           │  报文保护 / AES-GCM        [Green Book Ed.11] [本地离线]      │
│ 安全算法 · Suite 0/1/2│                                                              │
│                      │  ┌───────────────────────────┐  ┌─────────────────────────┐  │
│ 报文保护          ●   │  │ ① 参数                     │  │ ② 结果                  │  │
│ GMAC 认证             │  │ 模式  [加密] [解密]        │  │ ✓ 已生成 12 B 认证标签   │  │
│ HLS 双向认证          │  │ 保护  [认证+加密] [GMAC]   │  │ [HEX] [Base64] [ASCII]  │  │
│ 密钥工具              │  │ Suite [0 AES-128 ▾]        │  │ 0000 C8 1E 30 01 23 ... │  │
│ 哈希与校验            │  │                            │  │ 0010 ...                │  │
│ 数字签名              │  │ System Title (8 B)         │  │                         │  │
│ 证书                  │  │ [4D 4D 4D 00 00 BC 61 4E]  │  │ 字段表                  │  │
│ 报文解析              │  │ [HEX][ASCII][B64] 随机 清空│  │ Tag/Len/SC/IC/C/T       │  │
│                      │  │                            │  │                         │  │
│ 算法总览              │  │ Invocation Counter (4 B)   │  │ [复制] [下载] [去解密]  │  │
│ 测试向量              │  │ [01 23 45 67]  +1          │  └─────────────────────────┘  │
│                      │  │                            │                               │
│                      │  │ EK (16 B)      [生成] [👁] │  ┌─────────────────────────┐  │
│                      │  │ [00 01 02 ... 0E 0F]       │  │ ③ 计算轨迹              │  │
│                      │  │                            │  │ K → IV → AAD → P → T    │  │
│                      │  │ AK (16 B)      [生成] [👁] │  └─────────────────────────┘  │
│                      │  │ [D0 D1 D2 ... DE DF]       │                               │
│                      │  │                            │  ┌─────────────────────────┐  │
│                      │  │ 明文 APDU (13 B)           │  │ ④ 测试向量              │  │
│                      │  │ [C0 01 00 00 08 ...]       │  │ Table 48 · 认证+加密     │  │
│                      │  │ [HEX][ASCII][B64] 清空     │  │ [载入] [逐字节对比]      │  │
│                      │  │                            │  └─────────────────────────┘  │
│                      │  │ [计算并生成报文] [重置]     │                               │
│                      │  └───────────────────────────┘                               │
└──────────────────────┴──────────────────────────────────────────────────────────────┘
```

设计意图：

- **参数与结果同屏**，桌面端不需要来回滚动；改一个参数，结果区顶部出现“参数已变，点击重算”的轻提示（不自动重算，避免误以为结果已更新）。
- **计算轨迹**把“为什么是这个 tag”拆成五步，既方便教学，也方便排错。每一步的值可单独复制。
- **测试向量**放在结果下方，形成“算完就能对答案”的闭环。

### 3.3 移动布局

```
┌──────────────────────────────┐
│ ☰  DLMS 工作台      ⋯        │
├──────────────────────────────┤
│ [报文保护] [GMAC] [HLS] … →  │  横向 chips
├──────────────────────────────┤
│ 报文保护 · AES-GCM           │
│ ┌──────────────────────────┐ │
│ │ 模式 [加密] [解密]        │ │
│ │ 保护 [认证+加密] [GMAC]   │ │
│ │ Suite [0 ▾]              │ │
│ │ System Title (8 B)       │ │
│ │ [4D 4D …]                │ │
│ │ HEX · ASCII · B64  随机  │ │
│ │ …                        │ │
│ └──────────────────────────┘ │
│ ┌──────────────────────────┐ │
│ │ ✓ 已生成 12 B tag        │ │
│ │ [HEX] [Base64] [ASCII]   │ │
│ │ C8 1E 30 01 23 45 …      │ │
│ │ （8 B/行，横向可滚）      │ │
│ └──────────────────────────┘ │
├──────────────────────────────┤
│ [计算并生成报文]    状态 ✓    │  固定底栏
└──────────────────────────────┘
```

移动端取舍：

- 格式切换收成 `HEX · ASCII · B64` 三个小 chip；随机/清空变成图标按钮，保留 40 px 触控区。
- 结果区在计算后自动滚入视野，并有一次 600 ms 的高亮；顶部出现“回到参数”浮标。
- 字段表横向滚动，第一列（字段名）粘性固定。
- 不用 hover 才能看到的信息；点击字节弹出底部 sheet 显示偏移/字段/值。

### 3.4 输入组件：ByteField

所有十六进制/文本/密钥输入统一用一个组件，避免每个页面各写一套。

```
┌──────────────────────────────────────────────────────────────┐
│ System Title                              8 B · 必需         │
│ [HEX] [ASCII] [Base64]              [随机] [清空]            │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ 4D 4D 4D 00 00 BC 61 4E                                  │ │
│ └──────────────────────────────────────────────────────────┘ │
│ ✓ 8 字节 · 16 个 HEX 字符 · 可粘贴 "4D:4D:..."               │
└──────────────────────────────────────────────────────────────┘
```

规则：

- **格式切换是无损的**：内部始终存字节；HEX/Base64 可无损往返；ASCII/UTF-8 若含不可打印字节，切换时提示“有 3 个字节无法用 ASCII 表示，已用 · 代替，切回 HEX 不会丢”。
- **清空只清当前字段**，底部 toast 提供 5 秒“撤销”；“重置表单”才清空全部。
- **随机生成**：ST 生成 8 B；IC 生成 4 B 或从当前值 `+1`；EK/AK 生成对应长度；EC 私钥走密钥工具。
- **密钥字段默认遮蔽**，眼睛图标切换；复制密钥时 toast 提示“密钥已复制到剪贴板”。
- **长度徽标**实时显示 `当前 B / 期望 B`；错误时变红并在下方给出“差 1 字节 / 多了 2 字节”的具体提示。
- **粘贴归一化**：自动去掉 `0x`、空格、冒号、连字符、换行；遇到奇数个 nibble 或非法字符，定位到具体字节位置。
- **快捷键**：`Ctrl/Cmd + Enter` 计算；`Esc` 关闭抽屉/弹层；`Alt + C` 复制结果（不与浏览器冲突时）。

### 3.5 结果区

**状态条**（永远是结果区第一行）：

- `✓ 认证标签校验通过`（绿）
- `✓ 已生成 12 B 认证标签`（绿，加密模式）
- `⚠ 仅加密：没有完整性保护`（琥珀）
- `✗ 认证失败：tag 不匹配`（红）
- `✗ 报文长度与 Len 字段不一致`（红）

认证失败时，**默认不显示解密明文**，只显示“tag 不匹配，明文未展示”；提供“仍要查看（不安全）”二次展开。这是为了防止把未认证的明文当成可信结果。

**输入 ↔ 输出对照条**：状态条下方固定一行。加密时左侧是“输入 · 明文 APDU”、右侧是“输出 · 密文”；解密时自动翻转成“输入 · 完整密文”与“输出 · 明文 APDU”。两侧都显示字节数与复制按钮——这就是“加密报文 / 解密报文展示区”的核心，不需要来回切页。

**结果视图**：

- `HEX`：字节网格，16 B/行（窄屏横向滚动；实现时按 8 B/行重排），左侧偏移量，底部图例；字节按字段着色，hover/点击联动字段表。
- `Base64`：等宽 textarea，便于贴到工单/邮件。
- `ASCII`：仅可打印字符，不可打印显示 `·`，并标注“仅供肉眼检查，不要用于回填”。
- **字段表**：字段、偏移、长度、值、说明；说明列写关键语义（如“Len = 5 + 13 + 12”“SC: A=1,E=1,suite=0”）。
- **操作**：复制、下载 `.txt` / `.bin`、作为解密输入、作为加密明文、在新标签打开字段表（可选）。
- **联动**：从“解密”切到“加密”时，若当前有明文结果，询问“把这段明文带入加密？”；不自动覆盖用户输入。

### 3.6 各页面详细设计

#### 3.6.1 报文保护（AES-GCM）

**输入区**

- 模式：加密 / 解密（分段控件）。
- 保护方式：认证+加密 / 仅认证（GMAC）/ 仅加密（分段控件，带一行解释）。
- 安全套件：Suite 0 / 1 / 2（下拉；显示密钥长度与可用算法）。
- 封装家族（UI 简写）：glo-ciphering（service-specific，C8–CF）/ ded-ciphering（service-specific，D0–D7）/ general-glo-ciphering（DB）/ general-ded-ciphering（DC）。
- 外层 APDU 标签：自动 / 手动（C8–CF、D0–D7、DB、DC）。自动模式根据内层 APDU 首字节 +8 推断（C0→C8、C1→C9…），并在旁边显示推断依据。
- 字段：System Title、Invocation Counter、EK、AK、明文/密文输入。
- 解密专用：完整 APDU 粘贴框、期望 tag（可选，默认从报文提取）、发送方 ST。
- 高级：v1 固定按套件校验密钥长度；Key_Set 默认 0（单播），广播密钥与 Compression/V.44 留 v2。

**输出区**

- 密文 C、tag T、完整 APDU、字段表、计算轨迹。
- 解密：明文、tag 校验结果、SC/IC 解析、内层 APDU 标签识别。
- 快捷：`+1 IC 再算一次`（加密后常用）、`复制完整报文`、`去报文解析`。

**内置向量**：Table 48 三条（仅认证 / 仅加密 / 认证+加密），一键载入并对比。

**错误示例文案**

- `Suite 2 需要 32 B EK，当前 16 B。Gurux 的部分实现会把派生密钥截成 16 B，但规范要求 32 B。`
- `Len=0x1E 表示 30 B，但 SC 起实际有 32 B；请检查是否把 Tag/Len 自己算进去了。`
- `A=1 但报文末尾不足 12 B，找不到 tag。`

#### 3.6.2 GMAC 认证

两个子模式：

1. **报文 GMAC**：EK、AK、ST、IC、content → T(12)，可选输出 `SC‖IC‖T`。明文保持可见，页面明确写“只认证、不加密”。
2. **HLS-5**：challenge、EK、AK、ST、IC → `SC‖IC‖T`(17)。默认套用 `SC=0x10`；IV 用“计算方自己”的 ST，旁边标注“反推，非规范明文”。

结果区同样有字段表与“与期望 tag 对比”。内置 Table 51 两条向量。

#### 3.6.3 HLS 双向认证

- 机制选择：3 MD5 / 4 SHA-1 / 5 GMAC / 6 SHA-256 / 7 ECDSA（卡片式；0/1/2 显示为说明卡，不参与计算）。
- 方向：客户端计算 `f(StoC)` / 服务端计算 `f(CtoS)`。切换方向时，ST 顺序与质询值顺序自动翻转，并在公式预览里高亮变化。
- 字段随机制变化：
  - 3/4：challenge、secret。
  - 5：challenge、EK、AK、ST、IC。
  - 6：challenge（己方/对方）、secret、ST（己方/对方）。
  - 7：challenge（己方/对方）、ST（己方/对方）、签名私钥（或调用签名页）。
- **公式预览**：把实际值填进公式，逐段着色；这是本页最重要的教学元素。
- 输出：`f(x)` 的 HEX/Base64、长度、复制；验证模式可粘贴期望值。
- 内置 Table 51（GMAC）与 Table 52（ECDSA）向量。

#### 3.6.4 密钥工具

四个子页：

- **AES Key Wrap**：KEK、待包装密钥、Wrap/Unwrap；输出长度 +8；显示 RFC 3394 默认 IV；内置 `1111…` + `000102…` 向量。
- **ECDH**：曲线、己方私钥（PKCS#8 / JWK / 原始私钥 d）、对方公钥（`X‖Y` / `04‖X‖Y` / PEM）、PartyU/V、AlgID、keydatalen；输出 Z、派生密钥、K(i) 轨迹。原始私钥 d 时本地推导公钥，并显示“已推导 Q”。
- **KDF**：Z、AlgID、PartyU、PartyV、NonceU、hash、keydatalen；输出密钥与每个 counter 块。
- **随机密钥**：AES 16/32 B、EC P-256/P-384 密钥对；导出 HEX / JWK / PKCS#8 PEM。

#### 3.6.5 哈希与校验

- **哈希**：SHA-256 / SHA-384 / SHA-512 / SHA-1 / MD5；输入文本/HEX/文件；输出 HEX/Base64；显示字节数。HMAC 开关（SHA-256/384）。
- **CRC/FCS**：算法下拉（X.25 / CCITT-FALSE / ARC / ISO-HDLC / MODBUS）；输入 HEX/ASCII；输出数值、线上字节（可选低字节在前）、参数表；`追加 FCS` 按钮。
- **对比模式**：粘贴期望摘要/FCS，显示逐字节匹配；不匹配时标出第一个不同字节。

#### 3.6.6 数字签名

- 模式：签名 / 验签。
- 曲线与哈希：P-256+SHA-256、P-384+SHA-384（高级可拆开，但默认配对）。
- 签名：私钥导入（PKCS#8 PEM/DER、JWK、原始私钥 d）、消息输入、输出 `R‖S` 与 DER、复制/下载。
- 验签：公钥（`X‖Y`、`04‖X‖Y`、SPKI PEM、证书）、消息、签名（自动识别 raw/DER）、结果与失败原因。
- **格式转换器**：raw ↔ DER，画出 `30 len 02 len r 02 len s` 的结构；处理前导零与最高位补零。
- **DLMS HLS-7 预设**：方向、ST-C/ST-S、CtoS/StoC，一键拼出待签消息；与 HLS 页互相跳转。

#### 3.6.7 证书

- **输入**：拖拽/粘贴 PEM 或 DER；支持多张证书（链）。
- **左栏**：证书链列表，每张显示 Subject CN、有效期、状态点；点击切换详情。
- **右栏**：
  - 摘要：Subject、Issuer、Serial、Validity、公钥曲线、签名算法、SHA-256 指纹。
  - 扩展：KeyUsage（digitalSignature / keyAgreement 高亮）、BasicConstraints、SAN、SKI/AKI。
  - 验签：选择链中的签发者或粘贴签发者公钥 → 验证证书签名；显示“密码学校验通过 / 失败原因”。
  - 公钥提取：`X‖Y`（DLMS key_data）、`04‖X‖Y`、SPKI PEM、JWK；一键复制。
  - 用此证书验 DLMS 签名：消息 + raw/DER 签名 → 结果。
  - remove_certificate 参数：按 `by_serial` / `by_entity` 生成 class_id 64 方法 8 的 `certificate_identification`（A-XDR HEX + 字段表 + 复制）。
- **明确声明**：不做信任锚、CRL、OCSP；过期/未生效只做时间检查。
- **规划中**：证书签发、CSR 生成（灰显入口）。

#### 3.6.8 报文解析

- 输入：完整 HDLC 帧（`7E … 7E`）、wrapper 帧、或原始 APDU。
- 自动识别：
  - HDLC：去 flags、反转义、校验 FCS（CRC-16/X.25）、提取 APDU；FCS 错误时标红。
  - Wrapper：解析版本/长度，提取 APDU。
  - 原始 APDU：直接按标签解析。
- 安全层：
  - C8–CF / D0–D7：Tag、Len、SC、IC、C、T；Len 自洽检查。
  - DB/DC：system-title TLV、ciphered-content TLV。
  - DD：逐字段长度解析（tx、双 ST、date-time、other-info、key-info、ciphered-content）。
  - DF：字段 + 签名。
- 若填了密钥：内联解密/验签；否则只解析结构。
- 底部“送去解密”把字段带到报文保护页。

#### 3.6.9 算法总览 / 测试向量

- **算法总览**：按“报文保护 / 密钥 / 认证 / 签名证书 / 校验”分组的卡片；每张卡有状态徽标（可用 / 仅解析 / 规划中）、输入输出摘要、规范出处；点击进入对应页。Suite 3–15、V.44、证书签发以灰显“规划中”出现。
- **测试向量**：Table 48（3 条）、Table 51（2 条）、Table 52（2 条）、Annex C.1 KDF、AES-KW、CRC、SHA/MD5；每行“载入 / 运行 / 对比”；顶部“全部运行”显示通过数与失败详情。这个页面也是实现阶段的回归测试入口。

### 3.7 状态与交互细节

| 状态 | 表现 |
|---|---|
| 空 | 结果区显示“填入参数后计算”，不显示假数据；测试向量卡片可一键填充 |
| 计算中 | 主按钮 loading，结果区轻微遮罩；WebCrypto 异步，通常 <50 ms |
| 成功 | 绿色状态条 + 结果高亮一次；toast 可选关闭 |
| 参数已修改 | 结果区顶部琥珀细条“参数已变，结果仍是上一次的”，主按钮变为“重新计算” |
| 校验失败 | 红色状态条 + 具体原因 + “查看期望/实际” diff；认证失败默认隐藏明文 |
| 不支持 | 灰色卡片 + 说明 + 规范出处；不弹错误 |
| 复制成功 | 右下 toast 1.8 s；`aria-live="polite"` |

**其他交互**

- 粘贴完整 APDU 到解密框时，自动解析 Tag/Len/SC/IC；若 SC 的 suite 与当前选择不符，提示“报文声明 Suite 2，当前选择 Suite 0，是否切换？”
- 修改 Suite 时，若现有密钥长度不匹配，不静默清空；保留原值并标红，提示期望长度。
- `SC` 手动覆盖时，显示逐位开关（C/K/E/A/Suite），并与自动值双向同步。
- 所有“规划中”入口可点击查看说明，但不出现可用的计算按钮，避免误以为已支持。

### 3.8 输入校验规则

| 字段 | 规则 | 提示示例 |
|---|---|---|
| HEX | 去 `0x`/空格/`:`/`-`；偶数 nibble | `第 5 个字节只有半个字节（奇数个 HEX 字符）` |
| System Title | 恰好 8 B | `需要 8 B，当前 7 B（少 1 B）` |
| IC | 4 B，0–4294967295 | `IC 必须是 4 B（8 个 HEX 字符）` |
| EK/AK | Suite 0/1: 16 B；Suite 2: 32 B | `Suite 2 需要 32 B，当前 16 B` |
| Tag | 12 B | `DLMS tag 固定 12 B；当前 16 B，是否把 GCM 完整 tag 贴进来了？` |
| 签名 | P-256: 64 B；P-384: 96 B；DER 自动识别 | `64 B 像 DLMS plain 签名；DER 通常以 30 开头` |
| 质询值 (challenge) | 8–64 B；HLS-7 32–64 B | `HLS-7 的质询值至少 32 B` |
| APDU Len | `2 + Len` 或字段自洽 | `Len=30，但标签后只有 28 B` |
| 证书 | PEM 头尾完整 / DER 以 `30` 开头 | `PEM 缺少 END CERTIFICATE 行` |
| 证书时间 | 当前时间在 validity 内 | `证书已于 2025-... 过期（本机时间 ...）` |
| keyUsage | 签名用 digitalSignature；ECDH 用 keyAgreement | `该证书 keyUsage 不含 digitalSignature` |
| 曲线 | P-256/P-384 与套件匹配 | `Suite 2 应使用 P-384，当前公钥是 P-256` |

### 3.9 无障碍与移动端

- 所有输入有可见 `<label>`；错误用 `aria-describedby` + `aria-live="polite"`。
- 状态不只靠颜色：图标 + 文字 + 边框样式三重表达。
- 键盘可达：Tab 顺序 = 表单顺序；分段控件支持左右箭头；字节格可 Tab 聚焦并读出偏移/字段。
- 触控目标 ≥44×44 px；移动端不依赖 hover。
- 对比度 ≥ WCAG AA；字节色块上的文字用深色，不用浅色叠浅色。
- `prefers-reduced-motion` 时取消高亮动画。
- 移动端 375 px 宽度下无横向页面滚动（字节视图/字段表自身可滚）。

---

## 4. 技术方案

### 4.1 目录结构（已实现）

```
dlms-tool/
├─ index.html
├─ DESIGN.md
├─ design-preview.html          # 本轮的静态版式预览
├─ assets/
│  ├─ css/app.css
│  └─ js/
│     ├─ core/
│     │  ├─ bytes.js            # HEX/Base64/UTF-8、清零、常数时间比较
│     │  ├─ gcm.js              # AES-CTR + GHASH；支持 12 B tag
│     │  ├─ aes-kw.js           # RFC 3394（优先 WebCrypto AES-KW）
│     │  ├─ hash.js             # SHA-1/256/384/512 + MD5
│     │  ├─ kdf.js              # NIST Concatenation KDF
│     │  ├─ ec.js               # ECDSA/ECDH、raw↔DER、原始私钥 d→JWK
│     │  ├─ x509.js             # ASN.1 DER 解析、证书模型、验签
│     │  ├─ crc.js              # CRC-16/32 表驱动
│     │  └─ dlms.js             # SC、APDU 封装/解析、HLS 公式
│     ├─ ui/
│     │  ├─ app.js              # 路由、状态、toast
│     │  ├─ fields.js           # ByteField、格式转换、校验
│     │  ├─ result.js           # 字节视图、字段表、轨迹
│     │  └─ views/*.js          # 各页面
│     └─ vectors.js             # 规范测试向量
└─ tests/
   ├─ gcm.test.js
   ├─ kdf.test.js
   ├─ ec.test.js
   ├─ x509.test.js
   └─ crc.test.js
```

无构建步骤、无运行时依赖、无 CDN。使用经典 `<script>`（非 ES module），保证双击 `index.html` 也能运行；核心模块同时暴露 `globalThis.DLMS` 与 `module.exports`，便于 Node 测试。

### 4.2 关键实现决策

1. **GCM 12 B tag 的自研路径**
   WebCrypto 的 AES-GCM 只支持 16 B tag，无法直接校验 DLMS 的 12 B tag。方案：用 WebCrypto AES-CTR 生成密钥流，自己实现 GHASH 与 tag 截断；加密/解密/验签统一走这一条路径。用 Table 48 / 51 的全部向量做字节级回归。
   - 备选：加密用 WebCrypto AES-GCM 后截前 12 B；解密仍需 GHASH 验签，代码路径会分裂。因此统一用 CTR+GHASH 更可控。
2. **AES-KW 优先原生**
   `crypto.subtle.wrapKey/unwrapKey` 的 AES-KW 实现 RFC 3394；现代浏览器均支持，不支持时给出明确错误（v1 未实现纯 JS 回退）。
3. **ECDSA 的 raw 格式**
   WebCrypto `sign()` 返回的正是 `R‖S`（P-256 64 B、P-384 96 B），与 DLMS 报文一致；证书验签时把 DER 转 raw。公钥 `raw` 是 `04‖X‖Y`（65/97 B），DLMS key_data 需要去掉 `04`。
4. **原始私钥 d**
   v1 支持原始私钥 d：用内置 P-256/P-384 点乘推导公钥 Q，再构造 JWK 导入 WebCrypto。这样可以直接处理“只有 32/48 B 私钥”的现场材料，不必先转 PKCS#8。
5. **X.509 解析器自研**
   只实现 DLMS 证书需要的子集：Certificate/TBSCertificate、RDN、Validity、SPKI、常用扩展（KeyUsage、BasicConstraints、SAN、SKI/AKI）。长度支持短形式与 `0x81/0x82/0x83` 长形式；字符串支持 UTF8String/PrintableString/IA5String/BMPString。解析失败给出“第几个 TLV、期望什么”。
6. **状态与路由**
   不引入框架；一个轻量 store + `hashchange` 路由。表单状态只在内存中，`sessionStorage` 不存密钥；刷新即清空。
7. **安全边界**
   无网络请求、无第三方脚本、无遥测；密钥不写 localStorage；提供“清除全部密钥”按钮；页面卸载时清空引用。工具定位为诊断/教学，不做侧信道防护，不用于生产密钥管理。

### 4.3 测试与验收

**规范向量（必须全过）**

| 向量 | 期望 |
|---|---|
| Table 48 仅认证 | tag `06725D910F9221D263877516` |
| Table 48 仅加密 | C `411312FF935A47566827C467BC`（tag 不携带） |
| Table 48 认证+加密 | C 同上，tag `7D825C3BE4A77C3FCC056B6B` |
| Table 51 f(StoC) | `10000000011A52FE7DD3E72748973C1E28` |
| Table 51 f(CtoS) | `1001234567FE1466AFB3DBCD4F9389E2B7` |
| Table 52 f(StoC) / f(CtoS) | 两条 64 B 签名，用对应公钥验签通过 |
| Annex C.1 KDF | `C5F4512846EDE51CFB8CCF59F08A694E002EDF66B4CB1739AC26A74E49712F46`（Suite 1 取前 16 B） |
| AES-KW | `2E407E7FE4E742B77DC1B743516DE8455C77DC7C7391D924` |
| CRC-16/X.25(`123456789`) | `0x906E` |
| SHA-256("abc") | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| MD5("abc") | `900150983cd24fb0d6963f7d28e17f72` |

**实际验收（2026-10-21）**

- `node tests/run-tests.js` → **44 passed, 0 failed**（含 P-384 / RSA 证书、Suite 2 保护/解密往返、HLS-5 Suite 1/2 SC）。
- `node tests/ui-smoke.js` → **21 passed, 0 failed**（需本地 HTTP 服务 + Edge 远程调试；脚本见 `tests/ui-smoke.js`）。
- 浏览器“测试向量 → 全部运行” → **13 / 13 通过**。
- 已验证 1440 px 桌面与 390 px 移动布局；本机只实测 Edge（Chromium）内核，Firefox / Safari 未实测。

**其他验收**

- Node 测试全绿；浏览器“测试向量 → 全部运行”全绿。
- 目标浏览器：Chrome / Edge / Firefox / Safari 最新两个大版本；移动端 390 px、768 px、1440 px 三档。
- 无 console error；无网络请求（DevTools Network 为空，除本地文件）。
- 认证失败时默认不展示明文；仅加密时有明确警告。
- 所有“规划中”入口不可执行计算。

### 4.4 风险与对策

| 风险 | 对策 |
|---|---|
| GHASH/12 B tag 实现错 | 用 Table 48/51 全向量逐字节回归；再与 Python `cryptography` 交叉验证 |
| X.509 边界情况多 | 只支持 DLMS 相关子集；解析失败给 TLV 位置；用自签/中间证书样本测试 |
| 原始私钥 d→JWK 点乘错 | 与 WebCrypto 生成的密钥对交叉验证；校验 Q 在曲线上 |
| `file://` 下 WebCrypto 受限 | 优先测试 Chrome/Edge；文档给出 `python -m http.server` 兜底 |
| 大输入卡顿 | GHASH 用 32-bit 分块优化；输入 >64 KB 警告，>1 MB 拒绝 |
| 规范歧义 | 反推结论在 UI 内标注“反推/需实测”，并链接 `NOTES.md` 的核实台账 |
| 用户误把工具当生产密码机 | 顶部常驻“诊断/教学工具”标识；关于页写清边界 |

---

## 5. 实施顺序

> **P0–P6 已全部完成**；验收结果见 §0.1。下表保留为实施记录。

| 阶段 | 内容 | 验收 |
|---|---|---|
| P0 | 目录、设计 token、应用壳、路由、ByteField | 桌面/移动布局无溢出 |
| P1 | `bytes` / `gcm` / `dlms` + Table 48 向量 | GCM 三条全过 |
| P2 | 报文保护页：表单、校验、结果、字段表、轨迹 | 加密/解密闭环；错误提示可复现 |
| P3 | GMAC、HLS 3/4/5/6、AES-KW、KDF、哈希、CRC | Table 51 / Annex C.1 / KW / CRC 全过 |
| P4 | ECDSA、ECDH、raw↔DER、原始私钥 d | Table 52 验签通过 |
| P5 | X.509 解析/验签/链/公钥提取 | 样本证书全字段正确 |
| P6 | 报文解析、算法总览、测试向量页、响应式与无障碍 | 全量自检通过；移动端验收 |

每个阶段结束都跑一次 `tests/` 与浏览器自检；P1 不通过不进入 P2。

---

## 6. 已确认的 6 个点（2026-10-21，全按推荐）

> 以下是已确认记录，不再是待确认项；实现按这些默认值落地。

1. **范围与节奏**
   - 推荐：v1 做全套 8 个能力域，但按 P0–P6 分阶段交付；先把“报文保护 + GMAC + 测试向量”跑通，再扩证书/解析。
   - 备选：先只做报文保护 + GMAC + 哈希/CRC，证书/签名/解析放第二版。

2. **报文封装范围**
   - 推荐：v1 **构建 + 解析** C8–CF、D0–D7、DB/DC；**DD（general-ciphering）只做解析**，构建放 v2；DF 做解析，验签可在签名页对 content 完成，构建放 v2。
   - 备选：v1 就把 DD 的构建也做全（工作量明显增加，key-info 三种 CHOICE 都要覆盖）。

3. **私钥输入格式**
   - 推荐：PKCS#8 PEM/DER、JWK、**原始私钥 d**（P-256/P-384，本地推导公钥）。
   - 备选：只支持 PKCS#8/JWK，原始私钥 d 让用户自己先转换。

4. **证书功能边界**
   - 推荐：v1 解析、验签、链式校验、公钥提取、用证书验 DLMS 签名；**不做**证书签发/CSR/CRL/OCSP。
   - 备选：再加“生成自签名测试证书”（需要额外的 ASN.1 编码器，工作量 +）。

5. **界面形态与主题**
   - 推荐：多文件、无构建、可直接打开；浅色内容区 + 深色导航；中文界面保留英文术语；预留深色主题变量。
   - 备选：单文件 HTML（方便转发，但维护差）；或纯浅色无深色导航。

6. **目录名**
   - 推荐：`dlms-tool/`（当前已建，只有设计文档与预览）。
   - 备选：`dlms-crypto-workbench/`、`security-tool/`。

---

## 7. 附：本方案与现有资料的对应关系

- Suite 表、SC 位图、P/AAD：`reference/security-suites.html`、`dlms-security-complete-guide.html` 第 1–2 章。
- Table 48 三条报文、C8 Len 语义：第 2 课、完整教程 §6.6。
- Table 51 / HLS-5 IV 反推：第 4 课、`NOTES.md` 2026-10-07 条目。
- Table 52 / plain vs DER：完整教程 §7.7.1、`NOTES.md` 2026-10-20 更正。
- KDF（NIST Concatenation，不是 CMAC）：完整教程 §2.9、`.research/green-book-security-extract.md` §6。
- Suite 2 截断问题、Gurux 实现差异：`NOTES.md`「规范 vs 本地 Gurux 实现」。
- 证书字段、keyUsage、04 前缀：完整教程 §3.5–3.6。

> 本方案不修改上述任何文件；实现阶段只在 `dlms-tool/` 内新增代码。测试向量使用规范公开示例密钥，仅用于算法自检。
