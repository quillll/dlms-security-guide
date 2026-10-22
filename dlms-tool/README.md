# DLMS/COSEM 安全算法工作台

离线、零依赖的浏览器工具，用于 DLMS/COSEM 安全层的**计算、校验与报文拆分**。所有密钥与明文只在本地浏览器内处理，不上传、不持久化。

## 快速开始

- 直接双击 `index.html`（推荐 Edge / Chrome 等现代浏览器）。
- 或在本目录启动本地 HTTP 服务：

```bash
python -m http.server 8765 --bind 127.0.0.1
# 打开 http://127.0.0.1:8765/
```

不需要 `npm install`，没有构建步骤，没有 CDN / 外部字体 / 遥测。

## 功能

| 页面 | 能做什么 | v1 状态 |
|---|---|---|
| 报文保护 | AES-GCM 加密/解密；认证+加密 / 仅认证（GMAC）/ 仅加密；glo/ded-ciphering（C8–CF / D0–D7）与 general-glo/ded-ciphering（DB / DC） | 可用 |
| GMAC 认证 | 报文 GMAC 与 HLS-5；输出 `SC‖IC‖T` | 可用 |
| HLS 双向认证 | mechanism 3/4/5/6/7，客户端/服务端方向；公式与规范向量对比 | 可用 |
| 密钥工具 | AES-KW（RFC 3394）、ECDH + Concatenation KDF、KDF 单算、随机密钥 | 可用 |
| 哈希与校验 | SHA-256/384/512、SHA-1、MD5、HMAC、CRC-16/X.25（HDLC FCS）、CRC-32 | 可用 |
| 数字签名 | ECDSA P-256/P-384；raw `R‖S` ↔ DER；PKCS#8 / JWK / 原始私钥 d | 可用 |
| 证书 | X.509 解析、验签、链式校验、公钥提取（X‖Y / 04‖X‖Y / SPKI / JWK） | 可用 |
| 报文解析 | HDLC / wrapper / 原始 APDU；FCS 校验；SC/IC/密文/tag 字段拆分；可选内联解密 | 可用 |
| 算法总览 | 算法注册表与规范出处；规划中入口灰显 | 可用 |
| 测试向量 | Table 48 / 51 / 52、Annex C.1、AES-KW、CRC、SHA/MD5、证书链 | 可用（13/13） |

**未实现、仅保留入口**：V.44 压缩、general-ciphering（DD）构建、general-signing（DF）构建、证书签发/CSR、CRL/OCSP、信任锚判断、Suite 3–15。

## 术语

为避免直译造成的歧义，界面统一使用：

- **质询值（challenge）**：HLS 双向认证里由一方生成、另一方处理的随机值；避免直译成泛化的说法。
- **glo-ciphering / ded-ciphering**：界面简写，对应 service-specific glo/ded-ciphering（C8–CF / D0–D7）；`general-glo-ciphering` / `general-ded-ciphering`（DB / DC）保留 `general-` 前缀。中文只作解释。
- **原始私钥 d（raw scalar）**：32 B（P-256）或 48 B（P-384）的私钥标量，不是 PKCS#8。

## 测试

核心算法（Node 22，使用 WebCrypto）：

```bash
node tests/run-tests.js
# 期望：44 passed, 0 failed
```

浏览器 UI 冒烟（需要本地 HTTP 服务 + 带远程调试端口的 Edge）：

```bash
# 终端 1
python -m http.server 8765 --bind 127.0.0.1

# 终端 2
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" ^
  --headless=new --disable-gpu --remote-debugging-port=9223 ^
  http://127.0.0.1:8765/index.html

# 终端 3
node tests/ui-smoke.js
# 期望：21 passed, 0 failed
```

也可以打开页面里的「测试向量」→「全部运行」，在浏览器内跑 13 条规范向量。

测试证书由 OpenSSL 生成，放在 `tests/fixtures/`；只用于测试，不要用于生产。

## 目录

```
dlms-tool/
├─ index.html                  # 实际工具入口
├─ assets/
│  ├─ css/app.css
│  └─ js/
│     ├─ core/                 # bytes / gcm / hash / aes-kw / kdf / ec / x509 / crc / dlms
│     ├─ ui/                   # components.js / app.js
│     └─ vectors.js            # 规范向量 + 示例证书链
├─ tests/
│  ├─ run-tests.js             # 核心算法 44 项
│  ├─ ui-smoke.js              # UI 冒烟 21 项（CDP）
│  ├─ screenshots.js           # 评审截图脚本（可选）
│  └─ fixtures/                # OpenSSL 生成的测试证书
├─ DESIGN.md                   # 算法调研、UI 方案、技术决策与验收
├─ design-preview.html         # 历史静态设计稿
└─ README.md
```

## 安全边界

- 这是**诊断 / 教学工具**，不是生产密码机；没有侧信道防护、密钥生命周期管理或 HSM 集成。
- 所有计算在浏览器本地完成；没有网络请求，密钥不写入 `localStorage` / `sessionStorage`。
- 示例密钥与证书来自公开规范或测试夹具；**不要用于生产**。
- 证书页只做密码学校验（签名、有效期、keyUsage、链式签名），**不做信任锚、CRL、OCSP**。
- `file://` 下 WebCrypto 在部分浏览器可能受限；如遇问题，用本地 HTTP 服务打开。

## 规范出处

- Green Book Ed.11 §9.2：安全套件、SC、AES-GCM/GMAC、密钥包装、KDF、HLS、证书。
- Green Book Ed.11 Annex C：KDF / key agreement 测试向量。
- Blue Book Ed.17 Part 2：Security Setup、证书与密钥接口类。
- IEC 62056-46：HDLC FCS（CRC-16/X.25）。
- RFC 3394：AES Key Wrap；RFC 5280：X.509。

更完整的设计与取舍见 `DESIGN.md`。
