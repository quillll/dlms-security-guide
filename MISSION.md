# Mission: DLMS/COSEM 安全套件（Suite 0/1/2）与报文级加解密

## Why

用户正在实现或对接 DLMS/COSEM 客户端/服务端（电表通信）。已具备 DLMS 基础概念（OBIS、COSEM 对象、HDLC/wrapper），但密码学是初学。目标是能读懂绿皮书/蓝皮书原文中关于安全套件的条款，并把它落到可运行的代码与可核对的报文上——而不是停留在"知道有 Suite 0/1/2"。

## Success looks like

- 能不看资料说出 Suite 0/1/2 各自**强制**哪些算法（对称加密、哈希、曲线/签名），以及每个套件**允许**哪些安全等级，并解释为什么 Suite 0 不等于"加密"。
- 拿到一个 association 配置或一段抓包，能判断：用的是哪个套件、哪条安全策略、哪个安全等级。
- 能读懂绿皮书 §9.2 的报文结构，并写出一个被 ciphering 保护的 GET 请求的完整字节布局（security header、invocation counter、tag 长度）。
- 能讲清 GMAC（仅认证）与 encryption（认证+加密）在 IV/AAD/tag 上的差别，并能指出代码里对应的几行。
- 能根据绿皮书的 KDF 条款，说清 encryption key / authentication key 是怎么从主密钥派生出来的（输入串、哈希、长度）。
- 能用本地的 Gurux 实现或 Translator 工具，独立验证自己对某一个报文字节的判断。

## Constraints

- 密码学是初学：AES-GCM、ECDH、ECDSA 需要先建立直觉，再进规范条款。
- 授课语言为中文；规范原文是英文，术语保留英文并配中文解释。
- 手边没有具体设备/型号，教学以绿皮书 Ed.11、蓝皮书 Ed.17 与本地 Gurux 实现为准。
- 每次只推进一个可完成的小单元；避免一次灌输整章。

## Out of scope

- 非安全部分的协议细节（HDLC 帧格式、OBIS 编码、PLC/RF 物理层）——已有基础，需要时再补。
- PKI 运营（CA 生命周期、证书签发流程）——只在必要处点到证书字段。
- 具体国家/客户规范的合规差异（如某国网规范）——用户暂无此需求。
