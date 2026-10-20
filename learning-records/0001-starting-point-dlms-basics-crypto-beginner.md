# 起点：DLMS 基础已具备，密码学初学；目标为「实现/对接 + 读懂原文」

用户自述已掌握 DLMS/COSEM 的基本概念（OBIS、COSEM 对象、HDLC/wrapper），但**密码学是初学**；学习目的是实现/对接 DLMS 客户端或服务端、读懂绿皮书/蓝皮书原文，并先建立整体认知。首次会话明确了第一个具体主题：Suite 0/1/2 的详细区别与加解密算法。因此后续课程必须把"密码学直觉"与"规范条款"分开喂：先给最小必要的算法直觉（例如 GCM 的 IV 唯一性、ECDH 与 ECDSA 的分工），再进 §9.2 的表格与字节布局。

**Evidence**：首次会话的定向提问中明确选择"懂 DLMS/COSEM 基本概念"与"密码学是初学"两档，并主动指定主题为 "suite0-2 的详细区别，加解密算法等"；同时可访问本地 Green Book Ed.11 / Blue Book Ed.17 与 Gurux 三个语言的实现，说明其工作环境偏工程实现。

**Implications**：
- 不要重教 OBIS / COSEM 对象模型 / HDLC 帧结构；涉及时只做一句带过并给链接。
- 每课涉及 AES-GCM / ECDH / ECDSA 时，必须先在课内给出一句话直觉或指向 `reference/crypto-primer.html`，否则会超出工作记忆。
- 用户具备读英文规范的能力与材料（本地 PDF + Markdown），课程应持续给出**章节号 + 页码**级别的一手引用，并鼓励自行核对。
- 可放心使用本地 Gurux 实现与 Translator 工具作为"动手验证"环节（`.research/gurux-implementation-extract.md` 已在抽取中）。

**未验证的假设（下次可校准）**：用户偏好的实现语言尚不清楚（本地同时存在 C#、Java、C、Rust 参考），后续做代码级练习前应先问。
