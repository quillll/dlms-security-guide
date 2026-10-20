#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DLMS/COSEM 报文字节级加解密 · 对拍脚本
=======================================

用途：把绿皮书 Ed.11 自己给出的示例，用一份**独立实现**重算一遍，
      看能不能得到规范上印着的那串字节。能对上，就说明你理解了
      IV 怎么拼、AAD 放什么、tag 取多少位、KDF 的输入顺序。

用法：
    python verify-dlms-gcm.py

依赖：cryptography（`pip install cryptography`）。只用它的 AES-GCM 原语，
      不依赖任何 DLMS 库——这正是重点：用第三方原语复现 DLMS 的组装规则。

对拍目标（绿皮书 Ed.11）：
  第 1 部分  §9.2.7.2.4.10 Table 48 (p.255)  glo-get-request 的三种保护
  第 2 部分  §9.2.3.4.6.5 / Annex C.1 的 KDF 测试向量（Z → KDF → GUEK）
"""

import sys

# Windows 控制台默认可能是 GBK，先把输出编码固定成 UTF-8，避免中文变成乱码。
# （若你的终端仍显示乱码，先执行一次  chcp 65001 ）
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    sys.exit("需要 cryptography：请先执行  pip install cryptography")


# ══════════════════════════════════════════════════════════════════════
# 第 1 部分：Table 48 —— 同一条 Get-request，三种保护
# ══════════════════════════════════════════════════════════════════════

# 安全材料（Table 48 逐字）
SYS_T = bytes.fromhex("4D4D4D0000BC614E")                        # System Title, 8 octets
IC    = bytes.fromhex("01234567")                                # Invocation counter, 4 octets
EK    = bytes.fromhex("000102030405060708090A0B0C0D0E0F")        # Block cipher key, 16 octets
AK    = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")        # Authentication key, 16 octets
APDU  = bytes.fromhex("C0010000080000010000FF0200")              # Get-request (Clock, attr 2), 13 octets

IV = SYS_T + IC                                                  # §9.2.3.3.7.3: IV = Sys-T ‖ IC
TAG_LEN = 12                                                     # §9.2.3.3.7.6: t = 96 bit

# 规范上印着的期望值（Table 48）
EXPECT = {
    "auth_only": dict(                      # SC = 0x10
        ct=None,
        tag="06725D910F9221D263877516",
        frame="C81E1001234567C0010000080000010000FF020006725D910F9221D263877516",
    ),
    "encrypted": dict(                      # SC = 0x20
        ct="411312FF935A47566827C467BC",
        tag=None,
        frame="C8122001234567411312FF935A47566827C467BC",
    ),
    "auth_enc": dict(                       # SC = 0x30
        ct="411312FF935A47566827C467BC",
        tag="7D825C3BE4A77C3FCC056B6B",
        frame="C81E3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B",
    ),
}

GLO_GET_REQUEST = 0xC8                  # service-specific glo-ciphering 的 APDU tag


def gcm(sc_byte: bytes, plaintext: bytes, aad: bytes, key: bytes = EK):
    """按 DLMS 规则做一次 GCM：返回 (密文, 12 字节 tag)。

    DLMS 把 16 字节 tag 截到 96 bit；截断只取前 12 字节。
    """
    out = AESGCM(key).encrypt(IV, plaintext, aad)
    ct, tag16 = out[: len(out) - 16], out[len(out) - 16:]
    return ct, tag16[:TAG_LEN]


def build_frame(sc: bytes, payload: bytes, tag: bytes | None) -> bytes:
    """Tag ‖ Len ‖ SH(SC‖IC) ‖ payload [‖ tag]；Len 覆盖 SH 起的全部内容。"""
    body = sc + IC + payload + (tag or b"")
    return bytes([GLO_GET_REQUEST, len(body)]) + body


def part1() -> bool:
    print("=" * 72)
    print("第 1 部分 · Table 48：同一条 Get-request 的三种保护（security suite 0）")
    print("=" * 72)
    print(f"  System Title          {SYS_T.hex().upper()}")
    print(f"  Invocation counter    {IC.hex().upper()}")
    print(f"  IV = Sys-T ‖ IC       {IV.hex().upper()}   ({len(IV)} octets)")
    print(f"  加密密钥 EK           {EK.hex().upper()}   ({len(EK)} octets = {len(EK)*8} bit)")
    print(f"  认证密钥 AK           {AK.hex().upper()}   ({len(AK)} octets = {len(AK)*8} bit)")
    print(f"  待保护的 APDU         {APDU.hex().upper()}   ({len(APDU)} octets)")
    print()

    ok = True

    # ── A = 1, E = 0：仅认证（GMAC）─────────────────────────────────
    sc = bytes([0x10])
    aad = sc + AK + APDU                      # Table 46：SC ‖ AK ‖ (C) I
    _, tag = gcm(sc, b"", aad)                # 不加密封装：P 为空
    frame = build_frame(sc, APDU, tag)        # 明文照原样上传，后面挂 tag
    print("① 仅认证（Authenticated only, SC = 0x10）")
    print(f"   AAD = SC ‖ AK ‖ APDU   {len(aad)} octets")
    print(f"   P                      （空——没有内容被加密）")
    print(f"   算出 tag               {tag.hex().upper()}")
    print(f"   规范 tag               {EXPECT['auth_only']['tag']}   {'✓ 一致' if tag.hex().upper() == EXPECT['auth_only']['tag'] else '✗ 不一致'}")
    print(f"   完整报文               {frame.hex().upper()}")
    ok &= tag.hex().upper() == EXPECT["auth_only"]["tag"]

    # ── A = 0, E = 1：仅加密 ────────────────────────────────────────
    sc = bytes([0x20])
    ct, tag_ignored = gcm(sc, APDU, b"")      # Table 46：AAD 为空，P = (C) I
    frame = build_frame(sc, ct, None)         # tag 不计算也不携带（§9.2.3.3.7.1）
    print()
    print("② 仅加密（Encrypted only, SC = 0x20）")
    print(f"   AAD                    （空）")
    print(f"   算出密文               {ct.hex().upper()}")
    print(f"   规范密文               {EXPECT['encrypted']['ct']}   {'✓ 一致' if ct.hex().upper() == EXPECT['encrypted']['ct'] else '✗ 不一致'}")
    print(f"   完整报文               {frame.hex().upper()}")
    print(f"   （GCM 内部仍会算出 tag = {tag_ignored.hex().upper()}，但 DLMS 不携带、不校验它）")
    ok &= ct.hex().upper() == EXPECT["encrypted"]["ct"]

    # ── A = 1, E = 1：认证 + 加密 ───────────────────────────────────
    sc = bytes([0x30])
    ct, tag = gcm(sc, APDU, sc + AK)          # Table 46：P = (C) I，AAD = SC ‖ AK
    frame = build_frame(sc, ct, tag)
    print()
    print("③ 认证 + 加密（Encrypted and authenticated, SC = 0x30）")
    print(f"   AAD = SC ‖ AK          {len(sc + AK)} octets")
    print(f"   算出密文               {ct.hex().upper()}")
    print(f"   规范密文               {EXPECT['auth_enc']['ct']}   {'✓ 一致' if ct.hex().upper() == EXPECT['auth_enc']['ct'] else '✗ 不一致'}")
    print(f"   算出 tag               {tag.hex().upper()}")
    print(f"   规范 tag               {EXPECT['auth_enc']['tag']}   {'✓ 一致' if tag.hex().upper() == EXPECT['auth_enc']['tag'] else '✗ 不一致'}")
    print(f"   完整报文               {frame.hex().upper()}")
    print(f"   规范报文               {EXPECT['auth_enc']['frame']}   {'✓ 一致' if frame.hex().upper() == EXPECT['auth_enc']['frame'] else '✗ 不一致'}")
    ok &= ct.hex().upper() == EXPECT["auth_enc"]["ct"]
    ok &= tag.hex().upper() == EXPECT["auth_enc"]["tag"]
    ok &= frame.hex().upper() == EXPECT["auth_enc"]["frame"]

    return ok


# ══════════════════════════════════════════════════════════════════════
# 第 2 部分：KDF —— Annex C.1 的测试向量（Suite 1）
# ══════════════════════════════════════════════════════════════════════

import hashlib

ALG_ID  = bytes.fromhex("60857405080300")   # Table 26: AES-GCM-128 = 2.16.756.5.8.3.0（7 octets）
SYS_TC  = bytes.fromhex("4D4D4D0000BC614E") # 客户端 system title
SYS_TS  = bytes.fromhex("4D4D4D0000000001") # 服务端 system title
Z       = bytes.fromhex("C1CF8FE7891AEF3617D7190795E61FE6C24EFC3CCA2E08469BAD1A225CE6EA08")

EXPECT_KDF  = "C5F4512846EDE51CFB8CCF59F08A694E002EDF66B4CB1739AC26A74E49712F46"
EXPECT_GUEK = "C5F4512846EDE51CFB8CCF59F08A694E"


def kdf_concat(z: bytes, other_info: bytes, hash_name: str, keydatalen_bits: int) -> bytes:
    """NIST Concatenation KDF（§9.2.3.4.6.5 引用 SP 800-56A 5.8.1.1）。

    K(i) = Hash( counter(i) ‖ Z ‖ OtherInfo )，counter 为 4 字节大端，从 1 开始。
    规范：OtherInfo = AlgorithmID ‖ PartyUInfo ‖ PartyVInfo（SuppPub/SuppPriv 不使用）。
    """
    out = b""
    counter = 1
    while len(out) * 8 < keydatalen_bits:
        out += hashlib.new(hash_name, counter.to_bytes(4, "big") + z + other_info).digest()
        counter += 1
    return out[: (keydatalen_bits + 7) // 8]


def part2() -> bool:
    print()
    print("=" * 72)
    print("第 2 部分 · KDF：Annex C.1 的测试向量（security suite 1）")
    print("=" * 72)
    other_info = ALG_ID + SYS_TC + SYS_TS
    print(f"  Z                      {Z.hex().upper()}")
    print(f"  AlgorithmID            {ALG_ID.hex().upper()}   (AES-GCM-128, 7 octets)")
    print(f"  OtherInfo = AlgID ‖ PartyU ‖ PartyV")
    print(f"           = {other_info.hex().upper()}   ({len(other_info)} octets)")
    print(f"  hash                   SHA-256（suite 1）")

    full = kdf_concat(Z, other_info, "sha256", 128)
    # 规范的测试向量把 KDF 的整块输出（一个 SHA-256 = 32 字节）都印出来了，GUEK 取其前 16 字节
    full32 = hashlib.sha256((1).to_bytes(4, "big") + Z + other_info).digest()
    guek = full[:16]

    print()
    print(f"  Hash(1 ‖ Z ‖ OtherInfo) {full32.hex().upper()}")
    print(f"  规范 KDF 输出           {EXPECT_KDF}   {'✓ 一致' if full32.hex().upper() == EXPECT_KDF else '✗ 不一致'}")
    print(f"  GUEK = 前 16 字节       {guek.hex().upper()}")
    print(f"  规范 GUEK               {EXPECT_GUEK}   {'✓ 一致' if guek.hex().upper() == EXPECT_GUEK else '✗ 不一致'}")
    print()
    print("  ← 注意这里长度对不上的地方：Suite 1 的 keydatalen 是 128 bit（16 字节），")
    print("    但一次 SHA-256 会给出 32 字节。规范只取前 16 字节当 GUEK。")
    print("    这正是「实现容易把 Suite 2 的密钥也截成 16 字节」的诱因（见 NOTES.md）。")

    return full32.hex().upper() == EXPECT_KDF and guek.hex().upper() == EXPECT_GUEK


def part3() -> bool:
    """Annex C.2 / C.3：密钥协商产出的密钥，能不能用规范印的 Z 复算出来。

    这一部分专门演示一件事：KDF 的「谁的 system title 在前」决定结果。
    同一把 Z，PartyU/PartyV 顺序换个方向，派生出的密钥完全不同。
    """
    print()
    print("=" * 72)
    print("第 3 部分 · 密钥协商：Annex C.2（One-Pass DH）与 C.3（Static Unified）")
    print("=" * 72)

    ok = True

    def check(title, z_hex, other, expected_kdf, expected_ek):
        nonlocal ok
        got = hashlib.sha256((1).to_bytes(4, "big") + bytes.fromhex(z_hex) + other).digest()
        g = got.hex().upper()
        hit = (g == expected_kdf)
        ok &= hit and g[:32] == expected_ek
        print(f"  {title}")
        print(f"    OtherInfo            {other.hex().upper()}")
        print(f"    算出                  {g}")
        print(f"    规范                  {expected_kdf}   {'✓ 一致' if hit else '✗ 不一致'}")
        print(f"    EK = 前 16 字节       {g[:32]}   {'✓' if g[:32] == expected_ek else '✗ 规范 ' + expected_ek}")

    ALG_GCM128 = bytes.fromhex("60857405080300")

    # C.2 C(1e,1s) ECC CDH：客户端方向 KDF(Z, AlgID, Sys-TC, Sys-TS)
    Z_C2_C = "0D4385BA0DD756CBCAB9887EB538396EE8F090A14C1079B4359F115B977F4615"
    check("C.2 请求方向 · KDF(Z, AlgID, Sys-TC, Sys-TS)", Z_C2_C,
          ALG_GCM128 + SYS_TC + SYS_TS,
          "59A71FD81C929A86A99438DA17A66C058C6A93FD3065F5EE16A05D775927659B",
          "59A71FD81C929A86A99438DA17A66C05")

    # C.2 服务端方向：同一把性质，但两个 system title 交换位置
    Z_C2_S = "2B4302DC49790E2E78D990CFB52ED6E2F273DECE441A2D95E4301B93812A9FAC"
    check("C.2 响应方向 · KDF(Z, AlgID, Sys-TS, Sys-TC)", Z_C2_S,
          ALG_GCM128 + SYS_TS + SYS_TC,
          "F0184BDA9466BFA4601A64A7EF46504AB1A40C4851A0A644503599DF298B2E14",
          "F0184BDA9466BFA4601A64A7EF46504A")

    # C.3 C(0e,2s) ECC CDH：多了 NonceU（= 1 字节长度 + transaction-id）
    Z_C3 = "B1455B2AD5F68BCFFE6AD5412BA89548ACA7E0CBF4B1560D6A57496F15E931AD"
    NONCE_C = bytes.fromhex("080102030405060708")   # 长度 08 + transaction-id 0102030405060708
    NONCE_S = bytes.fromhex("080123456789012345")
    check("C.3 请求方向 · KDF(Z, AlgID, Sys-TC, Nonce-C, Sys-TS)", Z_C3,
          ALG_GCM128 + SYS_TC + NONCE_C + SYS_TS,
          "56C46B57DF675515C31025455822514AFA2CDEB3E0BF1CADA84576159E84DE7E",
          "56C46B57DF675515C31025455822514A")
    check("C.3 响应方向 · KDF(Z, AlgID, Sys-TS, Nonce-S, Sys-TC)", Z_C3,
          ALG_GCM128 + SYS_TS + NONCE_S + SYS_TC,
          "FC1314F7DE033B7DD19C80DBCF9FF2C5286DC8F76E87877BD90B9B7F00CD5613",
          "FC1314F7DE033B7DD19C80DBCF9FF2C5")

    print()
    print("  ← 注意 C.2 的两个方向：Z 不同、且 system title 的顺序相反；")
    print("    C.3 则在同一把 Z 上靠 NonceU 区分每次交易。顺序写反 = 派生出的密钥完全不同。")
    return ok


# ══════════════════════════════════════════════════════════════════════
# 第 4 部分：HLS 认证 mechanism 5（GMAC）—— Table 51 的测试向量
# ══════════════════════════════════════════════════════════════════════
#
# 这是「报文级认证 ≠ 报文保护」的活证据：同一条 GMAC 计算，既用来算
# ciphering 报文的 tag（第 1 部分），也用来处理 HLS 的挑战值。
# 而且注意：这里被认证的内容——(SC ‖ AK ‖ StoC) 或 (SC ‖ AK ‖ CtoS)——
# 是明文（没有任何东西被加密），正是第 1 部分「仅认证」那一档的做法。

# Table 51 的服务端/客户端 system title 与 Table 48 恰好互换角色：
SYS_TC_HLS = bytes.fromhex("4D4D4D0000000001")   # 客户端 system title
SYS_TS_HLS = bytes.fromhex("4D4D4D0000BC614E")   # 服务端 system title
IC_C_HLS   = bytes.fromhex("00000001")           # 客户端 invocation counter
IC_S_HLS   = bytes.fromhex("01234567")           # 服务端 invocation counter
CTOS       = bytes.fromhex("4B35366956616759")   # "K56iVagY"，8 octets
STOC       = bytes.fromhex("503677524A323146")   # "P6wRJ21F"，8 octets
SC_HLS     = bytes.fromhex("10")                 # GCM-AES-128 + 仅认证（A=1, E=0）

EXPECT_HLS = {
    # Pass 3：客户端算 f(StoC)。IV 用【本端】的 Sys-T ‖ IC —— 算的一方是客户端。
    "f_stoc": dict(
        iv=SYS_TC_HLS + IC_C_HLS,
        tag="1A52FE7DD3E72748973C1E28",
        out="10000000011A52FE7DD3E72748973C1E28",
    ),
    # Pass 4：服务端算 f(CtoS)。IV 用【本端】的 Sys-T ‖ IC —— 算的一方是服务端。
    "f_ctos": dict(
        iv=SYS_TS_HLS + IC_S_HLS,
        tag="FE1466AFB3DBCD4F9389E2B7",
        out="1001234567FE1466AFB3DBCD4F9389E2B7",
    ),
}


def part4() -> bool:
    print()
    print("=" * 72)
    print("第 4 部分 · HLS mechanism 5（GMAC）：Table 51 的测试向量（security suite 0）")
    print("=" * 72)
    print(f"  System Title 客户端     {SYS_TC_HLS.hex().upper()}")
    print(f"  System Title 服务端     {SYS_TS_HLS.hex().upper()}")
    print(f"  Invocation counter C    {IC_C_HLS.hex().upper()}")
    print(f"  Invocation counter S    {IC_S_HLS.hex().upper()}")
    print(f"  CtoS                    {CTOS.hex().upper()}   (\"K56iVagY\")")
    print(f"  StoC                    {STOC.hex().upper()}   (\"P6wRJ21F\")")
    print(f"  AK                      {AK.hex().upper()}")
    print(f"  SC                      {SC_HLS.hex().upper()}   (仅认证：A=1, E=0)")
    print()
    print("  ★ 关键：两趟用的是【不同】的 IV ——")
    print("     GMAC 由谁计算，IV 就用【谁自己】的 Sys-T ‖ IC（即本端的 system title 与计数器）。")
    print("     客户端算 f(StoC) → 用客户端的 Sys-T ‖ IC 与客户端 IC；")
    print("     服务端算 f(CtoS) → 用服务端的 Sys-T ‖ IC 与  服务端 IC。")
    print("     这一点从 Table 51 的 f(x) 封装就能反推出来（f(StoC)=10 00000001 …、f(CtoS)=10 01234567 …）。")
    print()

    ok = True

    def check_hls(title, challenge, expect, iv):
        nonlocal ok
        global IV
        saved = IV
        IV = iv                                    # 临时切到本趟的 IV
        aad = SC_HLS + AK + challenge               # AAD = SC ‖ AK ‖ 挑战值（明文）
        _, tag = gcm(SC_HLS, b"", aad)              # P 为空 —— 与第 1 部分「仅认证」同一机制
        out = SC_HLS + iv[8:] + tag                 # f(x) = SC ‖ IC ‖ T
        IV = saved
        t = tag.hex().upper()
        o = out.hex().upper()
        hit = (t == expect["tag"]) and (o == expect["out"])
        ok &= hit
        print(f"  {title}")
        print(f"    IV = 本端 Sys-T ‖ IC        {iv.hex().upper()}")
        print(f"    AAD = SC ‖ AK ‖ 挑战        {len(aad)} octets（全是明文）")
        print(f"    算出 T                      {t}")
        print(f"    规范 T                      {expect['tag']}   {'✓ 一致' if t == expect['tag'] else '✗ 不一致'}")
        print(f"    算出 f(x) = SC ‖ IC ‖ T     {o}")
        print(f"    规范 f(x)                   {expect['out']}   {'✓ 一致' if o == expect['out'] else '✗ 不一致'}")
        print()

    check_hls("Pass 3 · 客户端处理 StoC（f(StoC)）", STOC, EXPECT_HLS["f_stoc"], EXPECT_HLS["f_stoc"]["iv"])
    check_hls("Pass 4 · 服务端处理 CtoS（f(CtoS)）", CTOS, EXPECT_HLS["f_ctos"], EXPECT_HLS["f_ctos"]["iv"])

    print("  ← 注意 f(x) 的封装：SC ‖ IC ‖ T 共 1+4+12 = 17 字节（规范 LEN(X)=17）。")
    print("    SC 与 IC 是【明文照带】的，唯独 T 是算出来的——这正是签名/认证报文的样子。")
    return ok


if __name__ == "__main__":
    ok1 = part1()
    ok2 = part2()
    ok3 = part3()
    ok4 = part4()
    allok = ok1 and ok2 and ok3 and ok4
    print()
    print("=" * 72)
    print("结论：" + ("全部对上 ✓  —— 你手上的实现若算不出这些值，差异就在上面某几行里"
                    if allok else "有对不上的地方 ✗  —— 逐行核对 IV / AAD / tag 长度 / KDF 输入顺序"))
    print("=" * 72)
    sys.exit(0 if allok else 1)
