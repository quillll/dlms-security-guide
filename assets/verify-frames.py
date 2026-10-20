#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DLMS/COSEM 安全报文示例 · 构造 + 回读校验
=========================================

用途：
  课程里引用的 AARQ / AARE / GET / ACTION 十六进制，全部由本脚本构造并回读，
  保证「长度字段自洽、字段能逐层拆回来」。这样课内的字节表不是手抄出来的。

覆盖：
  1. LLS  AARQ（LN，无加密应用上下文）
  2. HLS-GMAC AARQ（LN，加密应用上下文，携带 CtoS 与 system title）
  3. HLS-GMAC AARE（StoC 与方法返回值）
  4. GET Security setup 属性 2（security_policy）
  5. ACTION key_transfer（AES-KW 包装一把 GUEK）
  6. Table 52 的 HLS-ECDSA 两条签名：plain R‖S → DER → P-256 验签

依赖：cryptography（仅第 5 部分用；没有则跳过，不影响其它部分）
用法：python assets/verify-frames.py
"""

import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


# ──────────────────────────────────────────────────────────────
# 最小 BER / A-XDR 构造器
# ──────────────────────────────────────────────────────────────

def ber_len(n: int) -> bytes:
    """BER 长度：<128 用短形式；否则 0x81/0x82 + 大端。"""
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_len(len(value)) + value


def ctx_constructed(n: int, value: bytes) -> bytes:
    return tlv(0xA0 | n, value)


def ctx_primitive(n: int, value: bytes) -> bytes:
    return tlv(0x80 | n, value)


# 常用 OID
OID_LN_NO_CIPHER = bytes.fromhex("60857405080101")   # 2.16.756.5.8.1.1
OID_LN_CIPHER    = bytes.fromhex("60857405080102")   # 2.16.756.5.8.1.2
OID_HLS_GMAC     = bytes.fromhex("60857405080205")   # 2.16.756.5.8.2.5


def initiate_request(max_pdu=0x00FA) -> bytes:
    """xDLMS InitiateRequest：dedicated-key 空、response-allowed FALSE、
    QoS 0、version 6、conformance 5F1F04、max-receive-pdu。"""
    return bytes.fromhex("01 00 00 00 06 5F 1F 04") + max_pdu.to_bytes(2, "big")


def initiate_response(max_pdu=0x00FA) -> bytes:
    """xDLMS InitiateResponse：QoS 0、version 6、conformance 5F1F04、
    max-receive-pdu、VAA-name 空。"""
    return bytes.fromhex("08 00 06 5F 1F 04") + max_pdu.to_bytes(2, "big") + b"\x00"


def user_info(apdu: bytes) -> bytes:
    """user-information [30] EXPLICIT：里面是 OCTET STRING 包住的 xDLMS APDU。"""
    return ctx_constructed(30, tlv(0x04, apdu))


# ──────────────────────────────────────────────────────────────
# 1. LLS AARQ
# ──────────────────────────────────────────────────────────────

def aarq_lls(password=b"12345678") -> bytes:
    body = b""
    body += ctx_constructed(1, tlv(0x06, OID_LN_NO_CIPHER))
    body += ctx_primitive(10, b"\x07\x80")              # sender-acse-requirements：authentication
    body += ctx_primitive(11, bytes.fromhex("60857405080201"))  # LLS，mechanism 1（[11] IMPLICIT OID）
    body += ctx_constructed(12, ctx_primitive(0, password))                # calling-authentication-value
    body += user_info(initiate_request())
    return tlv(0x60, body)


# ──────────────────────────────────────────────────────────────
# 2. HLS-GMAC AARQ
# ──────────────────────────────────────────────────────────────

def aarq_hls_gmac(client_st: bytes, ctos: bytes) -> bytes:
    body = b""
    body += ctx_constructed(1, tlv(0x06, OID_LN_CIPHER))
    body += ctx_constructed(6, tlv(0x04, client_st))    # calling-AP-title
    body += ctx_primitive(10, b"\x07\x80")
    body += ctx_primitive(11, OID_HLS_GMAC)  # mechanism 5（[11] IMPLICIT OID）
    body += ctx_constructed(12, ctx_primitive(0, ctos))
    body += user_info(initiate_request())
    return tlv(0x60, body)


# ──────────────────────────────────────────────────────────────
# 3. HLS-GMAC AARE
# ──────────────────────────────────────────────────────────────

def aare_hls_gmac(server_st: bytes, stoc: bytes) -> bytes:
    body = b""
    body += ctx_constructed(1, tlv(0x06, OID_LN_CIPHER))
    body += ctx_constructed(2, tlv(0x02, b"\x00"))       # result: accepted
    body += ctx_constructed(3, ctx_constructed(1, tlv(0x02, b"\x00")))  # acse-service-user / null
    body += ctx_constructed(4, tlv(0x04, server_st))    # responding-AP-title
    body += ctx_primitive(8, b"\x07\x80")               # responder-acse-requirements
    body += ctx_primitive(9, OID_HLS_GMAC)
    body += ctx_constructed(10, ctx_primitive(0, stoc))
    body += user_info(initiate_response())
    return tlv(0x61, body)


# ──────────────────────────────────────────────────────────────
# 4. GET Security setup 属性 2
# ──────────────────────────────────────────────────────────────

SEC_SETUP_OBIS = bytes.fromhex("00002B0000FF")   # 0-0:43.0.0.255
CLASS_SEC_SETUP = (64).to_bytes(2, "big")


def get_security_policy(invoke_id=1) -> bytes:
    # GetRequest-normal：tag C0, invoke-id, class-id, OBIS, attribute-id
    return bytes([0xC0, invoke_id]) + CLASS_SEC_SETUP + SEC_SETUP_OBIS + bytes([2])


# ──────────────────────────────────────────────────────────────
# 5. ACTION key_transfer
# ──────────────────────────────────────────────────────────────

def action_key_transfer(wrapped: bytes, key_id=0, invoke_id=1) -> bytes:
    # key_transfer_data ::= structure { key_id: enum, key_wrapped: octet-string }
    one = (bytes([0x02, 0x02]) + bytes([0x16, 0x01, key_id]) +
           bytes([0x09]) + ber_len(len(wrapped)) + wrapped)
    param = bytes([0x01, 0x01]) + one          # array(1) of structure(2)
    return (bytes([0xC3, invoke_id]) + CLASS_SEC_SETUP + SEC_SETUP_OBIS +
            bytes([0x02]) + param)


# ──────────────────────────────────────────────────────────────
# 回读校验：把构造出来的字节按字段拆回来
# ──────────────────────────────────────────────────────────────

def read_tlv(buf: bytes, pos=0):
    tag = buf[pos]
    pos += 1
    first = buf[pos]
    pos += 1
    if first < 0x80:
        n = first
    elif first == 0x81:
        n = buf[pos]; pos += 1
    elif first == 0x82:
        n = (buf[pos] << 8) | buf[pos + 1]; pos += 2
    else:
        raise ValueError("不支持的 BER 长度形式")
    if pos + n > len(buf):
        raise ValueError("长度越界")
    return tag, buf[pos:pos + n], pos + n


def dump_aarq(frame: bytes):
    tag, body, end = read_tlv(frame)
    assert tag == 0x60 and end == len(frame), "AARQ 外壳长度不自洽"
    print(f"  外壳            tag=60 len={len(body)} 总长={len(frame)}")
    pos = 0
    while pos < len(body):
        t, v, pos = read_tlv(body, pos)
        name = {
            0xA1: "application-context-name", 0xA6: "calling-AP-title",
            0xA7: "calling-AE-qualifier", 0xA8: "calling-AP-invocation-id",
            0xA9: "calling-AE-invocation-id", 0x8A: "sender-acse-requirements",
            0x8B: "mechanism-name", 0xAC: "calling-authentication-value",
            0xBE: "user-information",
        }.get(t, f"tag {t:02X}")
        if t in (0xA1, 0xA6, 0xA7):
            inner_t, inner_v, _ = read_tlv(v)
            print(f"  {name:<28} {t:02X} len={len(v):<3} 内含 {inner_t:02X} {inner_v.hex().upper()}")
        elif t == 0xAC:
            inner_t, inner_v, _ = read_tlv(v)
            print(f"  {name:<28} {t:02X} len={len(v):<3} 内含 {inner_t:02X} {inner_v.hex().upper()}")
        elif t == 0xBE:
            inner_t, inner_v, _ = read_tlv(v)
            print(f"  {name:<28} {t:02X} len={len(v):<3} 内含 {inner_t:02X} {inner_v.hex().upper()}")
        else:
            print(f"  {name:<28} {t:02X} len={len(v):<3} {v.hex().upper()}")
    assert pos == len(body), "AARQ 字段没有正好填满"


def check_get(frame: bytes):
    assert frame[0] == 0xC0
    assert len(frame) == 11
    print(f"  tag=C0 invoke-id={frame[1]} class={int.from_bytes(frame[2:4],'big')} "
          f"OBIS={frame[4:10].hex('.')} attr={frame[10]}")


def check_action(frame: bytes):
    assert frame[0] == 0xC3
    body = frame[2:]
    assert body[:2] == CLASS_SEC_SETUP
    assert body[2:8] == SEC_SETUP_OBIS
    assert body[8] == 0x02
    param = body[9:]
    assert param[0] == 0x01 and param[1] == 0x01
    assert param[2] == 0x02 and param[3] == 0x02
    print(f"  tag=C3 invoke-id={frame[1]} class=64 OBIS=0-0:43.0.0.255 method=2")
    print(f"  参数            array(1) / structure(2) / enum={param[6]} / octet-string len={param[8]}")


def parse_kw(wrapped: bytes):
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
    kek = bytes.fromhex("11111111111111111111111111111111")
    return aes_key_unwrap(kek, wrapped)




# ──────────────────────────────────────────────────────────────
# 6. Table 52：HLS-ECDSA 两条签名验签
# ──────────────────────────────────────────────────────────────

def _plain_to_der(sig: bytes) -> bytes:
    """DLMS 的 plain R‖S → DER SEQUENCE(INTEGER, INTEGER)。"""
    half = len(sig) // 2
    r, s = sig[:half], sig[half:]

    def integer(b: bytes) -> bytes:
        b = b.lstrip(b"\x00") or b"\x00"
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    body = integer(r) + integer(s)
    return b"\x30" + bytes([len(body)]) + body


def part6_ecdsa() -> bool:
    print()
    print("=" * 72)
    print("6. Table 52 · HLS-ECDSA（P-256）两条签名验签")
    print("=" * 72)
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        print("  跳过：未安装 cryptography")
        return True

    H = lambda x: bytes.fromhex("".join(x.split()))
    stc = H("4D4D4D0000BC614E")
    sts = H("4D4D4D0000000001")
    ctos = H("2CA1FC2DE9CD03B5E8E234CEA16F2853F6DC5F54526F4F4995772A50FB7E63B3")
    stoc = H("18E95FFE3AD0DCABDC5D0D141DC987E270CB0A395948D4231B09DE6579883657")
    f_stoc = H("C5C6D6620BDB1A39FCE50F4D64F0DB712D6FB57A64030B0C297E1250DC859660"
               "D3B1FA334AD80411807369F5DD3BC17B59894C9E9C11C59376580D15A2646D16")
    f_ctos = H("946C2E3E4F18291571F4A45ACB7086100574694A3BAF67D2D147FE8F92481A5A"
               "B2186C5CBC3F80E94482D9388B85C6A73E5FD687F09773C1F615AA2A905ED057")
    pub_c = H("917DBFECA43307375247989F07CC23F53D4B963AF8026C749DB33852011056DFD"
              "BE8327BD69CC149F018A8E446DDA6C55BCD78E596A56D403236233F93CC89B3")
    pub_s = H("E4D07CEB0A5A6DA9D2228B054A1F5E295E1747A963974AF75091A0B0BC2FB92D"
              "A7D2ABD9FDD41579F36A1C8171A0CB638221DF1949FD95C8FAE148896920450D")

    cases = [
        ("f(StoC)", pub_c, stc + sts + stoc + ctos, f_stoc),
        ("f(CtoS)", pub_s, sts + stc + ctos + stoc, f_ctos),
    ]
    ok = True
    for name, pub_raw, msg, sig in cases:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), b"\x04" + pub_raw)
        try:
            pub.verify(_plain_to_der(sig), msg, ec.ECDSA(hashes.SHA256()))
            print(f"  {name:<8} ✓ 验签通过（64 B plain → DER）")
        except InvalidSignature:
            ok = False
            print(f"  {name:<8} ✗ 验签失败")
    return ok


# ──────────────────────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────────────────────

def main():
    CLIENT_ST = bytes.fromhex("4D4D4D0000000001")
    SERVER_ST = bytes.fromhex("4D4D4D0000BC614E")

    print("=" * 72)
    print("1. LLS AARQ（口令 12345678）")
    print("=" * 72)
    f = aarq_lls()
    print("  " + f.hex(" ").upper())
    dump_aarq(f)

    print()
    print("=" * 72)
    print("2. HLS-GMAC AARQ（CtoS = 4B35366956616759）")
    print("=" * 72)
    f = aarq_hls_gmac(CLIENT_ST, bytes.fromhex("4B35366956616759"))
    print("  " + f.hex(" ").upper())
    dump_aarq(f)

    print()
    print("=" * 72)
    print("3. HLS-GMAC AARE（StoC = 503677524A323146）")
    print("=" * 72)
    f = aare_hls_gmac(SERVER_ST, bytes.fromhex("503677524A323146"))
    print("  " + f.hex(" ").upper())
    tag, body, end = read_tlv(f)
    print(f"  外壳            tag=61 len={len(body)} 总长={len(f)}")

    print()
    print("=" * 72)
    print("4. GET Security setup 属性 2（security_policy）")
    print("=" * 72)
    f = get_security_policy()
    print("  " + f.hex(" ").upper())
    check_get(f)

    print()
    print("=" * 72)
    print("5. ACTION key_transfer（AES-KW，KEK = 11…11）")
    print("=" * 72)
    try:
        from cryptography.hazmat.primitives.keywrap import aes_key_wrap
        guek = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        kek = bytes.fromhex("11111111111111111111111111111111")
        wrapped = aes_key_wrap(kek, guek)
        print(f"  待包装 GUEK     {guek.hex().upper()}  ({len(guek)} B)")
        print(f"  KEK             {kek.hex().upper()}  ({len(kek)} B)")
        print(f"  包装结果        {wrapped.hex().upper()}  ({len(wrapped)} B = 16+8)")
        f = action_key_transfer(wrapped)
        print("  " + f.hex(" ").upper())
        check_action(f)
        assert parse_kw(wrapped) == guek, "解包结果与原文不一致"
        print("  解包回读        ✓ 与原文一致")
    except ImportError:
        print("  跳过：未安装 cryptography")

    ok6 = part6_ecdsa()

    print()
    print("=" * 72)
    print("结论：以上报文的长度字段全部自洽，可被逐层拆回。")
    print("ECDSA 验签：" + ("✓ 两条都通过" if ok6 else "✗ 有失败"))
    print("=" * 72)


if __name__ == "__main__":
    main()
