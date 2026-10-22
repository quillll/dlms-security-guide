/* ============================================================
   DLMS 安全算法工作台 · CRC / FCS
   包含 DLMS HDLC 使用的 CRC-16/X.25（FCS-16）。
   ============================================================ */
(function (global) {
  "use strict";

  var DLMS = global.DLMS = global.DLMS || {};

  var CRC16 = {
    "X25": { name: "CRC-16/X.25（HDLC FCS）", poly: 0x1021, init: 0xFFFF, refin: true, refout: true, xorout: 0xFFFF, check: 0x906E },
    "CCITT-FALSE": { name: "CRC-16/CCITT-FALSE", poly: 0x1021, init: 0xFFFF, refin: false, refout: false, xorout: 0x0000, check: 0x29B1 },
    "ARC": { name: "CRC-16/ARC", poly: 0x8005, init: 0x0000, refin: true, refout: true, xorout: 0x0000, check: 0xBB3D },
    "MODBUS": { name: "CRC-16/MODBUS", poly: 0x8005, init: 0xFFFF, refin: true, refout: true, xorout: 0x0000, check: 0x4B37 }
  };

  var CRC32 = {
    "ISO-HDLC": { name: "CRC-32/ISO-HDLC", poly: 0x04C11DB7, init: 0xFFFFFFFF, refin: true, refout: true, xorout: 0xFFFFFFFF, check: 0xCBF43926 }
  };

  function reflect16(v) {
    var r = 0;
    for (var i = 0; i < 16; i++) {
      if (v & (1 << i)) r |= 1 << (15 - i);
    }
    return r & 0xFFFF;
  }

  function reflect32(v) {
    var r = 0;
    for (var i = 0; i < 32; i++) {
      if (v & (1 << i)) r |= 1 << (31 - i);
    }
    return r >>> 0;
  }

  function crc16(params, bytes) {
    var crc = params.init & 0xFFFF;
    var poly = params.refin ? reflect16(params.poly) : params.poly;
    for (var i = 0; i < bytes.length; i++) {
      if (params.refin) {
        crc ^= bytes[i];
        for (var j = 0; j < 8; j++) crc = (crc & 1) ? ((crc >>> 1) ^ poly) : (crc >>> 1);
      } else {
        crc ^= bytes[i] << 8;
        for (var k = 0; k < 8; k++) crc = (crc & 0x8000) ? (((crc << 1) ^ poly) & 0xFFFF) : ((crc << 1) & 0xFFFF);
      }
    }
    if (params.refout !== params.refin) crc = reflect16(crc);
    return (crc ^ params.xorout) & 0xFFFF;
  }

  function crc32(params, bytes) {
    var crc = params.init >>> 0;
    var poly = params.refin ? reflect32(params.poly) : params.poly;
    for (var i = 0; i < bytes.length; i++) {
      if (params.refin) {
        crc = (crc ^ bytes[i]) >>> 0;
        for (var j = 0; j < 8; j++) crc = (crc & 1) ? ((crc >>> 1) ^ poly) : (crc >>> 1);
      } else {
        crc = (crc ^ (bytes[i] << 24)) >>> 0;
        for (var k = 0; k < 8; k++) crc = (crc & 0x80000000) ? (((crc << 1) ^ poly) >>> 0) : ((crc << 1) >>> 0);
      }
    }
    if (params.refout !== params.refin) crc = reflect32(crc);
    return (crc ^ params.xorout) >>> 0;
  }

  function hdlcFcs(bytes) {
    var value = crc16(CRC16["X25"], bytes);
    return {
      value: value,
      hex: "0x" + value.toString(16).toUpperCase().padStart(4, "0"),
      bytesLE: new Uint8Array([value & 0xFF, (value >>> 8) & 0xFF]),
      bytesBE: new Uint8Array([(value >>> 8) & 0xFF, value & 0xFF])
    };
  }

  DLMS.CRC = {
    CRC16: CRC16,
    CRC32: CRC32,
    crc16: crc16,
    crc32: crc32,
    hdlcFcs: hdlcFcs
  };

  if (typeof module !== "undefined" && module.exports) module.exports = DLMS.CRC;
})(typeof globalThis !== "undefined" ? globalThis : this);
