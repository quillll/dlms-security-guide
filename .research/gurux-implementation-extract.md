# Gurux DLMS/COSEM implementation extract — security suites 0/1/2 and their cryptographic protection

**Method / provenance.** Everything below is quoted from the local source trees. Paths are relative to
`D:\project\personal\dlms\`, with these shorthands:

| Shorthand | Real location |
|---|---|
| `NET/` | `Gurux.DLMS.Net/Development/` (C# library) |
| `NET-EX-C/` | `Gurux.DLMS.Net/Gurux.DLMS.Client.Example.Net/` |
| `NET-EX-S/` | `Gurux.DLMS.Net/Gurux.DLMS.Server.Example.Net/Gurux.DLMS.Server.Example/` |
| `JAVA/` | `gurux.dlms.java-master/development/src/main/java/gurux/dlms/` |
| `JAVA-EX/` | `gurux.dlms.java-master/gurux.dlms.client.example.java/src/gurux/dlms/client/` |
| `C/` | `GuruxDLMS.c/development/` |
| `C-EX/` | `GuruxDLMS.c/` (example applications) |

All line numbers are file line numbers in those files.

**Tooling note (affects reproducibility):** `NET/Secure/GXSecure.cs` is **not valid UTF-8** (one non-ASCII
byte exists in the file), so a UTF-8 reader fails on it; it was scanned as Windows-1252. Other files read
fine as UTF-8. This is itself a small gotcha for tooling around this tree.

**Where the code does not answer the question**, the text says *"not found in the code"*.

---

## 1. The security-suite type, and the security-policy type

### 1.1 `SecuritySuite` (C#)

`NET/Objects/Enums/SecuritySuite.cs:42-68` — an untyped enum, so the numeric values are the declaration
order **0, 1, 2** (confirmed by the `XmlEnum` strings):

```csharp
    public enum SecuritySuite
    {
        /// <summary>
        /// GMAC ciphering is used with security setup version 0.
        /// </summary>
        /// <remarks>
        /// A.K.A Security Suite 0.
        /// </remarks>
        [XmlEnum("0")]
        Suite0,
        /// <summary>
        /// ECDSA P-256 ciphering is used.
        /// </summary>
        /// <remarks>
        /// A.K.A Security Suite 1.
        /// </remarks>
        [XmlEnum("1")]
        Suite1,
        /// <summary>
        /// ECDSA P-384 ciphering is used.
        /// </summary>
        /// <remarks>
        /// A.K.A Security Suite 2.
        /// </remarks>
        [XmlEnum("2")]
        Suite2
    }
```

There is **no Suite3+** member anywhere in the C# enum. Members: `Suite0 = 0`, `Suite1 = 1`, `Suite2 = 2`.

### 1.2 `SecuritySuite` (Java)

`JAVA/objects/enums/SecuritySuite.java:40-71` — the value is the **ordinal**, exposed via `getValue()`:

```java
public enum SecuritySuite {
	/**
	 * GMAC ciphering is used.<br>
	 * AES-GCM-128 for authenticated encryption and AES-128 for key wrapping. <br>
	 * A.K.A Security Suite 0.
	 */
	SUITE_0,
	/**
	 * ECDSA P-256 ciphering is used. <br>
	 * ECDH-ECDSAAES-GCM-128SHA-256. <br>
	 * A.K.A Security Suite 1.
	 */
	SUITE_1,
	/**
	 * ECDSA P-384 ciphering is used.<br>
	 * ECDH-ECDSAAES-GCM-256SHA-384. <br>
	 * A.K.A Security Suite 2.
	 */
	SUITE_2;

	public int getValue() {
		return this.ordinal();
	}
```

Members: `SUITE_0 = 0`, `SUITE_1 = 1`, `SUITE_2 = 2`.

### 1.3 `SecuritySuite` (C variant, optional cross-check)

`C/include/enums.h:164-173`:

```c
        DLMS_SECURITY_SUITE_V0 = 0,
...
        DLMS_SECURITY_SUITE_V1 = 1,
...
        DLMS_SECURITY_SUITE_V2 = 2
    } DLMS_SECURITY_SUITE;
```

### 1.4 `SecurityPolicy` (C#) — `[Flags]`, byte-sized

`NET/Objects/Enums/SecurityPolicy.cs:43-117`. Every member with its numeric value and the XML value:

| Member | Value | XML | Code comment (verbatim, abbreviated) |
|---|---|---|---|
| `None` | `0` | `0` | "Security is not used." |
| `Authenticated` | `0x1` | `1` | "All messages are authenticated using Security Suite 0." |
| `Encrypted` | `0x2` | `2` | "All messages are encrypted using Security Suite 0." |
| `AuthenticatedEncrypted` | `0x3` | `3` | "All messages are authenticated and encrypted using Security Suite 0." |
| `AuthenticatedRequest` | `0x4` | `4` | "Request is authenticated." / "This is used in Security Suite 1." |
| `EncryptedRequest` | `0x8` | `8` | "Request is encrypted." |
| `DigitallySignedRequest` | `0x10` | `16` | "Request is digitally signed." |
| `AuthenticatedResponse` | `0x20` | `32` | "Response is authenticated." |
| `EncryptedResponse` | `0x40` | `64` | "Response is encrypted." |
| `DigitallySignedResponse` | `0x80` | `128` | "Response is digitally signed." |

```csharp
    [Flags]
    public enum SecurityPolicy : byte
    {
        /// <summary>
        /// Security is not used.
        /// </summary>
        [XmlEnum("0")]
        None = 0,
        /// <summary>
        /// All messages are authenticated using Security Suite 0.
        /// </summary>
        [XmlEnum("1")]
        Authenticated = 0x1,
        /// <summary>
        /// All messages are encrypted using Security Suite 0.
        /// </summary>
        [XmlEnum("2")]
        Encrypted = 0x2,
        /// <summary>
        /// All messages are authenticated and encrypted using Security Suite 0.
        /// </summary>
        [XmlEnum("3")]
        AuthenticatedEncrypted = 0x3,
        /// <summary>
        /// Request is authenticated.
        /// </summary>
        /// <remarks>
        /// This is used in Security Suite 1.
        /// </remarks>
        [XmlEnum("4")]
        AuthenticatedRequest = 0x4,
```

How the bits are actually used in code:

* Version-0 policy restrictions — `NET/Objects/GXDLMSSecuritySetup.cs:208-227`:
```csharp
                if (Version == 0)
                {
                    switch (value)
                    {
                        case SecurityPolicy.None:
                        case SecurityPolicy.Authenticated:
                        case SecurityPolicy.Encrypted:
                        case SecurityPolicy.AuthenticatedEncrypted:
                            break;
                        default:
                            throw new Exception(string.Format("Invalid security policy value {0} for Version 0.", value));
                    }
                }
                else if (Version == 1)
                {
                    if (((Convert.ToByte(value)) & 0x3) != 0)
                    {
                        throw new Exception(string.Format("Invalid security policy value {0} for version 1.", value));
                    }
                }
```
* The only functional bit test in the whole C# library — `NET/Secure/GXSecure.cs:773`:
```csharp
                        if ((p.Settings.Cipher.SecurityPolicy & (SecurityPolicy.EncryptedRequest | SecurityPolicy.AuthenticatedRequest)) != 0)
```
  (a server rejects an unsigned `general-signing` request when policy demands authenticated/encrypted requests).
* Reset to `None` when the association changes: `NET/GXDLMSSettings.cs:1059` `Cipher.SecurityPolicy = SecurityPolicy.None;`.
* Written by the Security-setup `activate` method: `NET/Objects/GXDLMSSecuritySetup.cs:804-805` `case 1: SecurityPolicy = (SecurityPolicy)Convert.ToByte(e.Parameters);`.

### 1.5 `SecurityPolicy` (Java) — a `Set<SecurityPolicy>`, **different member set**

`JAVA/objects/enums/SecurityPolicy.java:45-83`:

```java
public enum SecurityPolicy {
    AUTHENTICATED(1),
    ENCRYPTED(2),
    AUTHENTICATED_REQUEST(0x4),
    ENCRYPTED_REQUEST(0x8),
    DIGITALLY_SIGNED_REQUEST(0x10),
    AUTHENTICATED_RESPONSE(0x20),
    ENCRYPTED_RESPONSE(0x40),
    DIGITALLY_SIGNED_RESPONSE(0x80);
```

**Gotcha:** the Java enum has **no `NONE` and no `AUTHENTICATED_ENCRYPTED (3)`** member, and it is a
`Set` with `forValue(int)` testing `(enums[pos].intValue & value) == enums[pos].intValue`
(`SecurityPolicy.java:149-159`). So `3` decodes to `{AUTHENTICATED, ENCRYPTED}` in Java but is a single
member in C#.

---

## 2. Security-level enum and the suite + level → algorithm mapping

### 2.1 Security level (C#)

`NET/Enums/Security.cs:40-58`:

```csharp
    public enum Security
    {
        /// <summary>
        /// Transport security is not used.
        /// </summary>
        None = 0,
        /// <summary>
        /// Authentication security is used.
        /// </summary>
        Authentication = 0x10,
        /// <summary>
        /// Encryption security is used.
        /// </summary>
        Encryption = 0x20,
        /// <summary>
        /// Authentication and Encryption security are used.
        /// </summary>
        AuthenticationEncryption = 0x30,
    }
```

Note the member name is `AuthenticationEncryption` (not `AuthenticationEncrypted`), and the values are
the **wire security-control bits**, not 0/1/2.

### 2.2 Security level (Java)

`JAVA/enums/Security.java:40-59`: `NONE(0)`, `AUTHENTICATION(0x10)`, `ENCRYPTION(0x20)`,
`AUTHENTICATION_ENCRYPTION(0x30)` — identical values.

### 2.3 Mapping suite + level to algorithms — the central switch

`NET/GXDLMS.cs:939-999` (`Cipher1`, the suite-1/2 writer) builds the security-control byte and the KDF
algorithm id:

```csharp
            switch (c.Security)
            {
                case Security.Authentication:
                    sc = 0x10;
                    break;
                case Security.AuthenticationEncryption:
                    sc = 0x30;
                    break;
                case Security.Encryption:
                    sc = 0x20;
                    break;
                default:
                    if (c.Signing != Signing.GeneralSigning)
                    {
                        throw new ArgumentOutOfRangeException("Invalid security.");
                    }
                    break;
            }
            AlgorithmId algorithmID;
            switch (c.SecuritySuite)
            {
                case SecuritySuite.Suite1:
                    algorithmID = AlgorithmId.AesGcm128;
                    sc |= 1;
                    break;
                case SecuritySuite.Suite2:
                    algorithmID = AlgorithmId.AesGcm256;
                    sc |= 2;
                    break;
                default:
                    throw new ArgumentOutOfRangeException("Invalid security suite.");
            }
```

So in suite 1/2 the **low nibble of the security-control byte is the suite number** and the high nibble is
the security level.

`NET/Ecdsa/Enums/AlgorithmId.cs:40-58` gives the algorithm-id values used in the KDF otherInfo
(declaration order = 0..3): `AesGcm128 = 0`, `AesGcm256 = 1`, `AesWrap128 = 2`, `AesWrap256 = 3`.

Algorithm selection by suite (C#):

| Concern | Suite 0 | Suite 1 | Suite 2 | Evidence |
|---|---|---|---|---|
| AES-GCM data key | AK/block key as configured (16 B) | KDF 16 B (AES-GCM-128) | KDF first 16 B (AES-GCM-256 expected) | `NET/GXDLMS.cs:1115-1123`, `NET/Secure/GXSecure.cs:855`, `:874` |
| KDF hash | n/a (`GenerateKDF` throws) | SHA-256 | SHA-384 | `NET/Secure/GXSecure.cs:292-309` |
| ECC curve | (P-384 fallback in the ternary) | P-256 | P-384 | `NET/GXDLMS.cs:1038`, `NET/Objects/GXDLMSSecuritySetup.cs:783-790` |
| Signing signature size accepted | — | 64 B | 96 B | `NET/Secure/GXSecure.cs:1001` |
| Signing space reserved | — | 65 B | 99 B | `NET/GXDLMS.cs:1265-1281` |
| AES key length used by the GCM engine | from key material | 128 | 256 | `C/src/ciphering.c:463` |

`NET/GXDLMS.cs:1265-1281`:

```csharp
            if (p.settings.Cipher != null && p.settings.Cipher.Signing == Signing.GeneralSigning)
            {
                if (p.settings.Cipher.SecuritySuite == SecuritySuite.Suite1)
                {
                    size = 65;
                }
                else if (p.settings.Cipher.SecuritySuite == SecuritySuite.Suite2)
                {
                    size = 99;
                }
            }
```

Level → which cipher is used is decided inside the GCM wrapper (`NET/Secure/GXGMac.cs:246-274`, quoted in
§4) and inside the HSM switch `NET/Secure/GXSecure.cs:404-417`:

```csharp
                switch (param.Security)
                {
                    case Security.Authentication:
                        keyType = CryptoKeyType.Authentication;
                        break;
                    case Security.Encryption:
                        keyType = CryptoKeyType.BlockCipher;
                        break;
                    case Security.AuthenticationEncryption:
                        keyType = CryptoKeyType.Authentication | CryptoKeyType.BlockCipher;
                        break;
```

Finally, the level is also mapped to the small integers 0..3 for the Security-setup `activate` argument —
`NET/Objects/GXDLMSSecuritySetup.cs:284-305`:

```csharp
                case Security.None:
                    value = 0;
                    break;
                case Security.Authentication:
                    value = 1;
                    break;
                case Security.Encryption:
                    value = 2;
                    break;
                case Security.AuthenticationEncryption:
                    value = 3;
                    break;
```

---

## 3. The ciphering implementation: IV/nonce, AAD, tag length, counter handling

### 3.1 Entry point and full APDU byte layout (C#)

`NET/Secure/GXSecure.cs:379-501` (`EncryptAesGcm`). Security-control byte construction and the GCM call:

```csharp
        static public byte[] EncryptAesGcm(AesGcmParameter param, byte[] plainText)
        {
            System.Diagnostics.Debug.WriteLine("Encrypt settings: " + param.ToString());
            byte tag;
            param.CountTag = null;
            GXByteBuffer data = new GXByteBuffer();
            tag = (byte)((byte)param.Security | (byte)param.SecuritySuite);
            if (param.Broacast)
            {
                tag |= 0x40;
            }
            if (param.Compression)
            {
                tag |= 0x80;
            }
            if (param.Type == CountType.Packet)
            {
                data.SetUInt8(tag);
            }
```

(the invocation counter follows as a big-endian UInt32 — see the `tmp`/`data.Set(tmp)` lines below.)

```csharp
            GXGMac gmac = new GXGMac(param.AuthenticationKey, param.BlockCipherKey, param.SystemTitle, (UInt32)param.InvocationCounter);
            ciphertext = gmac.Encrypt(plainText, tag);
```

and the frame wrapper (`NET/Secure/GXSecure.cs:476-497`):

```csharp
            if (param.Type == CountType.Packet)
            {
                GXByteBuffer tmp2 = new GXByteBuffer((ushort)(10 + data.Size));
                tmp2.SetUInt8(param.Tag);
                if (param.Tag == (int)Command.GeneralGloCiphering ||
                    param.Tag == (int)Command.GeneralDedCiphering ||
                    param.Tag == (int)Command.DataNotification)
                {
                    if (!param.IgnoreSystemTitle)
                    {
                        GXCommon.SetObjectCount(param.SystemTitle.Length, tmp2);
                        tmp2.Set(param.SystemTitle);
                    }
                    else
                    {
                        tmp2.SetUInt8(0);
                    }
                }
                GXCommon.SetObjectCount(data.Size, tmp2);
                tmp2.Set(data.Array());
                return tmp2.Array();
            }
```

Resulting **general-glo-ciphering** APDU (verified against the wrapper plus the level branches):

```
[ cmd=GeneralGloCiphering ][ len=8 ][ system title (8) ][ len=N ][ SC | IC(4, big endian) | payload | tag(12) ]
```

and for the legacy `glo-*` messages / `glo-initiate-request` the system title is omitted, so:
`[ cmd ][ len=N ][ SC | IC(4) | payload | tag(12) ]`. `N` = 1 + 4 + payloadlength (+ 12 for
authentication/`AE`). The count/level branches are `NET/Secure/GXSecure.cs:433-471`:

```csharp
            if (param.Security == Security.Authentication)
            {
                if (param.Type == CountType.Packet)
                {
                    data.Set(tmp);
                    param.CountTag = ciphertext;
                }
                if ((param.Type & CountType.Data) != 0)
                {
                    data.Set(plainText);
                }
                if ((param.Type & CountType.Tag) != 0)
                {
                    data.Set(ciphertext);
                }
            }
            else if (param.Security == Security.Encryption)
            {
                if (param.Type == CountType.Packet)
                {
                    data.Set(tmp);
                }
                data.Set(ciphertext);
            }
            else if (param.Security == Security.AuthenticationEncryption)
            {
                if (param.Type == CountType.Packet)
                {
                    data.Set(tmp);
                }
                if ((param.Type & CountType.Data) != 0)
                {
                    data.Set(ciphertext);
                }
                if ((param.Type & CountType.Tag) != 0)
                {
                    data.Set(param.CountTag);
                }
            }
```

with `NET/Secure/CountType.cs:37-45`:

```csharp
    enum CountType
    {
        /// <summary>
        /// Count packet.
        /// </summary>
        Packet = -1,
        Tag = 0x1,
        Data = 0x2
    }
```

`Packet = -1` is deliberate: `(-1 & CountType.Data) != 0` and `(-1 & CountType.Tag) != 0` are both true, so
`Type == Packet` means "SC + IC + everything". And `data.Set(null)` is a no-op
(`NET/GXByteBuffer.cs:866-872` `if (value != null)`), which is what makes the `AE`+`Packet` branch's
`data.Set(param.CountTag)` (CountTag is `null` for AE) harmless.

### 3.2 IV / nonce construction (C#)

`NET/Secure/GXGCMCryptoTransform.cs:62-96`:

```csharp
        public GXGCMCryptoTransform(
            SymmetricAlgorithm symmetricAlgorithm,
            byte[] cipherKey, byte[] nonce,
            UInt32 counter,
            UInt32 algorithmInitialblockCounter)
        {
            ...
            _algorithmInitialblockCounter = algorithmInitialblockCounter;
            _symmetricAlgorithm = symmetricAlgorithm;
            _nonceAndCounter = new byte[16];
            GXByteBuffer bb = new GXByteBuffer();
            bb.Set(nonce);
            if (nonce.Length > 8)
            {
                //If system title is too long.
                bb.Size -= 8 - nonce.Length;
            }
            else if (nonce.Length < 8)
            {
                //If system title is too small.
                bb.Size -= nonce.Length - 8;
            }
            bb.SetUInt32(counter);
            bb.SetUInt32(_algorithmInitialblockCounter);
            bb.Get(_nonceAndCounter);
            var zeroIv = new byte[_symmetricAlgorithm.BlockSize / 8];
            _counterEncryptor = symmetricAlgorithm.CreateEncryptor(cipherKey, zeroIv);
        }
```

So for the normal case (an 8-byte system title) the 16-byte GCM counter block is, byte for byte:

```
[ system title, 8 bytes ][ invocation counter, 4 bytes big endian ][ block counter, 4 bytes big endian ]
```

The `Size` arithmetic in lines 81-90 is worth reading twice, because `SetUInt32(value)` always writes at
`Size` and then does `Size += 4` (`NET/GXByteBuffer.cs:398-402`):

* title **shorter** than 8 → `bb.Size -= nonce.Length - 8` pads `Size` up to 8, so the counters land at
  offsets 8 and 12 and the block is the title zero-extended to 8 bytes (bytes `len..7` are whatever the
  fresh buffer holds, i.e. zeros);
* title **longer** than 8 → `bb.Size -= 8 - nonce.Length` grows `Size` past the title, so the two counters are
  written *after* the title and the final `bb.Get(_nonceAndCounter)` copies the **first 16 bytes of the title**
  — the invocation counter and block counter are dropped from the nonce entirely.

In practice this is masked because the rest of the library validates system titles to 8 bytes
(`NET/Secure/GXDLMSSecureClient.cs:157-164` `if (value != null && value.Length != 8) throw new
ArgumentOutOfRangeException("Invalid System Title.");`, `NET/Secure/GXSecure.cs:549-559`
`if (p.SystemTitle == null || p.SystemTitle.Length != 8)`).

The block counter is only ever written at offset 12 (`NET/Secure/GXGCMCryptoTransform.cs:125-133`):

```csharp
        private void IncreaseBlockCounter()
        {
            ++_algorithmInitialblockCounter;
            GXByteBuffer bb = new GXByteBuffer();
            bb.Capacity = 16;
            bb.Set(_nonceAndCounter);
            bb.SetUInt32(12, _algorithmInitialblockCounter);
            bb.Get(_nonceAndCounter);
        }
```

— i.e. incrementing the block counter **never carries into the invocation counter** (no `inc32` carry
propagation), and the counter block is never re-read from `_nonceAndCounter` before the IC is written; the
IV bytes are `ST || IC || blockcounter`.

The three initial block-counter values are chosen in `NET/Secure/GXGMac.cs:50-70`:

```csharp
        public GXGMac(
            byte[] authenticationKey,
            byte[] cipherKey,
            byte[] nonce,
            UInt32 counter)
        {
            _authenticationKey = authenticationKey;
            _aes = Aes.Create();
            _aes.Mode = CipherMode.ECB;
            _aes.Padding = PaddingMode.None;
            _encrypt = new GXGCMCryptoTransform(_aes, cipherKey, nonce, counter, 2);
            if (_authenticationKey != null)
            {
                _authentication = new GXGCMCryptoTransform(_aes, cipherKey, nonce, counter, 1);
                using (var tmp = new GXGCMCryptoTransform(_aes, cipherKey, new byte[12], 0, 0))
                {
                    _H = new byte[16];
                    tmp.TransformBlock(new byte[16], 0, 16, _H, 0);
                }
            }
        }
```

* `_encrypt` — CTR keystream, starts at counter block **2** (J0+1, the GCM data counter).
* `_authentication` — one block encrypt at counter block **1** (J0, used to mask GHASH).
* `H` — computed with a nonce of 12 zero bytes and initial block counter **0** (i.e. `E_K(0^128)`).

Java does the same thing by delegating to the JCE (`JAVA/secure/GXSecure.java:529-544`):

```java
    private static Cipher getCipher(final AesGcmParameter p, final boolean encrypt) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        GXByteBuffer iv = new GXByteBuffer();
        iv.set(p.getSystemTitle());
        iv.setUInt32(p.getInvocationCounter());
        SecretKeySpec eks = new SecretKeySpec(p.getBlockCipherKey(), "AES");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        int mode;
        if (encrypt) {
            mode = Cipher.ENCRYPT_MODE;
        } else {
            mode = Cipher.DECRYPT_MODE;
        }
        c.init(mode, eks, new GCMParameterSpec(12 * 8, iv.array()));
        return c;
    }
```

Java's IV is exactly `systemTitle || invocationCounter` (12 bytes) and `GCMParameterSpec(12 * 8, …)` also
pins the tag to **96 bits**.

The C variant builds the same 16-byte block (`C/src/ciphering.c:86-100`):

```c
    bb_attach(&nonceAndCounter, NONSE, 0, 16);
    bb_set(&nonceAndCounter, systemTitle, 8);
    bb_setUInt32(&nonceAndCounter, counter);
    bb_setUInt32(&nonceAndCounter, algorithmInitialblockCounter);
```

and `C/src/ciphering.c:79-84` shows the C counter handling writes only the last 4 bytes:

```c
static void gxgcm_increaseBlockCounter(gxByteBuffer* nonceAndCounter,
    uint32_t counter)
{
    nonceAndCounter->size = 12;
    bb_setUInt32(nonceAndCounter, counter);
}
```

### 3.3 AAD construction (C#), with the exact byte layout

`NET/Secure/GXGMac.cs:192-239`:

```csharp
        byte[] GetTag(byte tag, byte[] plainText, byte[] cipheredData)
        {
            byte[] zero = new byte[16];
            GXByteBuffer bb = new GXByteBuffer();
            //Length of the crypted data.
            double lenC = cipheredData != null ? 8 * cipheredData.Length : 0;
            //Length of the authenticated data.
            double lenA = (1 + _authenticationKey.Length) * 8;
            if (cipheredData == null)
            {
                //If data is not ciphered.
                lenA += 8 * plainText.Length;
            }
            int v = (int)(128 * Math.Ceiling(lenA / 128) - lenA);
            int u = (int)(128 * Math.Ceiling(lenC / 128) - lenC);
            bb.SetUInt8(tag);
            bb.Set(_authenticationKey, 0, _authenticationKey.Length);
            if (cipheredData == null)
            {
                bb.Set(plainText, 0, plainText.Length);
            }
            //Fill with zeroes.
            bb.Set(zero, 0, v / 8);
            //Write Ciphered data.
            if (cipheredData != null)
            {
                bb.Set(cipheredData, 0, cipheredData.Length);
                //Fill with zeroes.
                bb.Set(zero, 0, u / 8);
            }
            //Write length of the autheticated data in bits.
            bb.SetUInt64((UInt32)lenA);
            //Write length of the crypted data.
            bb.SetUInt64((UInt32)lenC);
            byte[] tmp = GetGHash(bb.Array());
            var auth = new byte[tmp.Length];
            _authentication.TransformBlock(tmp, 0, tmp.Length, auth, 0);
            tmp = new byte[12];
            Array.Copy(auth, tmp, 12);
            return tmp;
        }
```

The DLMS-specific parts a reader of the spec would look for:

* the **first AAD byte is the security-control byte** (`tag`), low nibble = suite, high nibble = level,
  plus `0x40` broadcast / `0x80` compression which the caller already folded in (`NET/Secure/GXSecure.cs:385-393`);
* the **authentication key AK itself is the second AAD field** — i.e. the AK is authenticated, not secret,
  in DLMS GCM;
* for the ciphered case the AAD never contains the plaintext; for authentication-only it contains the
  plaintext (`plainText`) and `lenC = 0`;
* `lenA`/`lenC` are written as 64-bit big-endian **bit** counts (`SetUInt64((UInt32)…)` — the upper 32 bits
  are always zero), and the explicit `v`/`u` zero-fill plus GHASH's own zero-fill of the trailing partial
  block is the standard GCM `pad(A) || pad(C) || [len(A)]64 || [len(C)]64` construction.

Java expresses the same AAD through JCE (`JAVA/secure/GXSecure.java:546-560`):

```java
    private static byte[] countTag(final Cipher c, final AesGcmParameter p, final byte[] data)
            throws IllegalBlockSizeException, BadPaddingException {
        GXByteBuffer data2 = new GXByteBuffer();
        data2.setUInt8(p.getSecurity().getValue() | p.getSecuritySuite().getValue());
        data2.set(p.getAuthenticationKey());
        if (data != null) {
            data2.set(data);
        }
        c.updateAAD(data2.array());
        byte[] tmp = c.doFinal();
        // DLMS Tag is only 12 bytes.
        byte[] tag = new byte[12];
        System.arraycopy(tmp, 0, tag, 0, 12);
        return tag;
    }
```

and for the AE decrypt path (`JAVA/secure/GXSecure.java:670-681`):

```java
            GXByteBuffer data2 = new GXByteBuffer();
            int tag = p.getSecurity().getValue() | p.getSecuritySuite().getValue();
            if (p.isCompressed()) {
                tag |= 0x80;
            }
            if (p.isBroadcasted()) {
                tag |= 0x40;
            }
            data2.setUInt8(tag);
            data2.set(p.getAuthenticationKey());
            c.updateAAD(data2.array());
            return c.doFinal(data);
```

C# decrypt re-derives the same AAD security-control byte from the parsed `sc` (`NET/Secure/GXSecure.cs:976-985`):

```csharp
                byte tag2 = (byte)((byte)p.Security | (byte)p.SecuritySuite);
                if (p.Broacast)
                {
                    tag2 |= 0x40;
                }
                if (p.Compression)
                {
                    tag2 |= 0x80;
                }
                decrypted = gmac.Decrypt(tmp2, tag2, p.Xml);
```

### 3.4 Tag length actually used

* **Always 12 bytes (96 bits)**, for every level and suite. Encryption tag: `Array.Copy(auth, tmp, 12)`
  (`NET/Secure/GXGMac.cs:236-238`); authentication-only tag: same `GetTag` path.
* Decrypt always reads exactly 12: `byte[] tag = new byte[12]` (`NET/Secure/GXSecure.cs:942`),
  `Array.Copy(data, len, readTag, 0, 12)` (`NET/Secure/GXGMac.cs:296-297`),
  `for (int pos = 0; pos != 12; ++pos)` in `TagsEquals` (`NET/Secure/GXGMac.cs:509-519`).
* Java: `GCMParameterSpec(12 * 8, …)` plus explicit truncation to 12.
* C: `ret = bb_set(aTag, &hash[0], 12);` (`C/src/ciphering.c:328`).
* Signature sizes are a *different* number (64/96, §8) — do not confuse them.

### 3.5 Counter increment and validation (C#)

Increment on send — the library increments after producing the frame:

* `NET/GXDLMS.cs:904-906`:
```csharp
            byte[] ret = GXCiphering.Encrypt(c, data);
            ++p.settings.Cipher.InvocationCounter;
            return ret;
```
* `NET/GXDLMS.cs:1243` (suite 1/2 `Cipher1`): `++p.settings.Cipher.InvocationCounter;`
* `NET/GXDLMS.cs:1975`: `++cipher.InvocationCounter;`
* `NET/Internal/GXAPDU.cs:293-294` (Glo-initiate-request inside AARQ): `++cipher.InvocationCounter;`
* conditional increment for GMAC authentication (`NET/Internal/GXAPDU.cs:1721-1725`):
```csharp
                byte[] tmp = GXCiphering.Encrypt(p, data.Array());
                if (settings.IncreaseInvocationCounterForGMacAuthentication)
                {
                    ++cipher.InvocationCounter;
                }
```
  The flag **defaults to `true`** — `NET/GXDLMSSettings.cs:241-249`:
```csharp
        /// <summary>
        /// Some meters expect that invocation counter is not increased 
        /// for the authentication when connection is established.
        /// </summary>
        public bool IncreaseInvocationCounterForGMacAuthentication
        {
            get;
            set;
        } = true;
```
  It is also exposed on the client and server (`NET/GXDLMSClient.cs:477-486`,
  `NET/GXDLMSServer.cs:714-723`).

Validation on receive, three independent places:

1. Against the meter's invocation-counter object — `NET/Secure/GXSecure.cs:881-896`:
```csharp
            UInt32 invocationCounter = 0;
            if (p.Security != Security.None)
            {
                invocationCounter = data.GetUInt32();
            }
            if (p.Settings != null && p.Settings.InvocationCounter != null)
            {
                if (invocationCounter < Convert.ToUInt32(p.Settings.InvocationCounter.Value))
                {
                    throw new GXDLMSExceptionResponse(ExceptionStateError.ServiceNotAllowed,
                            ExceptionServiceError.InvocationCounterError, p.Settings.InvocationCounter.Value);
                }
                // Update IC value.
                p.Settings.InvocationCounter.Value = invocationCounter;
            }
            p.InvocationCounter = invocationCounter;
```
2. Inside AARQ/AARE user-information parsing — `NET/Internal/GXAPDU.cs:726-733`:
```csharp
                if (p.Xml == null && settings.ExpectedInvocationCounter != 0)
                {
                    if (p.InvocationCounter < settings.ExpectedInvocationCounter)
                    {
                        return ExceptionServiceError.InvocationCounterError;
                    }
                    settings.ExpectedInvocationCounter = 1 + p.InvocationCounter;
                }
```
   Note this one advances the expectation to **IC + 1** while `GXSecure.cs:894` stores the received IC as-is.
3. On general-glo/ded decryption in `GetPdu` — `NET/GXDLMS.cs:5707-5714`:
```csharp
                        if (settings.ExpectedInvocationCounter != 0)
                        {
                            if (p.InvocationCounter < settings.ExpectedInvocationCounter)
                            {
                                throw new GXDLMSCipherException(string.Format("Data is ciphered using invalid invocation counter value. Actual: {0}. Expected: {1}", p.InvocationCounter, settings.ExpectedInvocationCounter));
                            }
                            settings.ExpectedInvocationCounter = p.InvocationCounter;
                        }
```

The server answers an IC error with the expected value in the exception reply
(`NET/GXDLMSServer.cs:1795-1797`, `:1894-1896`: `replyData.SetUInt32((UInt32)Settings.ExpectedInvocationCounter);`),
and the security suite of an incoming frame is **adopted / checked**:

```csharp
            p.SecuritySuite = (SecuritySuite)(sc & 0x3);
            if (p.Xml == null && p.SecuritySuite != p.Settings.Cipher.SecuritySuite)
            {
                //If client try to connect with wrong security suite version.
                throw new GXDLMSExceptionResponse(ExceptionStateError.ServiceNotAllowed,
                        ExceptionServiceError.DecipheringError, 0);
            }
            p.Security = (Security)(sc & 0x30);
```
(`NET/Secure/GXSecure.cs:788-796`), while `NET/GXDLMS.cs:5541` (`cipher.SecuritySuite = p.SecuritySuite;`)
adopts it silently on the general-glo/ded receive path without this check.

---

## 4. Authentication-only (GMAC) path vs the ciphering path

### 4.1 Tag production for `Security.Authentication`

`NET/Secure/GXGMac.cs:246-274` — the level decides whether the CTR keystream is applied at all:

```csharp
        public byte[] Encrypt(byte[] data, byte tag)
        {
            byte[] tmp;
            switch ((byte)(tag & 0x30))
            {
                case (byte)Security.Encryption:
                    {
                        tmp = new byte[data.Length];
                        _encrypt.TransformBlock(data, 0, data.Length, tmp, 0);
                    }
                    break;
                case (byte)Security.Authentication:
                    tmp = GetTag(tag, data, null);
                    break;
                case (byte)Security.AuthenticationEncryption:
                    byte[] encrypted = new byte[data.Length];
                    _encrypt.TransformBlock(data, 0, data.Length, encrypted, 0);
                    byte[] tmp2 = GetTag(tag, data, encrypted);
                    tmp = new byte[12 + data.Length];
                    //Add encrypted data.
                    Array.Copy(encrypted, tmp, data.Length);
                    //Add tag.
                    Array.Copy(tmp2, 0, tmp, data.Length, 12);
                    break;
                default:
                    throw new ArgumentException();
            }
            return tmp;
        }
```

Differences, precisely:

| | Authentication only | Authentication+Encryption |
|---|---|---|
| Returned bytes | 12 (tag only) | `data.Length + 12` (ciphertext ‖ tag) |
| `GetTag` AAD | `SC ‖ AK ‖ plaintext` (lenC = 0) | `SC ‖ AK ‖ ciphertext` (lenA excludes plaintext) |
| What goes on the wire | `SC ‖ IC ‖ plaintext ‖ tag` | `SC ‖ IC ‖ ciphertext ‖ tag` |
| `_encrypt` (counter block 2) used? | no | yes |
| `_authentication` (counter block 1) | yes | yes |

The caller distinguishes them at `NET/Secure/GXSecure.cs:433-471` (see §3.1): for
`Security.Authentication` it saves `param.CountTag = ciphertext` and appends the *plaintext*, then the tag;
`Security.Encryption` appends only the CTR result.

### 4.2 GMAC for HLS/HighGMAC authentication

`NET/Secure/GXSecure.cs:160-179` — challenge reply is `SC ‖ IC ‖ tag`:

```csharp
            else if (settings.Authentication == Authentication.HighGMAC)
            {
                //SC is always Security.Authentication.
                AesGcmParameter p = new AesGcmParameter(0,
                    settings,
                    Security.Authentication,
                    cipher.SecuritySuite,
                    ic,
                    secret,
                    cipher.BlockCipherKey,
                    cipher.AuthenticationKey);
                p.Type = CountType.Tag;
                challenge.Clear();
                //Security suite is 0.
                challenge.SetUInt8((byte)((int)Security.Authentication | (int)settings.Cipher.SecuritySuite));
                challenge.SetUInt32((UInt32)p.InvocationCounter);
                challenge.Set(GXSecure.EncryptAesGcm(p, tmp));
                tmp = challenge.Array();
                return tmp;
            }
```

Here `secret` is passed as the **system title** (used as the GCM nonce) — see `NET/GXDLMSClient.cs:1421-1425`
(`if (Settings.Authentication == Enums.Authentication.HighGMAC) { pw = Settings.Cipher.SystemTitle; }`) and
the equivalent on the responding side. Note `p.Type = CountType.Tag` means the SC and IC are **not** prepended
by `EncryptAesGcm` (only `Type == Packet` does that) — they are prepended manually here, which is why the
`Server/Client` challenge is `SC(0x10) ‖ IC(4) ‖ 12-byte tag`.

A second, independent GMAC helper exists on the ciphering object —
`NET/Secure/GXCiphering.cs:446-463`:

```csharp
        public byte[] GenerateGmacPassword(byte[] challenge)
        {
            AesGcmParameter p = new AesGcmParameter(0x10,
                null,
                Security.Authentication,
                SecuritySuite,
                InvocationCounter,
                systemTitle,
                BlockCipherKey,
                AuthenticationKey);
            p.Type = CountType.Tag;
            GXByteBuffer bb = new GXByteBuffer();
            byte[] data = GXSecure.EncryptAesGcm(p, challenge);
            bb.SetUInt8(0x10);
            bb.SetUInt32(InvocationCounter);
            bb.Set(data);
            return bb.Array();
        }
```
(`NET/Secure/GXCiphering.cs:446-463`; the whole body is quoted verbatim, including `bb.Set(data);` at line
461.)

### 4.3 Verifying an authentication-only frame

`NET/Secure/GXSecure.cs:942-965` — the `-5` is the SC byte plus the 4-byte IC:

```csharp
            byte[] tag = new byte[12];
            byte[] encryptedData;
            int length;
            if (p.Security == Security.Authentication)
            {
                length = len - 12 - 5;
                encryptedData = new byte[length];
                data.Get(encryptedData);
                data.Get(tag);
                // Check tag.
                EncryptAesGcm(p, encryptedData);
                if (!TagsEquals(tag, p.CountTag))
                {
                    if (p.Xml == null)
                    {
                        throw new GXDLMSCipherException("Decrypt failed. Invalid authentication tag.");
                    }
                    else
                    {
                        p.Xml.AppendComment("Decrypt failed. Invalid authentication tag.");
                    }
                }
                return encryptedData;
            }
```

and `TagsEquals` (`NET/Secure/GXGMac.cs:509-519`) compares 12 bytes with a **byte-by-byte early-exit loop**
(no constant-time comparison).

Note that `GXGMac.Decrypt` is *not* used for authentication-only; the early return above means the
CTR-keystream `TransformBlock` at `NET/Secure/GXGMac.cs:293` never sees an auth-only frame.

---

## 5. Key derivation (the DLMS KDF)

### 5.1 C# — `GenerateKDF`

`NET/Secure/GXSecure.cs:255-310` (two overloads). First overload builds `otherInfo`:

```csharp
        public static byte[] GenerateKDF(
                SecuritySuite securitySuite,
                byte[] z,
                AlgorithmId algorithmID,
                byte[] partyUInfo,
                byte[] partyVInfo,
                byte[] suppPubInfo,
                byte[] suppPrivInfo)
        {
            GXByteBuffer bb = new GXByteBuffer();
            bb.Set(new byte[] { 0x60, 0x85, 0x74, 0x05, 0x08, 0x03, (byte)algorithmID });
            bb.Set(partyUInfo);
            bb.Set(partyVInfo);
            if (suppPubInfo != null)
            {
                bb.Set(suppPubInfo);
            }
            if (suppPrivInfo != null)
            {
                bb.Set(suppPrivInfo);
            }
            return GenerateKDF(securitySuite, z, bb.Array());
        }
```

Second overload — counter **1** prepended, then `z`, then `otherInfo`, then one hash:

```csharp
        public static byte[] GenerateKDF(SecuritySuite securitySuite, byte[] z, byte[] otherInfo)
        {
            GXByteBuffer bb = new GXByteBuffer();
            bb.SetUInt32(1);
            bb.Set(z);
            bb.Set(otherInfo);
            if (securitySuite == SecuritySuite.Suite1)
            {
                using (SHA256 sha = new SHA256CryptoServiceProvider())
                {
                    return sha.ComputeHash(bb.Array());
                }
            }
            else if (securitySuite == SecuritySuite.Suite2)
            {
                using (SHA384 sha = new SHA384CryptoServiceProvider())
                {
                    return sha.ComputeHash(bb.Array());
                }
            }
            else
            {
                throw new ArgumentOutOfRangeException("Invalid security suite.");
            }
        }
```

Literal facts:

* the context/algorithm identifier is the **OID prefix `60 85 74 05 08 03` followed by one algorithm-id
  byte** (`0` = AES-GCM-128, `1` = AES-GCM-256, `2` = AES-WRAP-128, `3` = AES-WRAP-256 per
  `NET/Ecdsa/Enums/AlgorithmId.cs`), *not* an ASCII label;
* **`"ENC"` / `"AUT"` / `"MAC"` (or any other ASCII context string) is not found in the code** — a
  ripgrep for `"ENC"|"AUT"|"MAC"|"WRAP"` over `NET/` and `JAVA/` returns no matches, and over the whole
  `D:\project\personal\dlms` tree the only hit is the word "MAC" inside the Blue Book JSONL text, not code;
* derived sizes: suite 1 → SHA-256 → **32 bytes**; suite 2 → SHA-384 → **48 bytes**. There is **no
  key-length parameter** — callers slice with `SubArray(0, 16)`;
* the C# KDF computes **exactly one** hash block (the `SetUInt32(1)` counter is never advanced), which is
  sufficient only because all callers want ≤ 32 bytes (suite 1) / ≤ 48 bytes (suite 2) and then take 16.

### 5.2 Java — a general SP800-108-style counter-mode KDF

`JAVA/secure/GXSecure.java:383-448`:

```java
    public static byte[] generateKDF(final String hashAlg, final byte[] z, final int keyDataLen,
            final byte[] algorithmID, final byte[] partyUInfo, final byte[] partyVInfo, final byte[] suppPubInfo,
            final byte[] suppPrivInfo) {
        GXByteBuffer bb = new GXByteBuffer();
        bb.set(algorithmID);
        bb.set(partyUInfo);
        bb.set(partyVInfo);
        ...
        return generateKDF(hashAlg, z, keyDataLen, bb.array());
    }
```
```java
    private static byte[] generateKDF(final String hashAlg, final byte[] z, final int keyDataLen,
            final byte[] otherInfo) {
        byte[] key = new byte[keyDataLen / 8];
        try {
            MessageDigest md = MessageDigest.getInstance(hashAlg);
            int hashLen = md.getDigestLength();
            int cnt = key.length / hashLen;
            byte[] v = new byte[4];
            for (int pos = 1; pos <= cnt; pos++) {
                md.reset();
                getBytes(v, pos);
                md.update(v);
                md.update(z);
                md.update(otherInfo);
                byte[] hash = md.digest();
```

Java's `algorithmID` here is the **complete 7-byte OID‖algid**, supplied by the caller as a hex string,
and it is passed **before** partyUInfo (no separate prefix):

* `JAVA/GXDLMS.java:1226-1245`:
```java
        String alg, algID;
        int keyDataLen;
        switch (c.getSecuritySuite()) {
        case SUITE_1:
            sc |= 1;
            alg = "SHA-256";
            // AES-GCM-128
            algID = "60857405080300";
            keyDataLen = 256;
            break;
        case SUITE_2:
            sc |= 2;
            alg = "SHA-384";
            // AES-GCM-256
            algID = "60857405080301";
            keyDataLen = 384;
            break;
        default:
            throw new IllegalArgumentException("Invalid security suite.");
        }
```
* `JAVA/GXDLMSSecuritySetup.java:1194-1199` hard-codes suite-1 parameters on the server side:
```java
                    byte[] algID = GXCommon.hexToBytes("60857405080300"); // AES-GCM-128
                    GXByteBuffer kdf = new GXByteBuffer();
                    kdf.set(GXSecure.generateKDF("SHA-256", sharedSecret, 256,
                            algID, settings.getSourceSystemTitle(),
                            settings.getCipher().getSystemTitle(), null, null),
                            0, 16);
```

### 5.3 Where the KDF is used (C#)

| Call site | partyUInfo | partyVInfo | suppPubInfo | Notes |
|---|---|---|---|---|
| `NET/GXDLMS.cs:1115` (writer, both key-agreement modes) | `c.SystemTitle` (originator/client) | `tmp2.Array()` = recipient ST, or `(len‖txid) ‖ recipient ST` for static-unified | – | `tmp2` built at `:1101` and `:1052-1060` |
| `NET/Secure/GXSecure.cs:849-853` (reader, one-pass DH) | `p.SystemTitle` | `p.RecipientSystemTitle` | – | then `p.BlockCipherKey = kdf.SubArray(0, 16);` |
| `NET/Secure/GXSecure.cs:866-871` (reader, static unified) | `p.SystemTitle` | `transactionId.Array()` | `p.RecipientSystemTitle` | `.Array()` of a buffer that already holds `objectcount ‖ txid` |
| `NET/Objects/GXDLMSSecuritySetup.cs:685-688` (client deriving ephemeral global keys) | `client.Ciphering.SystemTitle` | `client.Settings.SourceSystemTitle` | – | algorithmID is **always `AesGcm128`**, even for suite 2 |

`NET/Secure/GXSecure.cs:855` and `:874`:
```csharp
                p.BlockCipherKey = kdf.SubArray(0, 16);
```

**Ordering subtlety worth flagging:** the three-field call at `:866-871` passes the transaction id in the
*partyVInfo* parameter and the recipient system title in the *suppPubInfo* parameter, but because
`GenerateKDF` concatenates sequentially the resulting otherInfo is
`OID‖algID ‖ originatorST ‖ (len‖transactionId) ‖ recipientST`. The writer side reaches the identical byte
string through `tmp2` (transaction id first, then `SourceSystemTitle`) at `NET/GXDLMS.cs:1052-1060` + `:1101`,
so the two sides agree — but the parameter names do not describe the fields.

---

## 6. Key wrapping / key transport

### 6.1 AES key wrap (RFC 3394) — C#

`NET/Secure/GXDLMSSecureClient.cs:169-219`:

```csharp
        private static readonly byte[] IV = new byte[] { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };

        /// <summary>
        /// Encrypt data using AES RFC3394 key-wrapping.
        /// </summary>
        /// <param name="kek">Key Encrypting Key, also known as Master key.</param>
        public static byte[] Encrypt(byte[] kek, byte[] data)
        {
            if (kek == null || (kek.Length != 16 && kek.Length != 32))
            {
                throw new ArgumentNullException("Invalid Key Encrypting Key");
            }
            if (data == null || (data.Length != 16 && data.Length != 32))
            {
                throw new ArgumentNullException("Invalid data.");
            }

            int n = data.Length / 8;
            byte[] block = new byte[data.Length + IV.Length];
            Array.Copy(IV, 0, block, 0, IV.Length);
            Array.Copy(data, 0, block, IV.Length, data.Length);
            byte[] buf = new byte[8 + IV.Length];
            using (Aes aes1 = Aes.Create())
            {
                aes1.Mode = CipherMode.ECB;
                aes1.Padding = PaddingMode.None;
                aes1.Key = kek;
                ICryptoTransform encryptor = aes1.CreateEncryptor();
                for (int j = 0; j != 6; j++)
                {
                    for (int i = 1; i <= n; i++)
                    {
                        Array.Copy(block, 0, buf, 0, IV.Length);
                        Array.Copy(block, 8 * i, buf, IV.Length, 8);
                        encryptor.TransformBlock(buf, 0, buf.Length, buf, 0);
                        int t = n * j + i;
                        for (int k = 1; t != 0; k++)
                        {
                            byte v = (byte)t;
                            buf[IV.Length - k] ^= v;
                            t = t >> 8;
                        }
                        Array.Copy(buf, 0, block, 0, 8);
                        Array.Copy(buf, 8, block, 8 * i, 8);
                    }
                }
                return block;
            }
        }
```

Byte layout: `A = 0xA6A6A6A6A6A6A6A6`, `R[i] = data[8i..8i+8]`, 6 rounds, `t = n*j + i` XORed into the
**last bytes** of A (`buf[IV.Length - k]`, i.e. little-endian-within-A). Only **16- or 32-byte** KEK and
**16- or 32-byte** plaintext are accepted in C#.

Decrypt (`NET/Secure/GXDLMSSecureClient.cs:227-282`) reverses it and checks the recovered A equals the IV:

```csharp
            if (!GXCommon.Compare(a, IV))
            {
                throw new ArithmeticException("AES key wrapping failed.");
            }
```

### 6.2 AES key wrap — Java

`JAVA/secure/GXSecure.java:87-88` (same IV) and `:151-243` (same algorithm); the public wrappers are
`JAVA/secure/GXDLMSSecureClient.java:130-169`:

```java
    public static byte[] encrypt(final byte[] kek, final byte[] data)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        return GXSecure.encryptAesKeyWrapping(data, kek);
    }
```
```java
    public static byte[] decrypt(final byte[] kek, final byte[] data) {
        if (kek == null) {
            throw new NullPointerException("Key Encrypting Key");
        }
        if (kek.length < 16) {
            throw new IllegalArgumentException("Key Encrypting Key");
        }
        if (kek.length % 8 != 0) {
            throw new IllegalArgumentException("Key Encrypting Key");
        }
```

Note the Java validation is weaker than C# (`kek.length % 8 == 0` and `>= 16`, and `data.length >= 16`),
i.e. **Java accepts key/data lengths C# rejects**.

### 6.3 Where wrapping is used — global key transfer

Client builds `array of structure{ enum keyId, octet-string wrappedKey }` —
`NET/Objects/GXDLMSSecuritySetup.cs:336-358`:

```csharp
            GXByteBuffer bb = new GXByteBuffer();
            bb.SetUInt8(DataType.Array);
            bb.SetUInt8((byte)list.Count);
            byte[] tmp;
            foreach (KeyValuePair<GlobalKeyType, byte[]> it in list)
            {
                bb.SetUInt8(DataType.Structure);
                bb.SetUInt8(2);
                GXCommon.SetData(client.Settings, bb, DataType.Enum, it.Key);
                tmp = GXDLMSSecureClient.Encrypt(kek, it.Value);
                GXCommon.SetData(client.Settings, bb, DataType.OctetString, tmp);
            }
            return client.Method(this, 2, bb.Array(), DataType.Array);
```

Server side unwraps with the meter KEK — `NET/Objects/GXDLMSSecuritySetup.cs:1001-1030`
(`GXDLMSSecureClient.Decrypt(settings.Kek, data)`) and applies them per key type at `:1084-1118`, including
`case GlobalKeyType.Kek: settings.Kek = GXDLMSSecureClient.Decrypt(settings.Kek, data);` (a **new KEK is
wrapped with the old KEK**).

Key lengths are validated against the suite — `NET/Objects/GXDLMSSecuritySetup.cs:138-139` (GUEK), `:158-159`
(GBEK), `:178-179` (GAK):

```csharp
                if ((SecuritySuite != SecuritySuite.Suite2 && value != null && value.Length != 16 && value.Length != 0) ||
                    SecuritySuite == SecuritySuite.Suite2 && value != null && value.Length != 32 && value.Length != 0)
```

### 6.4 ECDH-derived KEK / ephemeral global keys

`NET/Objects/GXDLMSSecuritySetup.cs:682-690` — ECDH shared secret → KDF → 16-byte key, assigned by keyId:

```csharp
                byte[] z = c.GenerateSecret(targetEphemeralKey);
                System.Diagnostics.Debug.WriteLine("Shared secret:" + GXCommon.ToHex(z, true));
                GXByteBuffer kdf = new GXByteBuffer();
                kdf.Set(GXSecure.GenerateKDF(client.SecuritySuite, z,
                    AlgorithmId.AesGcm128,
                    client.Ciphering.SystemTitle,
                    client.Settings.SourceSystemTitle, null, null));
                System.Diagnostics.Debug.WriteLine("KDF:" + kdf.ToString());
                list.Add(new KeyValuePair<GlobalKeyType, byte[]>((GlobalKeyType)keyId, kdf.SubArray(0, 16)));
```

then stored as `EphemeralBlockCipherKey` / `EphemeralBroadcastBlockCipherKey` /
`EphemeralAuthenticationKey` / `EphemeralKek` (`:693-710`). These take precedence over the static keys when
sending (`NET/GXDLMS.cs:789-815`):

```csharp
            if (settings.EphemeralBlockCipherKey != null)
            {
                return settings.EphemeralBlockCipherKey;
            }
            return settings.Cipher.BlockCipherKey;
```

---

## 7. Key agreement (ECDH): ephemeral unified model, one-pass DH, static unified model

### 7.1 The enums

`NET/Enums/KeyAgreementScheme.cs:43-60`:

```csharp
    public enum KeyAgreementScheme
    {
        [XmlEnum("0")]
        EphemeralUnifiedModel,
        [XmlEnum("1")]
        OnePassDiffieHellman,
        [XmlEnum("2")]
        StaticUnifiedModel       
    }
```

`NET/Enums/Signing.cs:42-73`: `None = 0`, `EphemeralUnifiedModel = 1`, `OnePassDiffieHellman = 2`,
`StaticUnifiedModel = 3`, `GeneralSigning = 4`.

`NET/Ecdsa/Enums/Ecc.cs:40-50`: `P256 = 0`, `P384 = 1`.

### 7.2 Curve selection per suite

`NET/GXDLMS.cs:1035-1044`:

```csharp
                if (keyid == 1)
                {
                    //Generate ephemeral key pair for each transaction.
                    c.EphemeralKeyPair = GXEcdsa.GenerateKeyPair(c.SecuritySuite == SecuritySuite.Suite1 ? Ecc.P256 : Ecc.P384);
                    GXEcdsa ka = new GXEcdsa(c.EphemeralKeyPair.Value);
                    ...
                    z = ka.GenerateSecret(c.KeyAgreementKeyPair.Key);
                }
```

`NET/Objects/GXDLMSSecuritySetup.cs:783-790`:

```csharp
        private static Ecc GetEcc(SecuritySuite suite)
        {
            if (suite == Enums.SecuritySuite.Suite1)
            {
                return Ecc.P256;
            }
            return Ecc.P384;
        }
```

Both are **`P384`-as-else**, so suite 0 also maps to P-384 if these paths are ever reached.

### 7.3 Output of the ECDH step and what is hashed into the KDF

`NET/Ecdsa/GXEcdsa.cs:163-185` — the shared secret is the **x coordinate only**, big-endian, of length
`SchemeSize(scheme)`:

```csharp
        public byte[] GenerateSecret(GXPublicKey publicKey)
        {
            ...
            GXByteBuffer bb = new GXByteBuffer();
            bb.Set(publicKey.RawValue);
            int size = SchemeSize(PrivateKey.Scheme);
            GXBigInteger x = new GXBigInteger(bb.SubArray(1, size));
            GXBigInteger y = new GXBigInteger(bb.SubArray(1 + size, size));
            GXEccPoint p = new GXEccPoint(x, y);
            GXCurve curve = new GXCurve(PrivateKey.Scheme);
            GXEccPoint ret = new GXEccPoint(null, null);
            GXShamirs.PointMulti(curve, ret, p, pk);
            return ret.x.ToArray();
        }
```

Public keys are raw uncompressed points with a leading `0x04` (see `SubArray(1, size)` above, and the
`0x04`-stripping when writing them on the wire at §7.4).

### 7.4 Wire layout of the agreed-key field (general-ciphering)

Writer — `NET/GXDLMS.cs:1164-1202`:

```csharp
            if (!sign)
            {
                // optional flag
                reply.SetUInt8(1);
                // agreed-key CHOICE
                reply.SetUInt8(2);
                // key-parameters
                reply.SetUInt8(1);
                reply.SetUInt8(keyid);
            }
            if (keyid == 1)
            {
                ...
                // key-ciphered-data
                GXCommon.SetObjectCount(0x80, reply);
                // Ephemeral public key client.
                reply.Set(c.EphemeralKeyPair.Key.RawValue, 1, c.EphemeralKeyPair.Key.RawValue.Length - 1);

                // Ephemeral Public Key Signature.
                reply.Set(GXSecure.GetEphemeralPublicKeySignature(keyid,
                        c.EphemeralKeyPair.Key, c.SigningKeyPair.Value));
            }
            else if (!sign)
            {
                reply.SetUInt8(0);
            }
```

So for one-pass DH the key-ciphered-data is `0x80` (raw, uncompressed) followed by the 64-byte ephemeral
public key (x‖y, leading `0x04` removed) and then the 64-byte signature. Reader —
`NET/Secure/GXSecure.cs:691-696`:

```csharp
                        if (kp.Key != null)
                        {
                            //Get Ephemeral public key.
                            int keySize = len / 2;
                            kp = new KeyValuePair<GXPublicKey, GXPrivateKey>(GXPublicKey.FromRawBytes(bb.SubArray(0, keySize)), kp.Value);
                        }
```

The responder's reply is parsed as a fixed structure — `NET/Objects/GXDLMSSecuritySetup.cs:660-682`:

```csharp
                if (GXCommon.GetObjectCount(value) != 128)
                {
                    throw new ArgumentOutOfRangeException("Invalid length.");
                }
                //Get ephemeral public key server.
                GXByteBuffer key = new GXByteBuffer();
                key.SetUInt8(4);
                key.Set(value, 64);
                GXPublicKey targetEphemeralKey = GXPublicKey.FromRawBytes(key.Array());
                //Get ephemeral public key signature server.
                byte[] signature = new byte[64];
                value.Get(signature);
                key.SetUInt8(0, (byte)keyId);
                //Verify signature.
                if (!GXSecure.ValidateEphemeralPublicKeySignature(key.Array(), signature, client.Ciphering.SigningKeyPair.Key))
                {
                    throw new GXDLMSCipherException("Invalid signature.");
                }
                byte[] z = c.GenerateSecret(targetEphemeralKey);
```

Note the hard-coded `128` (= 64-byte key + 64-byte signature) and the 64-byte signature buffer — both are
**suite-1-sized** constants (see gotchas).

### 7.5 Java equivalents (divergences)

`JAVA/GXDLMS.java:1272-1300`:

```java
            if (keyid == 1) {
                // Generate ephemeral key pair for each transaction.
                KeyPair kp = GXEcdsa.generateKeyPair(Ecc.P256);
                c.setEphemeralKeyPair(kp);
                KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                ka.init(kp.getPrivate());
                ka.doPhase(c.getKeyAgreementKeyPair().getPublic(), true);
                z = ka.generateSecret();
```
```java
            } else if (keyid == 2) {
                ...
                KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                ka.init(c.getKeyAgreementKeyPair().getPrivate());
                ka.doPhase(c.getKeyAgreementKeyPair().getPublic(), true);
                z = ka.generateSecret();
```

The Java one-pass-DH ephemeral key pair is **hard-coded to `Ecc.P256` regardless of the security suite**,
unlike the C# ternary at `NET/GXDLMS.cs:1038`. The Java static-unified path has the same shape but is
hard-coded `SHA-256`/256-bit KDF output at `JAVA/secure/GXSecure.java:987`. The Java server-side ephemeral
key generation is also `Ecc.P256` with a 64-byte signature (`JAVA/objects/GXDLMSSecuritySetup.java:1161-1189`).

The C variant has **no key-agreement/KDF implementation** ("kdf" has no match anywhere under `C/`): it
declares `gxPrivateKey keyAgreementKey` (`C/include/gxobjects.h:877`) and generates key pairs
(`C/src/gxinvoke.c:990` `gxecdsa_generateKeyPair((ECC)(target->securitySuite - 1), ...)`) but nothing that
derives a data key from a shared secret, and suite 1/2 are compile-time disabled (§10).

---

## 8. ECDSA signing / verification

### 8.1 What is signed and verified for HLS association authentication (C#)

**(a) Client → server `CtoS` (AARQ / `reply_to_HLS_authentication` argument).** The client composes the
input at `NET/GXDLMSClient.cs:1436-1457`:

```csharp
            else if (Settings.Authentication == Enums.Authentication.HighECDSA)
            {
                ...
                GXByteBuffer tmp = new GXByteBuffer();
                tmp.Set(Settings.Cipher.SystemTitle);
                tmp.Set(Settings.SourceSystemTitle);
                tmp.Set(Settings.StoCChallenge);
                tmp.Set(Settings.CtoSChallenge);
                pw = tmp.Array();
            }
```

i.e. `clientSystemTitle ‖ serverSystemTitle ‖ StoCChallenge ‖ CtoSChallenge` — **no password**. Then
`NET/GXDLMSClient.cs:1462-1463` calls `GXSecure.Secure(..., Settings.StoCChallenge, pw)` and `Secure`
signs `secret` (the `pw`) at `NET/Secure/GXSecure.cs:181-203`:

```csharp
            else if (settings.Authentication == Authentication.HighECDSA)
            {
                GXPrivateKey key = settings.Cipher.SigningKeyPair.Value;
                GXPublicKey pub = settings.Cipher.SigningKeyPair.Key;
                ...
                GXEcdsa sig = new GXEcdsa(key);
                data = sig.Sign(secret);
            }
```

(that whole `HighECDSA` branch is inside `#if !WINDOWS_UWP`).

The server verifies against `Secret ‖ SourceSystemTitle ‖ Cipher.SystemTitle ‖ StoC ‖ CtoS` —
`NET/Objects/GXDLMSAssociationLogicalName.cs:351-379`:

```csharp
            else if (settings.Authentication == Authentication.HighECDSA)
            {
                secret = null;
                GXByteBuffer tmp = new GXByteBuffer();
                tmp.Set(Secret);
                tmp.Set(settings.SourceSystemTitle);
                tmp.Set(settings.Cipher.SystemTitle);
                tmp.Set(settings.StoCChallenge);
                tmp.Set(settings.CtoSChallenge);
                GXPrivateKey key = settings.Cipher.SigningKeyPair.Value;
                ...
                GXEcdsa sig = new GXEcdsa(pub);
                equals = sig.Verify(clientChallenge, tmp.Array());
            }
```

`Secret` here is the association object's password attribute, so for ECDSA it must be **empty** for the
client and server inputs to match.

**(b) Server → client `StoC` (AARE).** Server composes at `NET/Objects/GXDLMSAssociationLogicalName.cs:403-417`:

```csharp
                if (settings.Authentication == Authentication.HighSHA256 ||
                    settings.Authentication == Authentication.HighECDSA)
                {
                    GXByteBuffer tmp = new GXByteBuffer();
                    if (settings.Authentication == Authentication.HighSHA256)
                    {
                        tmp.Set(Secret);
                    }
                    tmp.Set(settings.Cipher.SystemTitle);
                    tmp.Set(settings.SourceSystemTitle);
                    tmp.Set(settings.CtoSChallenge);
                    tmp.Set(settings.StoCChallenge);
                    secret = tmp.Array();
                }
                return GXSecure.Secure(settings, settings.Cipher, ic, settings.CtoSChallenge, secret);
```

i.e. `serverSystemTitle ‖ clientSystemTitle ‖ CtoSChallenge ‖ StoCChallenge` (again signed via
`GXSecure.Secure`'s `sig.Sign(secret)`). The client checks it at `NET/GXDLMSClient.cs:1503-1517`:

```csharp
                    if (Settings.Authentication == Enums.Authentication.HighECDSA)
                    {
                        ...
                        GXByteBuffer tmp2 = new GXByteBuffer();
                        tmp2.Set(Settings.SourceSystemTitle);
                        tmp2.Set(Settings.Cipher.SystemTitle);
                        tmp2.Set(Settings.CtoSChallenge);
                        tmp2.Set(Settings.StoCChallenge);
                        GXEcdsa sig = new GXEcdsa(Settings.Cipher.SigningKeyPair.Key);
                        equals = sig.Verify(value, tmp2.Array());
                    }
```

Ordering summary (all four values are the raw challenge octet strings, in the order written):

| Direction | Signed/verified input |
|---|---|
| CtoS (client signs, server verifies) | `[Secret] ‖ clientST ‖ serverST ‖ StoC ‖ CtoS` |
| StoC (server signs, client verifies) | `serverST ‖ clientST ‖ CtoS ‖ StoC` |

### 8.2 Hash and signature encoding (C#)

`NET/Ecdsa/GXEcdsa.cs:98-144` — hash is chosen by **curve**, and the signature is raw `r ‖ s`:

```csharp
        public byte[] Sign(byte[] data)
        {
            ...
            GXBigInteger msg;
            if (PrivateKey.Scheme == Ecc.P256)
            {
                using (SHA256 sha = SHA256.Create())
                {
                    msg = new GXBigInteger(sha.ComputeHash(data));
                }
            }
            else if (PrivateKey.Scheme == Ecc.P384)
            {
                using (SHA384 sha = SHA384.Create())
                {
                    msg = new GXBigInteger(sha.ComputeHash(data));
                }
            }
            ...
            GXByteBuffer signature = new GXByteBuffer();
            signature.Set(r.ToArray(false));
            signature.Set(s.ToArray(false));
            return signature.Array();
```

(For `NET5_0_OR_GREATER` the other branch uses `ECDsa.SignData(...)` with `HashAlgorithmName.SHA256/SHA384`
— `:145-153` — which also returns raw `r‖s`.)

Verification splits at `SchemeSize` — `NET/Ecdsa/GXEcdsa.cs:248-263`:

```csharp
            GXByteBuffer bb = new GXByteBuffer(signature);
            int size = SchemeSize(PublicKey.Scheme);
            GXBigInteger sigR = new GXBigInteger(bb.SubArray(0, size));
            GXBigInteger sigS = new GXBigInteger(bb.SubArray(size, size));
```

Accepted wire lengths are enforced on the receive path (`NET/Secure/GXSecure.cs:1000-1006`):

```csharp
                len = GXCommon.GetObjectCount(data);
                if (len != 64 && len != 96)
                {
                    throw new ArgumentException("Invalid signing.");
                }
                p.Signature = new byte[len];
```

i.e. **64 bytes for suite 1 (two 32-byte integers), 96 bytes for suite 2 (two 48-byte integers)** — DER
encoding is not used on the wire.

### 8.3 Ephemeral-public-key signatures (suite 1/2 key agreement)

`NET/Secure/GXSecure.cs:319-348`:

```csharp
        public static byte[] GetEphemeralPublicKeyData(int keyId,
                GXPublicKey ephemeralKey)
        {
            GXBitString tmp = (GXBitString)((GXAsn1Sequence)GXAsn1Converter.FromByteArray(ephemeralKey.ToEncoded()))[1];
            // Ephemeral public key client
            GXByteBuffer epk = new GXByteBuffer(tmp.Value);
            // First byte is 4 and that is not used. We can override it.
            epk.Data[0] = (byte)keyId;
            return epk.Array();
        }
```
```csharp
        public static byte[] GetEphemeralPublicKeySignature(
            int keyId,
                GXPublicKey ephemeralKey,
                GXPrivateKey signKey)
        {
            byte[] epk = GetEphemeralPublicKeyData(keyId, ephemeralKey);
            // Add ephemeral public key signature.
            GXEcdsa c = new GXEcdsa(signKey);
            byte[] sign = c.Sign(epk);
            return sign;
        }
```

**The `0x04` uncompressed-point prefix is overwritten with the key-id** — that byte is authenticated data,
not a point prefix. Validation converts the raw `r‖s` back to DER before calling the curve code —
`NET/Secure/GXSecure.cs:357-369`:

```csharp
            GXAsn1Integer a = new GXAsn1Integer(sign, 0, 32);
            GXAsn1Integer b = new GXAsn1Integer(sign, 32, 32);
            GXAsn1Sequence s = new GXAsn1Sequence();
            s.Add(a);
            s.Add(b);
            byte[] tmp = GXAsn1Converter.ToByteArray(s);
            GXEcdsa c = new GXEcdsa(publicSigningKey);
            bool ret = c.Verify(sign, data);
```

(two hard-coded 32-byte halves — suite-1 sized).

### 8.4 General signing (`Signing.GeneralSigning`) — what exactly is signed

`NET/GXDLMS.cs:1208-1255`: the signed buffer is the general-signing header **minus the tag byte** plus the
ciphered content:

```csharp
            GXByteBuffer signedData = new GXByteBuffer();
            signedData.Set(reply.Data, 1, reply.Size - 1);
            ...
                // Len
                GXCommon.SetObjectCount(5 + tmp.Length, reply);
                GXCommon.SetObjectCount(5 + tmp.Length, signedData);
                // Add SC
                reply.SetUInt8(sc);
                signedData.SetUInt8(sc);
                // Add IC.
                reply.SetUInt32(p.settings.Cipher.InvocationCounter);
                signedData.SetUInt32(p.settings.Cipher.InvocationCounter);
            ...
            reply.Set(tmp);
            signedData.Set(tmp);
            ...
            if (sign && p.settings.Cipher.Signing != Signing.None)
            {
                // Signature
                GXEcdsa ecdsa = new GXEcdsa(key);
                System.Diagnostics.Debug.WriteLine("Counting signature: " + signedData);
                byte[] signature = ecdsa.Sign(signedData.Array());
                GXCommon.SetObjectCount(signature.Length, reply);
                reply.Set(signature);
            }
```

So the suite-1/2 general-signing signature covers:
`transaction-id ‖ originatorST ‖ recipientST ‖ date-time ‖ other-info ‖ key-parameters ‖ [glo-command] ‖ length ‖ SC ‖ IC ‖ ciphertext`.
The verifying side rebuilds it — `NET/Secure/GXSecure.cs:994-1024`:

```csharp
                GXByteBuffer signedData = new GXByteBuffer();
                signedData.Set(data.Data, 1, contentStart - 1);
                signedData.Set(p.CipheredContent);
                ...
                    GXEcdsa c = new GXEcdsa(kp.Key);
                    System.Diagnostics.Debug.WriteLine("Verifying signature: " + signedData);
                    if (!c.Verify(p.Signature, signedData.Array()))
                    {
                        throw new Exception("Invalid signature.");
                    }
```

### 8.5 Java ECDSA

`JAVA/secure/GXSecure.java:477-527` — JCE `SHA256withECDSA` is **hard-coded** (no SHA-384 path), and the
DER signature is truncated to `r(32) ‖ s(32)`:

```java
    public static byte[] getEphemeralPublicKeySignature(final int keyId, final PublicKey ephemeralKey,
            final PrivateKey signKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] epk = getEphemeralPublicKeyData(keyId, ephemeralKey);
        // Add ephemeral public key signature.
        Signature instance = Signature.getInstance("SHA256withECDSA");
        instance.initSign(signKey);
        instance.update(epk);
        byte[] sign = instance.sign();
        GXAsn1Sequence tmp2 = (GXAsn1Sequence) GXAsn1Converter.fromByteArray(sign);
        LOGGER.log(Level.FINEST, "{0}", GXCommon.toHex(sign));
        GXByteBuffer data = new GXByteBuffer(64);
        // Truncate to 64 bytes. Remove zeros from the begin.
        byte[] arr = ((GXAsn1Integer) tmp2.get(0)).getByteArray();
        if (arr.length < 32) {
            GXByteBuffer bb = new GXByteBuffer();
            bb.size(32 - arr.length);
            bb.set(arr);
            arr = bb.array();
        }
        data.set(arr, arr.length - 32, 32);
        arr = ((GXAsn1Integer) tmp2.get(1)).getByteArray();
        data.set(arr, arr.length - 32, 32);
        return data.array();
    }
```

and the validator rebuilds DER from two 32-byte halves:
```java
        GXAsn1Integer a = new GXAsn1Integer(sign, 0, 32);
        GXAsn1Integer b = new GXAsn1Integer(sign, 32, 32);
```

By contrast, Java's *general-signing* path **is** suite-aware for the hash but still serialises a suite-1
sized signature (`JAVA/GXDLMS.java:1449-1471`):

```java
            if (p.getSettings().getCipher().getSecuritySuite() == SecuritySuite.SUITE_1) {
                sig = Signature.getInstance("SHA256withECDSA");
            } else if (p.getSettings().getCipher().getSecuritySuite() == SecuritySuite.SUITE_2) {
                sig = Signature.getInstance("SHA384withECDSA");
            } else {
                throw new IllegalArgumentException("Invalid security suite.");
            }
            ...
            bb.set(((GXAsn1Integer) seq.get(0)).getByteArray());
            if (bb.size() != 32) {
                bb.move(1, 0, 32);
            }
            bb.set(((GXAsn1Integer) seq.get(1)).getByteArray());
            if (bb.size() != 64) {
                bb.move(33, 32, 32);
            }
```

The C# side has the same two hard-coded 32-byte halves (`NET/Secure/GXSecure.cs:362-363`) even though
`GXEcdsa.Verify` itself is curve-aware.

---

## 9. Where the suite is selected / configured

### 9.1 Library-level configuration surface (C#)

The single mutable holder is `GXCiphering` (`NET/Secure/GXCiphering.cs`), assigned into the settings in both
secure-client constructors — `NET/Secure/GXDLMSSecureClient.cs:49-53` and `:79-81`:

```csharp
            Ciphering = new GXCiphering(ASCIIEncoding.ASCII.GetBytes("ABCDEFGH"));
            Settings.Cipher = Ciphering;
```

Its properties (`NET/Secure/GXCiphering.cs:144-206`): `Security` (`:147`), `SecurityPolicy` (`:165`),
`SecuritySuite` (`:174`), `InvocationCounter` (`:183`), `TransactionId` (`:192`, must be 8 or 0 bytes
unless `TestMode`). `GXCiphering.CopyTo` copies `Security`, `SecuritySuite`, `Signing`,
`InvocationCounter`, `SystemTitle`, `BlockCipherKey`, `AuthenticationKey`, `TransactionId` (`:123-133`).

Green-Book default keys are hard-coded in the constructors — `NET/Secure/GXCiphering.cs:96-102`:

```csharp
        public GXCiphering(byte[] title)
        {
            Security = Security.None;
            SystemTitle = title;
            BlockCipherKey = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
            AuthenticationKey = new byte[] { 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF };
        }
```

Also: `NET/Secure/GXDLMSSecureClient.cs:131-141` exposes `internal SecuritySuite` (an alias for
`Settings.Cipher.SecuritySuite`), and the translator carries its own copy used for key-length validation on
command-line import (`NET/GXDLMSTranslator.cs:263`, `:338-339`, `:366-367`, `:393-394`):

```csharp
                    else if (!((SecuritySuite != SecuritySuite.Suite2 && value.Length == 16) ||
                        (SecuritySuite == SecuritySuite.Suite2 && value.Length == 32)))
```

Defaults: `NET/GXDLMSMeter.cs:145-150` marks the suite `[DefaultValue(Objects.Enums.SecuritySuite.Suite0)]`;
Java `GXCiphering` initialises `securitySuite = SecuritySuite.SUITE_0`
(`JAVA/secure/GXCiphering.java:108`), as does `AesGcmParameter` (`JAVA/secure/AesGcmParameter.java:114`) and
`GXDLMSTranslator` (`JAVA/GXDLMSTranslator.java:142`); the C variant sets `target->suite =
DLMS_SECURITY_SUITE_V0;` in `cip_init` (`C/src/ciphering.c:336`).

### 9.2 Security-setup object attributes / methods

Attributes (`NET/Objects/GXDLMSSecuritySetup.cs:1120-1157`): 1 = logical name, **2 = SecurityPolicy**, **3 =
SecuritySuite**, 4 = ClientSystemTitle, 5 = ServerSystemTitle, 6 = Certificates (only when `Version > 0`):

```csharp
            //SecurityPolicy
            if (all || CanRead(2))
            {
                attributes.Add(2);
            }
            //SecuritySuite
            if (all || CanRead(3))
            {
                attributes.Add(3);
            }
```

Values array (`:273-276`): `return new object[] { LogicalName, SecurityPolicy, SecuritySuite, ... }`.
The suite is written by attribute write at `:1450` (`SecuritySuite = (SecuritySuite)Convert.ToInt32(e.Value);`)
and read as `DataType.Enum` at `:1344`.

Methods (`:313-427`): `Activate(client, Security)` → method 1 with `GetSecurityValue(...)`; `Activate(client,
SecurityPolicy)` → method 1 with the raw policy byte; `GlobalKeyTransfer` → method 2;
`KeyAgreement` → method 3; `GenerateKeyPair` → method 4; `GenerateCertificate` → method 5. Method arguments
are guarded by the suite (`:792-801`):

```csharp
                if (SecuritySuite == SecuritySuite.Suite0 && e.Index > 3)
                {
                    throw new ArgumentOutOfRangeException(Properties.Resources.InvalidSecuritySuiteVersion);
                }
```
and `:938-947`:
```csharp
            if (SecuritySuite == SecuritySuite.Suite0)
            {
                ...
                throw new ArgumentOutOfRangeException(Properties.Resources.InvalidSecuritySuiteVersion);
            }
            ...
            KeyValuePair<GXPublicKey, GXPrivateKey> value = GXEcdsa.GenerateKeyPair(GetEcc(SecuritySuite));
```

XML round-trip enforces the "no suite 1/2 in version 0" rule (`:1472-1475`):
```csharp
            SecuritySuite = (SecuritySuite)reader.ReadElementContentAsInt("SecuritySuite");
            if (SecuritySuite != SecuritySuite.Suite0 && Version == 0)
            {
                throw new Exception(string.Format("Security suite {0} is not available for Suite 0", SecuritySuite));
            }
```
and writes `writer.WriteElementString("SecuritySuite", (int)SecuritySuite);` (`:1578`).

Server-side adoption of a Security-setup object — `NET/GXDLMSSettings.cs:1154-1160`:

```csharp
        private void UpdateSecurity(byte[] systemTitle, GXDLMSSecuritySetup ss)
        {
            if (ss != null)
            {
                Cipher.SecuritySuite = ss.SecuritySuite;
                Cipher.SecurityPolicy = ss.SecurityPolicy;
```
and the reset to suite 0 when the association changes — `NET/GXDLMSSettings.cs:1054-1065`:
```csharp
                if (assignedAssociation is GXDLMSAssociationLogicalName ln)
                {
                    ln.AssociationStatus = AssociationStatus.NonAssociated;
                    ln.XDLMSContextInfo.CypheringInfo = null;
                    InvocationCounter = null;
                    Cipher.SecurityPolicy = SecurityPolicy.None;
                    EphemeralBlockCipherKey = null;
                    EphemeralBroadcastBlockCipherKey = null;
                    EphemeralAuthenticationKey = null;
                    Cipher.SecuritySuite = SecuritySuite.Suite0;
                    Cipher.Signing = Signing.None;
                }
```

### 9.3 Example **client** configuration (C#)

`NET-EX-C/Settings.cs:334-343` — the command-line/config option that sets the suite:

```csharp
                    case 'V':
                        try
                        {
                            settings.client.Ciphering.SecuritySuite = (SecuritySuite)Enum.Parse(typeof(SecuritySuite), it.Value);
                        }
                        catch (Exception)
                        {
                            throw new ArgumentException("Invalid security suite option '" + it.Value + "'. (Suite0, Suite1, Suite2)");
                        }
                        break;
```

Security level and signing in the same parser (`:305-333` and `:344-354`):

```csharp
                            else if (string.Compare("AuthenticationEncryption", it.Value, true) == 0)
                            {
                                settings.client.Ciphering.Security = Security.AuthenticationEncryption;
                            }
```
```csharp
                    case 'K':
                        try
                        {
                            settings.client.Ciphering.Signing = (Signing)Enum.Parse(typeof(Signing), it.Value);
                            settings.client.ProposedConformance |= Conformance.GeneralProtection;
                        }
```

Help text (`NET-EX-C/Settings.cs:556-558`):

```csharp
            Console.WriteLine(" -C \t Security Level. (None, Authentication, Encrypted, AuthenticationEncryption)");
            Console.WriteLine(" -V \t Security Suite version. (Default: Suite0). (Suite0, Suite1 or Suite2)");
            Console.WriteLine(" -K \t Signing (None, EphemeralUnifiedModel, OnePassDiffieHellman or StaticUnifiedModel, GeneralSigning).");
```

Suite → key/certificate file layout in the example (`NET-EX-C/GXDLMSReader.cs:148-171`) — **suite 2 stores
everything in a `384` subdirectory** and files are prefixed `D` (digital signature) or `A` (key agreement):

```csharp
        private static string GetPath(SecuritySuite securitySuite, CertificateType type, string path, byte[] systemTitle)
        {
            string pre;
            if (securitySuite == SecuritySuite.Suite2)
            {
                path = Path.Combine(path, "384");
            }
```

Also note the example refuses compression for suite 0 (`NET-EX-C/GXDLMSReader.cs:851-861`):

```csharp
                if (Client.CompressionOptions.EnableCompression)
                {
                    if (Client.Ciphering.SecuritySuite == 0)
                    {
                        Console.WriteLine("Security suite 0 doesn't use compression.");
                    }
                    else
                    {
                        Console.WriteLine("Compression is enabled.");
                    }
                }
```

### 9.4 Example **server** configuration (C#)

`NET-EX-S/GXDLMSBase.cs:203-218` (ECDSA HLS association; note the suite is **Suite0**):

```csharp
        private void AddHighLevelAssociationEcdsa()
        {
            GXDLMSAssociationLogicalName obj = new GXDLMSAssociationLogicalName("0.0.40.0.8.255");
            obj.ClientSAP = 23;
            ...
            obj.AuthenticationMechanismName.MechanismId = Authentication.HighECDSA;
            ...
            GXDLMSSecuritySetup s = new GXDLMSSecuritySetup("0.0.43.0.7.255");
            s.SecuritySuite = SecuritySuite.Suite0;
            obj.SecuritySetupReference = s.LogicalName;
            s.ServerSystemTitle = Ciphering.SystemTitle;
            Items.Add(s);
        }
```

`NET-EX-S/GXDLMSBase.cs:223-248` (ciphered HLS association, with the invocation-counter Data object):

```csharp
            GXDLMSSecuritySetup s = new GXDLMSSecuritySetup("0.0.43.0.8.255");
            s.SecuritySuite = SecuritySuite.Suite0;
            obj.SecuritySetupReference = s.LogicalName;
            s.ServerSystemTitle = Ciphering.SystemTitle;
            obj.ApplicationContextName.ContextId = ApplicationContextName.LogicalNameWithCiphering;
            Items.Add(s);
            // Add invocation counter.
            GXDLMSData d = new GXDLMSData("0.0.43.1.8.255");
            d.Value = 0;
            d.SetDataType(2, DataType.UInt32);
            Items.Add(d);
```

and `NET-EX-S/GXDLMSBase.cs:688-695`:

```csharp
        void Init()
        {
            //KEK is used when authentication keys are updated.
            Kek = ASCIIEncoding.ASCII.GetBytes("1111111111111111");

            //If pre-established connections are used.
            ClientSystemTitle = ASCIIEncoding.ASCII.GetBytes("ABCDEFGH");
            Ciphering.Security = Security.AuthenticationEncryption;
```

### 9.5 Example client configuration (Java)

`JAVA-EX/Settings.java:262-274`:

```java
            case 'V':
                if ("None".compareTo(it.getValue()) == 0) {
                } else if ("Suite0".compareTo(it.getValue()) == 0) {
                    settings.client.getCiphering().setSecuritySuite(SecuritySuite.SUITE_0);
                } else if ("Suite1".compareTo(it.getValue()) == 0) {
                    settings.client.getCiphering().setSecuritySuite(SecuritySuite.SUITE_1);
                } else if ("Suite2".compareTo(it.getValue()) == 0) {
                    settings.client.getCiphering().setSecuritySuite(SecuritySuite.SUITE_2);
                } else {
                    throw new IllegalArgumentException(
                            "Invalid Ciphering option '" + it.getValue() + "'. (Suite0, Suite1, Suite2)");
                }
                break;
```

(help text at `JAVA-EX/Settings.java:100`; suite-2 path handling at
`JAVA-EX/GXDLMSSecureClient2.java:86-90` `if (securitySuite == SecuritySuite.SUITE_2)`.)

### 9.6 ANSI-C examples (optional cross-check)

`C-EX/GuruxDLMSClientExample/src/main.c:727-745`:

```c
        case 'V':
            if (strcasecmp("Suite0", optarg) == 0)
            {
                con.settings.cipher.suite = DLMS_SECURITY_SUITE_V0;
            }
            else if (strcasecmp("Suite1", optarg) == 0)
            {
                con.settings.cipher.suite = DLMS_SECURITY_SUITE_V1;
            }
            else if (strcasecmp("Suite2", optarg) == 0)
            {
                con.settings.cipher.suite = DLMS_SECURITY_SUITE_V2;
            }
```

`C-EX/GuruxDLMSServerExample/src/exampleserver.c:1098-1108` — the only suite-1 server object in the C tree:

```c
int addSecuritySetupHighEcdsa()
{
    int ret;
    const unsigned char ln[6] = { 0, 0, 43, 0, 4, 255 };
    if ((ret = INIT_OBJECT(securitySetupHighEcdsa, DLMS_OBJECT_TYPE_SECURITY_SETUP, ln)) == 0)
    {
        BB_ATTACH(securitySetupHighEcdsa.serverSystemTitle, SERVER_SYSTEM_TITLE, 8);
        //Ciphering is not used.
        securitySetupHighEcdsa.securityPolicy = DLMS_SECURITY_POLICY_NOTHING;
        securitySetupHighEcdsa.securitySuite = DLMS_SECURITY_SUITE_V1;
    }
    return ret;
}
```

The same pattern appears at `C-EX/GuruxDLMSServerExample2/src/main.c:1066` and
`C-EX/GuruxDLMSSimpleServerExample/src/main.c:721` (suite 0 there).

GUI example (`GXDLMSDirector/Development/MainForm.cs:7377-7381`) hard-codes suite 1 when generating keys:

```csharp
                GXEcdsaKeysDlg dlg = new GXEcdsaKeysDlg(Properties.Settings.Default.GeneratorAddress, keys,
                    certificates,
                    Properties.Resources.GXDLMSDirectorTxt,
                    SecuritySuite.Suite1,
                    null);
```

---

## 10. Things the code reveals that the spec text would not make obvious

1. **The authentication key is part of the AAD.** `NET/Secure/GXGMac.cs:214-215` writes the SC byte and then
   `_authenticationKey` into the GHASH input, and `lenA = (1 + _authenticationKey.Length) * 8`
   (`:206`). Java and C do the same (`JAVA/secure/GXSecure.java:549-550`,
   `C/src/ciphering.c:306`). The AK is therefore authenticated but not encrypted.
2. **The AAD first byte is the whole security-control byte, including the broadcast (`0x40`) and compression
   (`0x80`) flags.** C# folds them in before calling `GetTag` (`NET/Secure/GXSecure.cs:385-393`) and
   re-derives them on decrypt (`:976-984`). Java's *decrypt* path folds them in
   (`JAVA/secure/GXSecure.java:671-677`) but Java's `countTag`/AE-encrypt paths do **not**
   (`:549`, `:620-622`) — an asymmetry that will break tag comparison if those flags are ever set on a
   Java-encrypted frame.
3. **`GXSecure.cs`'s KDF uses the OID `60 85 74 05 08 03` + one algorithm-id byte, not an ASCII context
   label.** `"ENC"`/`"AUT"`/`"MAC"` are *not found in the code* anywhere in the .NET, Java or C trees.
4. **The C# KDF has no key-length parameter and computes a single hash block.** Callers slice
   `SubArray(0, 16)` (`NET/Secure/GXSecure.cs:855`, `:874`; `NET/GXDLMS.cs:1123`;
   `NET/Objects/GXDLMSSecuritySetup.cs:690`). Java instead implements the counter-mode loop with
   `keyDataLen` 256/384 (`JAVA/secure/GXSecure.java:407-432`, `JAVA/GXDLMS.java:1234`, `:1241`). A Java
   implementation and a C# implementation agree only because both take the first 16 bytes.
5. **Suite 2 still uses a 16-byte data key in every code path found.** `p.BlockCipherKey = kdf.SubArray(0, 16)`
   for both suites (`NET/Secure/GXSecure.cs:855`, `:874`), and the AE branch passes
   `kdf.SubArray(0, 16)` (`NET/GXDLMS.cs:1123`). The 32-byte AES-GCM-256 path is only reachable through the
   HSM/`CryptoNotifier` key-provider route, which validates 16 *or* 32 bytes
   (`NET/Secure/GXSecure.cs:920-937`).
6. **`GXDLMSSecuritySetup.UpdateEphemeralKeys` always derives with `AlgorithmId.AesGcm128`**, regardless of
   `client.SecuritySuite` (`NET/Objects/GXDLMSSecuritySetup.cs:685-688`); the Java server hard-codes
   `"60857405080300"`/`"SHA-256"`/256 bits the same way (`JAVA/objects/GXDLMSSecuritySetup.java:1194-1199`).
7. **Ephemeral-key structures are size-hard-coded to suite 1**: `!= 128` length check and a 64-byte
   signature buffer (`NET/Objects/GXDLMSSecuritySetup.cs:664`, `:674`), and
   `NET/Secure/GXSecure.cs:362-363` splits any signature into two 32-byte halves.
8. **Java hard-codes `Ecc.P256` for the ephemeral key pair even for suite 2** —
   `JAVA/GXDLMS.java:1274` `KeyPair kp = GXEcdsa.generateKeyPair(Ecc.P256);` — and
   `JAVA/secure/GXSecure.java:481` hard-codes `"SHA256withECDSA"` for ephemeral signatures. The C# code
   selects the curve from the suite at the equivalent place (`NET/GXDLMS.cs:1038`). This is a real
   interop divergence for suite 2.
9. **Java's AE `AesGcmParameter` is constructed with a hard-coded `0x31`** in the writer
   (`JAVA/GXDLMS.java:1335` `s = new AesGcmParameter(0x31, ...)`), where C# passes the computed `sc`
   (`NET/GXDLMS.cs:1117`). In this path it is inert (`s.setType(CountType.DATA | CountType.TAG)` at
   `JAVA/GXDLMS.java:1412` means the tag field is never written, and the wire SC/ciphering AAD byte comes
   from the separately computed `sc`, `JAVA/GXDLMS.java:1434` + `JAVA/secure/GXSecure.java:671`), but it is a
   hard-coded suite-1 value sitting in a code path that also serves suite 2.
10. **Java's general-signing signature is truncated to a suite-1 size** — `JAVA/GXDLMS.java:1449-1471`
    chooses `SHA256withECDSA`/`SHA384withECDSA` by suite, then forces `r` to 32 bytes and the whole signature
    to 64 bytes (`if (bb.size() != 64) { bb.move(33, 32, 32); }`), so suite 2 cannot produce its 96-byte
    signature here. C# instead signs `signedData` directly and writes whatever length `GXEcdsa.Sign` returns
    (`NET/GXDLMS.cs:1250-1254`), and only *accepts* 64/96 on receive (`NET/Secure/GXSecure.cs:1001`).
11. **Compatibility branches:** the `Italy` standard suppresses the system title in the ciphering
    wrapper (`NET/GXDLMS.cs:886` `s.IgnoreSystemTitle = p.settings.Standard == Standard.Italy;` →
    `NET/Secure/GXSecure.cs:489-492` writes a single `0x00` instead), and the example client has a
    Landis+Gyr workaround for a missing StoC in HLS (`NET/GXDLMSClient.cs:1489-1493`
    `if (manufacturerId == "LGZ" && Settings.Authentication == Enums.Authentication.High)`).
12. **`IncreaseInvocationCounterForGMacAuthentication` defaults to `true`** (`NET/GXDLMSSettings.cs:249`)
    even though its doc-comment describes the opposite case; the increment then happens in
    `NET/Internal/GXAPDU.cs:1722-1725` and `NET/GXDLMSClient.cs:1464-1467`.
13. **Two different IC bookkeeping rules coexist**: the AARQ/AARE parser stores `ExpectedInvocationCounter =
    1 + p.InvocationCounter` (`NET/Internal/GXAPDU.cs:732`) while `GXSecure.DecryptAesGcm` stores the received
    value unchanged (`NET/Secure/GXSecure.cs:894`) and `GetPdu` stores `= p.InvocationCounter`
    (`NET/GXDLMS.cs:5713`).
14. **A frame can carry a different suite than configured and be accepted** on the general-glo/ded receive
    path: `NET/GXDLMS.cs:5541` `cipher.SecuritySuite = p.SecuritySuite;` (no comparison), whereas
    `NET/Secure/GXSecure.cs:790-795` throws `DecipheringError` on a suite mismatch.
15. **Security-suite mismatch is a hard failure without an XML translator**, and the translator's key-length
    validation is suite-driven (`NET/GXDLMSTranslator.cs:338-339`).
16. The C variant **compiles suite 1/2 support off by default** — `C/include/gxignore.h:196-200`:
    ```c
    //Security Suite 1 is used.
    // #define DLMS_SECURITY_SUITE_1

    //Security Suite 2 is used.
    //#define DLMS_SECURITY_SUITE_2
    ```
    and has no KDF/key-agreement implementation at all (no `kdf` identifier under `C/`).
17. **Default hard-coded system title in the .NET client is `"ABCDEFGH"`** and the default keys are the
    Green Book values (`NET/Secure/GXDLMSSecureClient.cs:51`, `NET/Secure/GXCiphering.cs:100-101`;
    server-side `ClientSystemTitle = ASCIIEncoding.ASCII.GetBytes("ABCDEFGH")`,
    `Kek = ASCIIEncoding.ASCII.GetBytes("1111111111111111")` at `NET-EX-S/GXDLMSBase.cs:691-694`).
18. **Suite 0 still carries a suite value in the SC byte's low nibble** — `tag = (byte)((byte)param.Security
    | (byte)param.SecuritySuite)` (`NET/Secure/GXSecure.cs:385`), so a suite-0 AE frame is `0x30` and a
    suite-1 AE frame is `0x31`. Suite 0 therefore also matches `sc & 0x3 == 0`
    (`NET/Secure/GXSecure.cs:789`).
19. The Java `SecurityPolicy` decode is a `Set` and lacks `NONE`/`AUTHENTICATED_ENCRYPTED` (§1.5), while the
    C# enum is `[Flags] : byte` with `None = 0`.

---

## Implementation gotchas worth practising

* **Nonce/IV assembly.** C# builds a 16-byte counter block `ST(8) ‖ IC(4 BE) ‖ blockCounter(4 BE)` where the
  block counter is written at offset 12 only and **never carries into the IC**
  (`NET/Secure/GXGCMCryptoTransform.cs:78-93`, `:125-133`). Java hands JCE `ST ‖ IC` (12 bytes) and lets the
  library do J0/inc32. Both are correct GCM, but a hand-rolled implementation must use counter block 2 for the
  first data block, 1 for the tag mask, and 0 for H (`NET/Secure/GXGMac.cs:60-68`). Getting the initial block
  counter wrong produces a valid-looking tag that no one else accepts.
* **The system title is silently reshaped, not validated, inside the GCM helper**
  (`NET/Secure/GXGCMCryptoTransform.cs:78-93`): a short title is zero-extended to 8 bytes, and a title longer
  than 8 bytes makes the final `bb.Get(_nonceAndCounter)` copy the first 16 bytes of the *title* and drop the
  counters from the nonce altogether. Only the outer API (`NET/Secure/GXDLMSSecureClient.cs:161-164`,
  `NET/Secure/GXSecure.cs:549-559`) insists on exactly 8 bytes.
* **AAD = `SC ‖ AK ‖ [plaintext] ‖ pad ‖ [ciphertext] ‖ pad ‖ lenA(bit) ‖ lenC(bit)`** — the AK is inside the
  AAD (`NET/Secure/GXGMac.cs:214-232`). If you "improve" this by omitting the AK, every other implementation
  rejects your tags.
* **Tag is always 96 bits** — for both authentication-only and AE, and in .NET, Java and C. Do not emit a
  128-bit tag (`NET/Secure/GXGMac.cs:236-238`, `JAVA/secure/GXSecure.java:556-558`,
  `C/src/ciphering.c:328`).
* **Authentication-only frames are not encrypted.** The APDU is `SC ‖ IC ‖ plaintext ‖ tag` and the receiver
  subtracts **12 + 5** (`NET/Secure/GXSecure.cs:947`). Do not run the CTR keystream over an auth-only frame:
  `GXGMac.Decrypt` starts with an unconditional `_encrypt.TransformBlock` and is only safe because the
  auth-only case returns earlier (`NET/Secure/GXSecure.cs:945-965`).
* **The security-control byte differs by level and carries the suite in its low nibble**: `0x10 | suite`,
  `0x20 | suite`, `0x30 | suite`, plus `0x40` broadcast and `0x80` compression, and the byte you put in the
  AAD must be the byte you put on the wire (`NET/Secure/GXDLMS.cs:968-999` + `NET/Secure/GXSecure.cs:385-393`,
  `:976-984`).
* **Invocation counter discipline.** Counters are big-endian UInt32, incremented *after* each protected send
  (`NET/GXDLMS.cs:905`, `:1243`); receivers must compare with *their* stored counter and reject lower values
  (`NET/Secure/GXSecure.cs:886-895`, `NET/GXDLMS.cs:5707-5714`). Two Code paths use `+1` bookkeeping and two
  use the raw received value — mixing them up gives spurious `InvocationCounterError`. The GMAC-only
  increment is flag-controlled and the flag defaults to `true` (`NET/GXDLMSSettings.cs:249`).
* **`Type = Packet` is `-1`, and both `Data` and `Tag` bit tests are true for it** (`NET/Secure/CountType.cs`
  + `NET/Secure/GXSecure.cs:433-475`). Re-implementing this with `Packet = 0` silently drops the plaintext
  and the tag.
* **KDF context ordering matters.** The bytes are `counter(0x00000001) ‖ Z ‖ OID‖algID ‖ partyU ‖ partyV
  [‖ suppPub] [‖ suppPriv]` (`NET/Secure/GXSecure.cs:264-276`, `:286-291`). In the static-unified model the
  transaction id is passed in the *partyVInfo* slot and the recipient title in the *suppPubInfo* slot
  (`NET/Secure/GXSecure.cs:866-871`) while the writer reaches the same order through `tmp2`
  (`NET/GXDLMS.cs:1052-1060`, `:1101`). Copy the byte order, not the parameter names.
* **Suite 2 curve/key-size traps.** C# falls back to P-384 for anything that is not suite 1
  (`NET/GXDLMS.cs:1038`, `NET/Objects/GXDLMSSecuritySetup.cs:783-790`); Java hard-codes P-256 for ephemeral
  keys and SHA-256 for ephemeral signatures (`JAVA/GXDLMS.java:1274`, `JAVA/secure/GXSecure.java:481`); the
  ephemeral-key parse assumes a 64-byte key + 64-byte signature (`NET/Objects/GXDLMSSecuritySetup.cs:664`,
  `:674`). All three assumptions break for suite 2 unless handled explicitly.
* **Signature encoding is raw `r‖s`, not DER, on the wire** (`NET/Ecdsa/GXEcdsa.cs:141-144`), 64 bytes for
  suite 1 and 96 for suite 2 (`NET/Secure/GXSecure.cs:1001`). But the *ephemeral public key signature*
  helpers convert to/from a 2×32-byte DER structure (`NET/Secure/GXSecure.cs:357-367`,
  `JAVA/secure/GXSecure.java:509-517`) — DER is only an internal detail there.
* **The `0x04` point prefix is overwritten with the key-id** before signing/verifying the ephemeral public
  key (`NET/Secure/GXSecure.cs:319-327`). Verify the key-id byte, not the SEC1 prefix.
* **HLS ECDSA input composition is asymmetric in a way that matters**: the `CtoS` signature covers
  `clientST ‖ serverST ‖ StoC ‖ CtoS` while the `StoC` signature covers `serverST ‖ clientST ‖ CtoS ‖ StoC`
  (`NET/GXDLMSClient.cs:1451-1456` and `:1510-1514`, `NET/Objects/GXDLMSAssociationLogicalName.cs:354-359`
  and `:406-415`). The server's verify additionally prefixes the association `Secret`, which must be empty for
  ECDSA.
* **General signing does not include the initial tag byte of the general-signing PDU** — the signed buffer
  starts at offset 1 and includes the ciphertext, SC and IC (`NET/GXDLMS.cs:1208-1245`,
  `NET/Secure/GXSecure.cs:997-999`).
* **Tag comparison is early-exit and not constant time** (`NET/Secure/GXGMac.cs:509-519`); if you are writing
  production code, replace it with a constant-time compare.
* **Key wrap accepts only 16/32-byte material in C#** and rejects everything else up front
  (`NET/Secure/GXDLMSSecureClient.cs:179-186`), while Java only requires a multiple of 8 (≥16)
  (`JAVA/secure/GXDLMSSecureClient.java:146-163`). The IV is the RFC-3394 constant
  `A6A6A6A6A6A6A6A6` (`NET/Secure/GXDLMSSecureClient.cs:169`, `JAVA/secure/GXSecure.java:87-88`).
* **A new KEK is delivered wrapped with the old KEK** (`NET/Objects/GXDLMSSecuritySetup.cs:1104-1106`), so key
  rotation order matters; and the unwrapped keys are only *applied* after the reply is generated
  (`:1001-1003`, `ApplyKeys` at `:1084`).
* **Suite 0 cannot use Security-setup methods above index 3**, and suite 1/2 cannot be used with `Version == 0`
  (`NET/Objects/GXDLMSSecuritySetup.cs:796-800`, `:1472-1475`) — the object version and the suite are
  coupled.
