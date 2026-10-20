# DLMS/COSEM Green Book Ed. 11 — Security Extract (citation-backed)

**Scope.** Every fact below is taken from the local converted Markdown of DLMS UA 1000-1 Ed. 11 (Green Book), not from memory. Where a claim is not supported by these files it is marked **UNCERTAIN / NOT FOUND**. Quotes are verbatim (whitespace/line-wrap artefacts of the PDF→Markdown conversion are normalised only where noted, in square brackets).

**Files used (absolute paths):**

| Short name | Absolute path |
|---|---|
| `ch9-9-2` | `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md` |
| `ch9-9-3` | `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-3-dlms-cosem-application-layer-service-specificati.md` |
| `ch9-9-4` | `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-4-dlms-cosem-application-layer-protocol-specificat.md` |
| `ch9-9-5` | `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-5-abstract-syntax-of-cosem-pdus.md` |
| `ch3-3-2` | `D:\project\personal\dlms\GreenBook\output\book\ai\ch3\markdown\ch3-3-2-definitions-related-to-cryptographic-security.md` |
| `ch4-4-3` (supporting) | `D:\project\personal\dlms\GreenBook\output\book\ai\ch4\markdown\ch4-4-3-naming-and-addressing.md` |
| `chC` (supporting) | `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\` |

---

## 1. Definition of "security suite" and the exact list of suites

### Definition

- `A security suite determines the set of cryptographic algorithms available for the various cryptographic primitives and the key sizes.`
- `The DLMS/COSEM security suites – see Table 27 – are based on NSA Suite B and include cryptographic algorithms for authentication, encryption, key agreement, digital signature and hashing`.

**Source:** `ch9-9-2 ...\ch9-9-2-information-security-in-dlms-cosem.md` §9.2.3.7 (p.228)

### Table 27 — DLMS/COSEM security suites (verbatim)

| Security Suite Id | Security suite name | Authenticated encryption | Digital signature | Key agreement | Hash | Key-transport | Compression |
|---|---|---|---|---|---|---|---|
| 0 | AES-GCM-128 | AES-GCM-128 | – | – | – | AES-128 key wrap | – |
| 1 | ECDH-ECDSA-AES-GCM-128-SHA-256 | AES-GCM-128 | ECDSA with P-256 | ECDH with P-256 | SHA-256 | AES-128 key wrap | V.44 |
| 2 | ECDH-ECDSA-AES-GCM-256-SHA-384 | AES-GCM-256 | ECDSA with P-384 | ECDH with P-384 | SHA-384 | AES-256 key wrap | V.44 |
| All other reserved | – | – | – | – | – | – | – |

**Source:** `ch9-9-2 ...\ch9-9-2-information-security-in-dlms-cosem.md` §9.2.3.7, Table 27 (p.228)

- **Suite 0 has no public-key capability, no hash and no compression.** This is stated by the dashes in Table 27 and independently by Table 21 (`Suite 0` → curve `–`, OID `–`).
- There is **no "Suite B" numbered suite** in this list; Suite B is only the *basis* of the design and the name of the certificate profile (§9.2.6.5). The only suite IDs are **0, 1, 2**, everything else reserved.

### Algorithms mandated by §9.2.3.7 (verbatim bullets)

- Symmetric: `authentication and encryption: the Advanced Encryption Standard (AES) shall be used as specified in FIPS PUB 197, with key sizes of 128 and 256 bits. AES shall be used with the Galois/Counter Mode (GCM) of operation specified in NIST SP 800-38D:2007;`
- Signature: `digital signature: the Elliptic Curve Digital Signature Algorithm (ECDSA) shall be used as specified FIPS PUB 186-4:2013 and in NSA1, using the curves P-256 or P-384;`
- Key agreement: `the Ephemeral Unified Model C(2e, 0s, ECC CDH) scheme, see 9.2.3.4.6.2`, `the One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) scheme, see 9.2.3.4.6.3; and`, `the Static Unified Model C(0e, 2s, ECC CDH) scheme, see 9.2.3.4.6.4` — `shall be used using the elliptic curves P-256 or P-384.`
- Hash: `hashing: the Secure Hash Algorithms (SHA) SHA-256 and SHA-384 shall be used as specified in FIPS PUB 180-4:2012.`
- `In addition, a key wrapping and a compression algorithm are available.`

### Per-suite algorithm / key-length facts stated elsewhere (more precise than Table 27)

| Parameter | Suite 0 | Suite 1 | Suite 2 | Source |
|---|---|---|---|---|
| Encryption (block cipher) key EK | 128 bits (16 octets) | 128 bits (16 octets) | 256 bits (32 octets) | §9.2.3.3.7.4 (`for security suite 0 and 1, 128 bits (16 octets): len(EK) = 128` / `for security suite 2, 256 bits (32 octets): len(EK) = 256`) |
| Authentication key AK | `same rules apply as for the encryption key` (⇒ 128 bits for suites 0/1, 256 bits for suite 2) | ditto | ditto | §9.2.3.3.7.5 |
| Authentication tag length t | 96 bits | 96 bits | 96 bits | §9.2.3.3.7.6 (`In security suites 0, 1 and 2 its value shall be 96 bits.`) |
| KEK (master key) | 128 bits (16 octets) | 128 bits (16 octets) | 256 bits (32 octets) | §9.2.3.3.8 (`for security suite 0 and 1, 128 bits (16 octets): len(KEK) = 128` / `for security suite 2, 256 bits (32 octets): len(KEK) = 256.`) |
| Digital signature | none | `elliptic curve P-256 with the SHA-256 hash algorithm` | `elliptic curve P-384 with the SHA-384 hash algorithm` | §9.2.3.4.5 |
| Curve / OID | – | `NIST curve P-256`, ASN.1 OID `1.2.840.10045.3.1.7` | `NIST curve P-384`, ASN.1 OID `1.3.132.0.34` | §9.2.3.4.2.2, Table 21 |
| Message digest for signatures | – | – | – | §9.2.3.4.4 (generic); concrete pairing only in §9.2.3.4.5 |
| Certificate signature algorithm | – | `ecdsa-with-SHA256, OID 1.2.840.10045.4.3.2 in the case of security suite 1` | `ecdsa-with-SHA384, OID 1.2.840.10045.4.3.3 in the case of security suite 2` | §9.2.6.4.2 |
| Compression | – | `V.44` | `V.44` | Table 27; algorithm specified in §9.2.3.6 |

### Certificate profile per suite (Suite B)

- `NSA3 specifying the NSA Suite B Base Certificate and CRL Profile.` (§9.2.6.3.1)
- §9.2.6.5 title: `Suite B end entity certificate types to be supported by DLMS servers`. Requirements: `Every DLMS server must use X.509 v3 format and contain either: - a P-256 or P-384 ECDSA-capable signing key; or - a P-256 or P-384 ECDH-capable key agreement key.` and `Every certificate must be signed using ECDSA. The signing CA's key must be P-256 or P-384 if the certificate contains a key on P-256. The signing CA's key must be P-384 if the certificate contains a key on P-384.`
- Table 41 (per suite, verbatim cells): Suite 1 → `Root Certification Authority (Root-CA) Self-Signed Certificate using P-256 signed with P-256`; Suite 2 → `Root Certification Authority (Root-CA) Self-Signed Certificate using P-384 signed with P-384`. Suite 1 additionally allows `Subordinate CA Certificate (Sub-CA) using P-256 signed with P-384` and `End-Entity Signature Certificate using P-256 signed with P-384` and `End-Entity Key Establishment Certificate using P-256 signed with P-384` and `End-Entity TLS Certificate using P-256 signed with P-384`; for suite 2 the corresponding "signed with P-384" duplicates are `–`.
- `An example Certificate is given in Annex B.`
- SubjectPublicKeyInfo: `The value of the parameter shall be 1.2.840.10045.3.1.7 for the curve NIST P-256 and 1.3.132.0.34 for the curve NIST P-384.` and algorithm OID `1.2.840.10045.2.1` described as `ECDSA and ECDH Public Key.` (§9.2.6.4.3.5)

**UNCERTAIN / NOT FOUND:** no definition of the term "security suite" in `ch3-3-2` (the cryptographic-security definitions file contains definitions of *cryptographic key*, *key wrapping*, *key-transport*, *deprecated*, etc., but **no entry for "security suite"**). No Suite-B numeric suite Id beyond 0/1/2. No per-suite certificate *validity period* / *key usage* table beyond what is above.

---

## 2. Security levels and their numeric codes

### What the files actually provide

The files use **two different notions**, and neither is presented as a single "security level" enum with the values NONE(0)/AUTHENTICATION(1)/ENCRYPTION(2)/AUTH+ENC(3):

**(a) Authentication security levels for AA establishment** — `There are three different authentication mechanisms available with different authentication security levels:` (`no security (Lowest Level Security) authentication`, `Low Level Security (LLS) authentication`, `High Level Security (HLS) authentication`).

**Source:** `ch9-9-2` §9.2.2.2.2.1 (p.205); identical wording repeated in `ch9-9-4 ...\ch9-9-4-dlms-cosem-application-layer-protocol-specificat.md` §9.4.2.2.3 (p.312): `Authentication of the client, the server or both is one of the security aspects addressed by the DLMS/COSEM specification. Three authentication security levels are specified:`

These three are **not** given numeric codes as "security levels"; their numeric identity is the **authentication mechanism name / mechanism_id**:

| mechanism_id | Mechanism name | Source |
|---|---|---|
| 0 | `COSEM_lowest_level_security_mechanism_name ::= mechanism_id(0)` | `ch9-9-4` §9.4.2.2.3, Table 83 |
| 1 | `COSEM_low_level_security_mechanism_name ::= mechanism_id(1)` | ditto |
| 2 | `COSEM_high_level_security_mechanism_name ::= mechanism_id(2)` | ditto |
| 3 | `..._using_MD5 ::= mechanism_id(3)` | ditto |
| 4 | `..._using_SHA-1 ::= mechanism_id(4)` | ditto |
| 5 | `..._using_GMAC ::= mechanism_id(5)` | ditto |
| 6 | `..._using_SHA-256 ::= mechanism_id(6)` | ditto |
| 7 | `..._using_ECDSA ::= mechanism_id(7)` | ditto |

**(b) Message protection combinations** — defined not as an enum but by the **A and E subfields of the security control byte** and their security-control values:

| SC A field (bit 4) | SC E field (bit 5) | Protection | Plaintext P | Source |
|---|---|---|---|---|
| 0 | 0 | `None` | `–` | §9.2.7.2.4.3, Table 46 |
| 0 | 1 | `Authenticated only` | `–` | ditto |
| 1 | 0 | `Encrypted only` | `(C) I` | ditto |
| 1 | 1 | `Encrypted and authenticated` | `(C) I` | ditto |

- `Bit 4: "A" subfield: indicates that authentication is applied`
- `Bit 5: "E" subfield: indicates that encryption is applied`
- `In DLMS/COSEM, it is also possible to use GCM to provide confidentiality only: in this case, the authentication tags are simply not computed and checked.` (§9.2.3.3.7.1)

**Source:** `ch9-9-2` §9.2.7.2.4.2 (Table 45), §9.2.7.2.4.3 (Table 46), §9.2.3.3.7.1

**Worked SC byte values from the document (suite 0):** in Table 48 the security control byte takes values `10` (authentication), `20` (encryption), `30` (authenticated encryption) — i.e. bits 3..0 = 0 = suite Id, bit 4 / bit 5 / both set. Same suite-0 values in Table 51 (`SC ... 10`), and in Annex C the general-ciphering values `31` appear for authenticated encryption.

**UNCERTAIN / NOT FOUND — important:** these files contain **no enumeration of "security levels" with numeric codes**, and **no statement restricting which security levels are allowed for which suite**. The Green Book states no rule such as "suite 0 supports only authentication and encryption but not signature"; what it states instead is capability-by-table: Table 27 gives suite 0 `–` for digital signature / key agreement / hash / compression, and message signature is by definition absent for suite 0 (the general-signing APDU uses ECDSA/`Signing key`, Table 44). Any statement that "security level X is only allowed with suite Y" is **not found in these files** — it would have to come from DLMS UA 1000-1 Part 2 (Blue Book), which is referenced (`For older versions, see their specification in DLMS UA 1000-1, the "Blue Book".`) but not present here.

---

## 3. The security policy field — possible values and meaning

### Table 42 — Security policy values ("Security setup" version 1)

The enum type shall be interpreted as an unsigned 8 type (bit map):

| Bit | Security policy |
|---|---|
| 0 | `unused, shall be set to 0` |
| 1 | `unused, shall be set to 0` |
| 2 | `authenticated request` |
| 3 | `encrypted request` |
| 4 | `digitally signed request` |
| 5 | `authenticated response` |
| 6 | `encrypted response` |
| 7 | `digitally signed response` |

**Source:** `ch9-9-2 ...\ch9-9-2-information-security-in-dlms-cosem.md` §9.2.7.2.2, Table 42 (p.248)

Verbatim lead-in and footnote:

- `In the case of "Security setup" version 1 – see DLMS UA 1000-1 Part 2 Ed.15:2021, 4.4.7 – the enum type shall be interpreted as an unsigned 8 type; the meaning of each bit is as shown in Table 42.`
- `In the case of "Security policy" version 0 the possible security policy values are specified in DLMS UA 1000-1 Part 2 Ed.15:2021, 5.4.8. For both "Security policy" version 0 and 1 the value (0) means that no cryptographic protection is required.`

### Numeric values

Derived from the bit map above (document does not print combined decimal values for the policy, but it does for the analogous access-rights enum):

| Value | Meaning (derived) |
|---|---|
| 0 | no cryptographic protection required (`the value (0) means that no cryptographic protection is required`) |
| 4 (bit 2) | authenticated request |
| 8 (bit 3) | encrypted request |
| 16 (bit 4) | digitally signed request |
| 32 (bit 5) | authenticated response |
| 64 (bit 6) | encrypted response |
| 128 (bit 7) | digitally signed response |

**UNCERTAIN / NOT FOUND:** the document gives no printed decimal example for the security policy; the numbers above are a direct reading of "bit n ⇒ 2^n" from Table 42 and from the access-rights table's own examples. "Security policy version 0" values are **explicitly delegated** to the Blue Book (`DLMS UA 1000-1 Part 2 Ed.15:2021, 5.4.8`) and are not in these files.

### Related but distinct: access rights (Table 43)

`Access rights are held by the object_list attribute of "Association LN" or the access_rights_list of "Association SN" objects.` — the access_mode enum is likewise an unsigned8 bit map:

| Bit | Attribute access | Method access |
|---|---|---|
| 0 | read-access | access |
| 1 | write-access | not-used |
| 2 | authenticated request | authenticated request |
| 3 | encrypted request | encrypted request |
| 4 | digitally signed request | digitally signed request |
| 5 | authenticated response | authenticated response |
| 6 | encrypted response | encrypted response |
| 7 | digitally signed response | digitally signed response |

Documented examples (verbatim): `enum (3): read-write`, `enum (6) write access with authenticated request`, `enum (255): read-write access with authenticated, encrypted and digitally signed request and response`; methods: `enum (1): access`, `enum (2): not used`, `enum (5): access with authenticated request`, `enum (253): access with authenticated, encrypted and digitally signed request and response`.

Enforcement rule (verbatim): `APDUs with more protection than required by the security policy are always allowed. APDUs with less protection than required by the security policy and the access rights shall be rejected.` and `The protection to be applied shall meet the stronger of the requirement stipulated by the security policy and the access rights.` (§9.2.2.4)

**Source:** `ch9-9-2` §9.2.7.2.2 Table 43 (p.248), §9.2.2.4 (p.208)

### Where the policy lives

- `The security context defines security attributes relevant for cryptographic transformations and includes the following elements:` … `the security policy, determining the kind(s) of protection to be applied generally to all xDLMS APDUs exchanged within an AA. The possible security policies are specified in 9.2.7.2.2;` … `The security context is managed by "Security setup" objects`.
- **UNCERTAIN / NOT FOUND:** no explicit *client security policy* vs *server security policy* numeric pair is defined in these files. The only client/server split is the bit map's request (bits 2/3/4) vs response (bits 5/6/7) halves, held by the "Security setup" object.

**Source:** `ch9-9-2` §9.2.2.3 (p.208)

---

## 4. Ciphering with AES-GCM: IV, AAD, tag, security header, SC byte, invocation counter

### 4.1 IV / nonce construction

- `In DLMS/COSEM, for the construction of the initialization vector IV deterministic construction as specified in NIST SP 800-38D:2007, 8.2.1 shall be used: the IV is the concatenation of two fields, called the fixed field and the invocation field.`
- `The length of the IV shall be 96 bits (12 octets): len(IV) = 96. Within this:`
  - `the leading (i.e. the leftmost) 64 bits (8 octets) shall hold the fixed field. It shall contain the system title, see 4.3.4;`
  - `the trailing (i.e. the rightmost) 32 bits shall hold the invocation field. The invocation field shall be an integer counter.`
- Formula as printed in the figures and examples: `IV = Sys-T II IC` (concatenation operator `II`), 12 bytes / 96 bits.
- `In the case of the general-ciphering service, AAD contains additional elements as well.` (does not change the IV)
- System title definition: `The system title Sys-T shall uniquely identify each DLMS/COSEM entity.` … `shall be 8 octets long` … `The first three (most significant) octets should hold the three-letter manufacturer ID. … The remaining 5 octets shall ensure uniqueness.`

**Source:** `ch9-9-2` §9.2.3.3.7.3 (p.216), §9.2.7.2.4.1 (p.250), §9.2.7.2.4.5 (`See 9.2.3.3.7.3.`); system title: `ch4-4-3 ...\ch4-4-3-naming-and-addressing.md` §4.3.4 (p.49)

**Worked value (Table 48):** `System Title Sys-T 4D4D4D0000BC614E`, `Invocation counter IC 01234567`, `Initialization Vector IV Sys-T II IC` → `4D4D4D0000BC614E01234567`, `12` bytes / `96` bits.

### 4.2 AAD (Additional Authenticated Data)

Table 46 — Plaintext and Additional Authenticated Data (verbatim cell contents):

| E | A | Protection | P | A for service-specific glo/ded + general-glo-/general-ded-ciphering | A for general-ciphering |
|---|---|---|---|---|---|
| 0 | 0 | None | – | – | – |
| 0 | 1 | Authenticated only | – | `SC II AK II (C) I` | `SC II AK II transaction-id II 1 originator-system-title II 1 recipient-system-title II 1 date-time II 1 other-information II 1 (C) I` |
| 1 | 0 | Encrypted only | `(C) I` | – | – |
| 1 | 1 | Encrypted and authenticated | `(C) I` | `SC II AK` | `SC II AK II transaction-id II 1 originator-system-title II 1 recipient-system-title II 1 date-time II 1 other-information 1` |

Footnote 1 verbatim: `The fields transaction-id ….other-information are A-XDR encoded OCTET STRINGs. The length and the value of each field is included in the AAD.`

Where `SC = Security control byte`, `AK = Authentication key`, `I = the information, i.e. the xDLMS APDU or the COSEM data to be protected`, and `(C)` denotes the ciphered form. Note the figure legend: `- Authentication only: SC II AK II (C) Information; - Encryption only: Null - Authenticated encryption: SC II AK`.

**Source:** `ch9-9-2` §9.2.7.2.4.3, Table 46 (p.251); §9.2.7.2.4.1 (p.250)

**Worked values (Table 48, suite 0):**
- Authentication: `A-A = 10D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFC0010000080000010000FF0200`, `30` bytes / `240` bits (SC byte `10` + 16-octet AK + 13-octet APDU).
- Encryption: `A-E = –`, `0` bytes.
- Authenticated encryption: `A-AE = 30D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF`, `17` bytes / `136` bits (SC byte `30` + AK only).

### 4.3 Authentication tag length

- `The bit length of the authentication tag, denoted t, is a security parameter. In security suites 0, 1 and 2 its value shall be 96 bits.`
- Confirmed by every worked example: `Authentication tag T ... 12` bytes / `96` bits.

**Source:** `ch9-9-2` §9.2.3.3.7.6 (p.217); Table 48 (§9.2.7.2.4.10)

### 4.4 Security header

- `The security header SH includes the security control byte concatenated with the invocation counter: SH = SC II IC.`
- Size in the worked example: `Security header SH ... SH = SC-A II IC / SH = SC-E II IC / SH = SC-AE II IC` → `1001234567`, `2001234567`, `3001234567`, `5` bytes / `40` bits.

**Source:** `ch9-9-2` §9.2.7.2.4.2 (p.251), Table 48 (§9.2.7.2.4.10, p.255)

### 4.5 Security control byte bit layout

| Bit 7 | Bit 6 | Bit 5 | Bit 4 | Bit 3..0 |
|---|---|---|---|---|
| Compression | Key_Set | E | A | Security_Suite_Id |

- `Bit 3…0: Security_Suite_Id, see 9.2.3.7`
- `Bit 4: "A" subfield: indicates that authentication is applied`
- `Bit 5: "E" subfield: indicates that encryption is applied`
- `Bit 6: Key_Set subfield: 0 = Unicast, 1 = Broadcast;`
- `Bit 7: Indicates the use of compression.`
- `Compression ... The use of compression is indicated by bit 7 of the Security Control Byte` (§9.2.3.6)
- Table-45 footnote: `The Key_Set bit is not relevant and shall be set to 0 when the service-specific dedicated ciphering, the general-ded-ciphering or the general-ciphering APDUs are used.` (also restated in Table 47 footnote 1: `In the case of the general-ciphering APDU, the key-set bit of the security control byte is not relevant and shall be set to zero.`)

**Source:** `ch9-9-2` §9.2.7.2.4.2, Table 45 (p.251); §9.2.3.6 (p.227); Table 47 footnote (§9.2.7.2.4.9, p.254)

### 4.6 Invocation counter (frame counter)

- Size: `4` bytes / `32` bits; it is `the invocation field of the initialization vector` and is carried in the security header.
- `It is an integer counter which increments upon each invocation of the authenticated encryption function using the same key. When a new key is established the related invocation counter shall be reset to 0.` (Table 47)
- Full behaviour (§9.2.3.3.7.3, verbatim):
  - `Each encryption key (EK) has two invocation counters (IC) associated with it, one for the authenticated encryption function and the other for the authenticated decryption function.`
  - `when the key is established, the corresponding IC's are reset to 0`
  - `when the authenticated encryption function is used, the corresponding IC is used after which it is incremented by 1. If the maximum value of the IC has been reached, any further invocations of the authenticated encryption function shall return an error and the IC shall not be incremented.`
  - `When the authenticated decryption function is used, the value of the IC is verified. The value must be equal to or greater than the lowest acceptable value.`
  - `If the value being verified satisfies this requirement, the lowest acceptable value is set to the IC value verified plus 1 following the use of the authentication decryption function.`
  - `If the value being verified is less than the lowest acceptable value, the verification fails and so does the authenticated decryption function.`
  - `If the value being verified is equal to the maximum value, the authenticated decryption function shall return an error.`
  - `NOTE The maximum number of invocations is 2^32-1.`
  - `The bit length of the fixed field limits the number of distinct physical devices that can implement the authenticated encryption function for the given key to 2^64.`

**Source:** `ch9-9-2` §9.2.3.3.7.3 (p.216), §9.2.7.2.4.9 Table 47 (p.254)

- Error behaviour on the receiver (from the protocol spec): `Protection is not verified or removed due to invocation counter error | exception-response (state-error = service-not-allowed, service-error = invocation-counter-error) value = lowest acceptable value of invocation counter` and `Protection is not verified or removed due to deciphering error | exception-response (state-error = service-not-allowed, service-error = deciphering-error)`. **Source:** `ch9-9-4 ...\ch9-9-4-dlms-cosem-application-layer-protocol-specificat.md` (line 2336–2337, table of error handling)

### 4.7 GCM input length limits (context)

`- len(P) < 239-256 - len(A) < 264-1 - 1 < len(IV) < 264-1.` — as printed; these are superscript-mangled renderings in the converted Markdown of NIST's bounds `len(P) < 2^39 − 256`, `len(A) < 2^64 − 1`, `1 < len(IV) < 2^64 − 1` (**UNCERTAIN**: the exponents were lost in conversion; the digits `239-256`, `264-1` are literal in the file). Also: `The bit lengths of P, A and IV shall all be multiples of 8, so that these values are byte strings.` **Source:** `ch9-9-2` §9.2.3.3.7.2 (p.215)

---

## 5. Authentication-only protection (GMAC / AES-GCM without plaintext)

- GCM specialisation: `If the GCM input is restricted to data that is not to be encrypted, the resulting specialization of GCM, called GMAC, is simply an authentication mode on the input data.` and `When the input is restricted to non-confidential data, the resulting variant of GCM is called GMAC. For GMAC, the authenticated encryption and decryption functions become the functions for generating and verifying an authentication tag on the non-confidential data.` and `For the purposes of DLMS/COSEM, the GMAC algorithm as specified in 9.2.3.3.7.2 shall be used.`
- **Tag computation:** the tag is the AES-GCM/GMAC tag over AAD only; Table 46 gives, for `E=0, A=1` (`Authenticated only`): `P = –` (no plaintext; the worked example prints `Plaintext P → Null`) and `A = SC II AK II (C) I`.
- **Dependence on one output:** the outputs listed for GCM are `a ciphertext, denoted C whose bit length is the same as that of the plaintext P` and `an authentication tag, or tag, for short, denoted T.`
- **How IV/AAD differ from the ciphering case:**
  - IV: **unchanged** — still `IV = Sys-T II IC` (`Sys-T` = system title of the *originator* / the sender of the challenge), 96 bits. Worked value in Table 51 (HLS GMAC): client `4D4D4D000000000100000001`, server `4D4D4D0000BC614E01234567`.
  - AAD: **additional data is present** — in authentication-only mode the full message `(C) I` (or `SC II AK II StoC`) is *additional authenticated data*, not plaintext; there is no plaintext and no ciphertext. For suite 0's SC byte this is `10` (bit 4 only).
  - The example's `AAD = SC II AK II (C) Information` is exactly the recovered message, so a receiver verifies the tag and then takes the (unencrypted) information from the AAD.
- **Worked GMAC values present in the files:**
  - HLS GMAC (Table 51): `SC II AK II StoC = 10D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF503677524A323146`, `T = GMAC (SC II AK II StoC) = 1A52FE7DD3E72748973C1E28` (12 bytes / 96 bits), `f(StoC) = SC II IC II T = 10000000011A52FE7DD3E72748973C1E28` (17 bytes / 136 bits).
  - and `SC II AK II CtoS = 10D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF4B35366956616759`, `T (SC II AK II CtoS) = FE1466AFB3DBCD4F9389E2B7`, `f(CtoS) = SC II IC II T = 1001234567FE1466AFB3DBCD4F9389E2B7`.
  - xDLMS APDU authentication-only (Table 48): `T = 06725D910F9221D263877516`, `SH = 1001234567`, complete APDU `C81E1001234567C0010000080000010000FF020006725D910F9221D263877516` (32 bytes).
- **What is absent:** the HLS GMAC challenge-response is *not* a general-ciphering/invocation-counter-protected APDU in the same sense; nonetheless the returned value carries an IC (`f(StoC) = SC II IC II T`).

**Source:** `ch9-9-2` §9.2.3.3.7.1 (p.214), §9.2.3.3.7.2 (p.215), §9.2.3.3.5 (p.213), §9.2.7.2.4.3 Table 46 (p.251), §9.2.7.4 Tables 50–51 (p.260–261), §9.2.7.2.4.10 Table 48 (p.255)

**UNCERTAIN / NOT FOUND:** the files do not state a *separate* GMAC invocation rule set for the HLS case (e.g. whether the HLS-secret GMAC uses dedicated ICs). They show ICs `00000001` (client) and `01234567` (server) in the example without a rule tying them to `reply_to_HLS_authentication`.

---

## 6. Key derivation: the KDF, its hash, and exact context/input strings

### Algorithm

- `The NIST Concatenation KDF as specified in NIST SP 800-56A Rev. 2: 2013, 5.8.1.1 and NSA2, Clause 5 shall be used.`
- `Function call: kdf(Z, OtherInput)` — `where OtherInput consists of keydatalen and OtherInfo.`

**Source:** `ch9-9-2 ...\ch9-9-2-information-security-in-dlms-cosem.md` §9.2.3.4.6.5 (p.226)

### Exact input parameters (verbatim)

| Parameter | Statement |
|---|---|
| hashlen | `This will be 256 (for SHA-256) in the case of security suite 1 and 384 (for SHA-384) in the case of security suite 2;` |
| max_hash_inputlen | `The length shall be less than 264 bits for SHA-256 and less than 2128 bits for SHA-384.` (as printed; exponents lost in conversion — NIST: 2^64 / 2^128 — **UNCERTAIN** on exact exponent rendering) |
| H (hash) | `a hash function: SHA-256 in the case of security suite 1 and SHA-384 in the case of security suite 2.` |
| Z | `Z: a byte string that represents the shared secret z;` |
| keydatalen | `an integer that indicates the length (in bits) of the secret keying material to be generated: 128 bit for security suite 1 and 256 bit for security suite 2;` |
| OtherInfo | `A bit string equal to the following concatenation: AlgorithmID \|\| PartyUInfo \|\| PartyVInfo {\|\|SuppPubInfo}{\|\|SuppPrivInfo}` |
| AlgorithmID | `When key agreement is used to agree on the GUEK and GAK, then the algorithm ID used shall be AES-GCM-128 / AES-GCM-256. When it is used to agree on the KEK then the algorithm ID used shall be AES-WRAP-128 / AES-WRAP-256. See Table 26;` |
| SuppPubInfo | `(Optional) SuppPubInfo: A bit string containing additional, mutually known public information. Not used in DLMS/COSEM;` |
| SuppPrivInfo | `(Optional) SuppPrivInfo: A bit string containing additional, mutually known private information ... Not used in DLMS/COSEM.` |
| Output | `In DLMS/COSEM, key derivation delivers a single key for a given purpose. The length is as determined by the security suite.` |

### Table 25 — OtherInfo subfields and substrings

| Subfield / Substring | C(2e, 0s) | C(1e, 1s) | C(0e, 2s) | Length in octets | Value |
|---|---|---|---|---|---|
| AlgorithmID | Fixed | Fixed | Fixed | 7 | See Table 26 |
| PartyUinfo | Fixed | Fixed | Variable | 8+n | – |
| IDU | Fixed | Fixed | Fixed | 8 | `originator-system-title` |
| NonceU | – | – | Variable | n | `Datalen = length of transaction-id, shall be 1 octet` / `Data = value of transaction-id` |
| PartyVInfo | Fixed | Fixed | Fixed | 8 | – |
| IDV | Fixed | Fixed | Fixed | 8 | `recipient-system-title` |

Note under the table: `"originator-system-title", transaction-id" and "recipient-system-title" are the fields of the general-ciphering APDU`.

### Table 26 — Cryptographic algorithm IDs (AlgorithmID values)

| Algorithm | COSEM cryptographic algorithm ID | Encoded value |
|---|---|---|
| AES-GCM-128 | `2.16.756.5.8.3.0` | `60 85 74 05 08 03 00` |
| AES-GCM-256 | `2.16.756.5.8.3.1` | `60 85 74 05 08 03 01` |
| AES-WRAP-128 | `2.16.756.5.8.3.2` | `60 85 74 05 08 03 02` |
| AES-WRAP-256 | `2.16.756.5.8.3.3` | `60 85 74 05 08 03 03` |

Footnote: `Attention is drawn to a correction to this table where the encoded values were erroneous in versions of the Green Book prior to Ed. 8.2.`

### Which key ID is used to derive which key

- `When key agreement is used to agree on the GUEK and GAK, then the algorithm ID used shall be AES-GCM-128 / AES-GCM-256. When it is used to agree on the KEK then the algorithm ID used shall be AES-WRAP-128 / AES-WRAP-256.`
- The `Security suite` field of the worked examples is `ECDH-ECDSA-AES-GCM-128-SHA-256` (i.e. suite 1), and `Security Suite ... ECDH-ECDSA-AES-128-GCM` appears in Table 52 (name variant; **UNCERTAIN** — the file uses two different suite-1 name spellings: `ECDH-ECDSA-AES-GCM-128-SHA-256` in Table 27/Annex C and `ECDH-ECDSA-AES-128-GCM` in Table 52).

### Pseudocode / function-call forms actually present

| Scheme | Printed call form | Source |
|---|---|---|
| C(1e, 1s) | `1. Compute kdf(Z, OtherInput)` / `2. Destroy Z` | §9.2.3.4.6.3, Table 23 |
| C(2e, 0s) | `1. Compute kdf(Z, OtherInput)` / `2. Destroy Z` | §9.2.3.4.6.2, Table 22 |
| C(0e, 2s) | `1. Compute DerivedKeyingMaterial using NonceU` / `2. Destroy Z` | §9.2.3.4.6.4, Table 24 |
| C(2e, 0s) Annex C | `KDF(Z,AlgID,Sys-TC,Sys-TS)` | `chC` C.1 |
| C(1e, 1s) Annex C | `KDF(Z,AlgID,Sys-TC, Sys-TS)` GC-C ; `KDF(Z,AlgID,Sys-TS, Sys-TC)` GC-S | `chC` C.2 |
| C(0e, 2s) Annex C | `KDF(Z,AlgID,Sys-TC, Nonce-C, Sys-TS)` GC-C ; `KDF(Z,AlgID,Sys-TS, Nonce-S, Sys-TC)` GC-S | `chC` C.3 |

### Test values present in the files

- **C(2e, 0s) full vector (Annex C.1)**: `Shared Secret Z = C1CF8FE7891AEF3617D7190795E61FE6C24EFC3CCA2E08469BAD1A225CE6EA08` (32 bytes / 256 bits); `AlgorithmID AlgID = 60857405080300 // AES-GCM-128` (7 bytes); `KDF(Z,AlgID,Sys-TC,Sys-TS) = C5F4512846EDE51CFB8CCF59F08A694E002EDF66B4CB1739AC26A74E49712F46` (32 bytes / 256 bits); `Global Unicast Encryption Key GUEK = C5F4512846EDE51CFB8CCF59F08A694E` (16 bytes / 128 bits) — i.e. **the GUEK is the leading 128 bits of the 256-bit KDF output**. Source: `chC C.1 ...\channex-c-normative-use-of-key-agreement-schemes-i-c-1-ephemeral-unified-model-c-2e-0s-ecc-cdh-sche.md`
- **Annex C.2/C.3 add**: `originator-system-title: this is used as the PartyUInfo element of OtherInfo`, `recipient-system-title: this is used as the PartyVInfo element of OtherInfo`, `transaction-id: this field is used as Nonce` / `transaction-id: as required; not needed for the key derivation process`. Nonce example: `Nonce Client Nonce-C 080102030405060708 // Nonce-C is transaction-id with length` (9 bytes / 72 bits) and `080123456789012345`.
- No separate "KDF test-vector" table with expected outputs for suites 2 exists in these files.

**UNCERTAIN / NOT FOUND:** no KDF usage for deriving an *authentication key from the encryption key* (i.e. no AK = KDF(EK) construction) appears anywhere in these files; AK is either the dedicated "authentication key" held by the Security setup object (global) or has `the same rules … as for the encryption key` (§9.2.3.3.7.5), and is established by key wrapping or key agreement (Table 28). Any AK-derivation-from-EK scheme found in some implementations is **not in these files**. Also: no KEK→EK derivation in the files; KEK is only used to *wrap* other keys (AES key wrap).

---

## 7. Key wrapping / key transport

### Algorithm

- `For the purposes of DLMS/COSEM the AES key wrap algorithm shall be used; see 9.2.3.3.8.` (§9.2.3.3.6, i.e. `Symmetric key algorithms may be used to wrap (i.e., encrypt) keying material using a key-wrapping key (also known as a key encrypting key).` and `Key wrapping differs from simple encryption in that the wrapping process includes an integrity feature.`)
- `For wrapping key data DLMS/COSEM has selected the AES key wrap algorithm specified in RFC 3394. The algorithm is designed to wrap or encrypt key data. It operates on blocks of 64 bits. Before being wrapped, the key data is parsed into n blocks of 64 bits. The only restriction the key wrap algorithm places on n is that n has to be at least two.`
- `The AES key wrap can be configured to use any of the three key sizes supported by the AES codebook: 128, 192, 256.`
- `The inputs to the key wrapping process are the Key Encrypting Key KEK and the plaintext to be wrapped. The plaintext consists of n 64-bit blocks, containing the key data being wrapped. The output is the ciphertext, (n+1) 64 bit values.`
- `The inputs to the unwrap process are the KEK and (n+1) 64-bit blocks of ciphertext consisting of previously wrapped key.`
- KEK size per suite: `for security suite 0 and 1, 128 bits (16 octets): len(KEK) = 128` / `for security suite 2, 256 bits (32 octets): len(KEK) = 256.`

**Source:** `ch9-9-2` §9.2.3.3.6 (p.214), §9.2.3.3.8 (p.217)

### How a wrapped key is formed and transported

- `The algorithm is the AES key wrap algorithm specified in 9.2.3.3.8. The KEK is the master key. Consequently, this method can be used only between parties sharing the master key, i.e. between a client and a server.`
- Static keys that can be established by wrapping: `- the master key, KEK; and/or - the global unicast encryption key GUEK; and/or - the global broadcast encryption key GBEK; and/or - the (global) authentication key, GAK.`
- `To establish these static keys using key wrap, the key shall be first generated by the client, then it shall be transferred to the server by invoking the key_transfer method of the "Security setup" object … The method invocation parameter shall carry the key_id(s) and the wrapped key(s).`
- Ephemeral case: `the originator of the xDLMS APDU or the COSEM data randomly generates an ephemeral key. This key shall be wrapped using the AES key wrap algorithm and the KEK and shall be sent to the recipient together with the xDLMS APDU or the COSEM data that have been ciphered using the ephemeral key.`

**Source:** `ch9-9-2` §9.2.5.4 (p.231)

### On-the-wire form (general-ciphering key-info)

From Table 29 (`key information choices`):

- `wrapped-key` (selectable, S) — `The EK is transported using key wrapping`, with mandatory sub-fields: `kek-id` (M) and `key-ciphered-data` (M) where `master-key` (the value carried by kek-id) `Identifies the key used for wrapping the key-ciphered-data. 0 = Master Key (KEK)` and `key-ciphered-data` is `Randomly generated key wrapped with KEK`.
- `identified-key` (S) — carries `key-id`: `global-unicast-encryption-key` → `GUEK`, `global-broadcast-encryption-key` → `GBEK`.
- `agreed-key` (S) — carries `key-parameters` (`Identifier of the key agreement scheme: 0x01: C(1e, 1s ECC CDH) 0x02: C(0e,2s ECC CDH) All other reserved.`) and `key-ciphered-data` (`In the case of the C(1e, 1s, ECC CDH) scheme: the public key Qe, U, of the ephemeral key agreement key pair of party U, signed with the private digital signature key of party U.` / `In the case of the C(0e, 2s, ECC CDH) scheme: an octet-string of length zero.`)
- Legend: `M: Mandatory (part of a SEQUENCE)`, `S: Selectable (part of a CHOICE)`.
- Note: `Using key identification restricts exchanging protected xDLMS APDUs / COSEM data between a client and a server because the GUEK and the GBEK shall not be disclosed to any party other than the client and the server.`

ASN.1 (verbatim, `ch9-9-5 …\ch9-9-5-abstract-syntax-of-cosem-pdus.md`):

```asn1
Key-Id ::= ENUMERATED
{
global-unicast-encryption-key      (0),
global-broadcast-encryption-key    (1)
}
Kek-Id ::= ENUMERATED
{
master-key                         (0)
}
Identified-Key ::= SEQUENCE { key-id Key-Id }
Wrapped-Key ::= SEQUENCE { kek-id Kek-Id, key-ciphered-data OCTET STRING }
Agreed-Key ::= SEQUENCE { key-parameters OCTET STRING, key-ciphered-data OCTET STRING }
Key-Info ::= CHOICE
{
identified-key                     [0] Identified-Key,
wrapped-key                        [1] Wrapped-Key,
agreed-key                         [2] Agreed-Key
}
```

**Source:** `ch9-9-2` §9.2.5.2, Table 29 (p.230–231); `ch9-9-5` (Key-info ASN.1, lines 1030–1060)

### Which suite allows which

- The suite determines **key-transport size**, not the mechanism: Table 27 gives `AES-128 key wrap` for suites 0 and 1 and `AES-256 key wrap` for suite 2.
- Key *agreement* (the alternative to wrapping) is impossible for suite 0: Table 27 gives `–` for Key agreement on suite 0 and Table 21 gives `–` for the curve.
- `Key agreement can be used to establish static keys between a server and a client or ephemeral keys between a server and a client or a third party.` … `the One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) scheme … the Static Unified Model C(0e, 2s, ECC CDH) scheme specified in 9.2.3.4.6.4.` ; `the Ephemeral Unified Model C(2e,0s, ECC CDH) scheme can be used by the client and the server to agree on the: - master key, KEK; and/or - global unicast encryption key GUEK; and/or - global broadcast encryption key GBEK; and/or - (global) authentication key, GAK.` ; `Unless specified otherwise in a project specific companion specification, the C(1e, 1s ECC CDH) scheme shall be used.`
- Key agreement is available for suites 1 and 2 only (Table 27 lists `ECDH with P-256` / `P-384`).

**Source:** `ch9-9-2` §9.2.5.5 (p.232), §9.2.3.7 Table 27 (p.228), §9.2.3.4.2.2 Table 21 (p.219)

### Worked wrapped-key bytes present in the files

Annex C.2 (`chC ...c-2-one-pass-diffie-hellman-c-1e-1s-ecc-cdh-sche.md`): key-ciphered-data length `8180` (= 128 bytes, BER long-form length) with value `C323C2BD45711DE4688637D919F92E9DB8FB2DFC213A88D21C9DC8DCBA917D8170511DE1BADB360D50058F794B0960AE11FA28D392CFF907A62D13E3357B1DC0B51BE089D0B682863B2217201E73A1A9031968A9B4121DCBC3281A69739AF87429F5B3AC5471E7B6A04A2C0F2F8A25FD772A317DF97FC5463FEAC248EB8AB8BE` for a **C(1e, 1s)** agreed key, and the corresponding `ciphered-content` `81EB3100000000F4350696…D2ADFAA7` (235 bytes).

**UNCERTAIN / NOT FOUND:** the files do **not** contain a complete worked **AES-key-wrap (RFC 3394)** input/output vector (no "KEK + key data → wrapped key" test vector). The only wrapped-key bytes present are the `key-ciphered-data` of *agreed-key* (a signed ephemeral public key for C(1e,1s)), not an RFC 3394 wrap example. There is also no statement that wrapping is restricted to suites ≠ 0.

---

## 8. Security header format and protection of the xDLMS APDU (byte layout + worked example)

### 8.1 Component sizes (from the document's own tables/figures)

| Field | Size | Contents | Source |
|---|---|---|---|
| APDU tag | 1 octet | ciphered-APDU tag, e.g. `general-ciphering` = `[221]` = `DD`, `glo-get-request` = `[200]` = `C8` | `ch9-9-5` (lines 71–97) |
| Length | 1 octet (short form) or 2+ octets (long form, `81 xx` / `82 xx xx`) | length of the following value | derived from the examples below (**UNCERTAIN** as an explicit rule; no A-XDR length-encoding rule is stated in these files) |
| Security Header `SH` | 5 octets (SC 1 + IC 4) | `SH = SC II IC` | §9.2.7.2.4.2 + Table 48 |
| Security control byte `SC` | 1 octet | see §4.5 above | Table 45 |
| Invocation counter `IC` | 4 octets (32 bits) | big-endian integer counter | §9.2.3.3.7.3, Table 48 |
| Ciphertext / unprotected APDU | same length as P | only when E=1 | Table 46 |
| Authentication tag `T` | 12 octets (96 bits) | only when A=1 | §9.2.3.3.7.6 |

### 8.2 Per-APDU-type layouts (verbatim from the figures' reconstructed text)

- Service-specific glo-/ded-ciphering: `Tag | Len | SH | (C) I [| T]` and — for the non-general types — there is **no** system-title, transaction-id, date-time, other-information or key-info field:
  - `Authentication only: SC-A II (C) Information II T` with `AAD = SC II AK II (C) Information`
  - `Encryption only: SC-E II Ciphertext` with `AAD = null`
  - `Encrypted and authenticated: SC-AE II Ciphertext II T` with `AAD = SC II AK`
- general-glo-ciphering / general-ded-ciphering: outer structure `Tag | system-title | ciphered-content` (ASN.1: `General-Glo-Ciphering ::= SEQUENCE { system-title OCTET STRING, ciphered-content OCTET STRING }`, `General-Ded-Ciphering` identical), and `ciphered-content` = `SH | (Compressed) APDU [| T]` with the SC values named `SC-C`, `SC-A/SC-CA`, `SC-E/SC-CE`, `SC-EA/SC-CEA` in the figure.
- general-ciphering: outer structure `Tag | transaction-id | originator-system-title | recipient-system-title | date-time | other-information | key-info | ciphered-content`, with the note `All fields are A-XDR encoded OCTET STRINGs.` / `The length and the value of each field is included in the AAD.` and `ciphered-content` = `SH | (Compressed) APDU [| T]`.
- general-signing: ASN.1 `General-Signing ::= SEQUENCE { transaction-id, originator-system-title, recipient-system-title, date-time, other-information, content, signature }` — no security header, no tag; `signature` carries the ECDSA signature.

**Source:** `ch9-9-2` §9.2.7.2.4.6–9.2.7.2.4.8 (p.252–254, Figures 107–109), §9.2.7.2.5 (p.259); `ch9-9-5` (General-Ciphering/General-Signing ASN.1, lines 700–733)

Table 47 additionally records, per APDU family, which fields exist (`+` present / `–` absent / `Service specific` / tag numbers `[219] [220] [221]`), and the meaning of `security control byte` and `Invocation counter` (quoted in §4.5/§4.6 above).

### 8.3 Worked example — Table 48 (`glo-get-request`, suite 0, unicast)

Security material (verbatim from the table):

| Field | Value | LEN (bytes) | bits |
|---|---|---|---|
| Security suite | `GCM-AES-128` | | |
| `System Title` `Sys-T` | `4D4D4D0000BC614E` (`here, the five last octets contain the manufacturing number in hexa`) | 8 | 64 |
| `Invocation counter` `IC` | `01234567` | 4 | 32 |
| `Initialization Vector` `IV` | `Sys-T II IC` → `4D4D4D0000BC614E01234567` | 12 | 96 |
| `Block cipher key (global)` `EK` | `000102030405060708090A0B0C0D0E0F` | 16 | 128 |
| `Authentication Key` `AK` | `D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF` | 16 | 128 |
| SC (unicast key) | `SC-A = 10`, `SC-E = 20`, `SC-AE = 30` | 1 | 8 |
| Security header `SH` | `1001234567` / `2001234567` / `3001234567` | 5 | 40 |
| APDU to be protected | `C0010000080000010000FF0200` (`Get-request, attribute 2 of the Clock object`) | 13 | 104 |
| P | `Null` / `C0010000080000010000FF0200` / same | 13 | 104 |
| A | `SC II AK II APDU` / `–` / `SC II AK` | | |
| A-A | `10D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFC0010000080000010000FF0200` | 30 | 240 |
| A-E | `–` | 0 | 0 |
| A-AE | `30D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF` | 17 | 136 |
| C | `NULL` / `411312FF935A47566827C467BC` / same | 13 | 104 |
| T | `06725D910F9221D263877516` / `–` / `7D825C3BE4A77C3FCC056B6B` | 12 | 96 |
| Complete ciphered APDU | `TAG II LEN II SH II APDU II T` / `TAG II LEN II SH II C` / `TAG II LEN II SH II C II T` | – | – |
| Authenticated APDU | `C81E1001234567C0010000080000010000FF020006725D910F9221D263877516` | 32 | 256 |
| Encrypted APDU | `C8122001234567411312FF935A47566827C467BC` | 20 | 160 |
| Authenticated and encrypted APDU | `C81E3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B` | 32 | 256 |

Footnote: `In this example the value of the invocation counter is 01234567. In the real life, the value shall be incremented with each invocation of the AES-GCM algorithm.`

### 8.4 Byte offsets derived from the Table 48 examples (derived, not printed)

| APDU | Tag@0 | Len@1 | SH@2..6 | payload@7.. | Tag `T` |
|---|---|---|---|---|---|
| `glo-get-request` authenticated (32 B) | `C8` | `1E` (=30) | `1001234567` | APDU `C0010000080000010000FF0200` (13 B) @7..19 | `06725D910F9221D263877516` @20..31 |
| `glo-get-request` encrypted (20 B) | `C8` | `12` (=18) | `2001234567` | C @7..19 | – |
| `glo-get-request` auth+enc (32 B) | `C8` | `1E` (=30) | `3001234567` | C @7..19 | `7D825C3BE4A77C3FCC056B6B` @20..31 |
| `general-ciphering` (Annex C.2, 401 B) | `DD` | `08` (`DD 08` + 8-byte transaction-id starts the SEQUENCE) | inside `ciphered-content` after `…01018180C3…` | – | – |

- Consistency check: `LEN = 1 + 4 + 13 + 12 = 30 = 0x1E` for the authenticated case, and `1 + 4 + 13 = 18 = 0x12` for the encrypted-only case. **The `Len` field therefore counts from the SC byte through the end of the tag, excluding the tag and Len bytes themselves.** (Derived; the document never states this rule in words.)

**Verbatim general-ciphering APDU (Annex C.2, C(1e,1s) ACCESS.request):** `DD080102030405060708084D4D4D0000BC614E084D4D4D00000000010000010201018180C323C2BD45711DE4688637D919F92E9DB8FB2DFC213A88D21C9DC8DCBA917D8170511DE1BADB360D50058F794B0960AE11FA28D392CFF907A62D13E3357B1DC0B51BE089D0B682863B2217201E73A1A9031968A9B4121DCBC3281A69739AF87429F5B3AC5471E7B6A04A2C0F2F8A25FD772A317DF97FC5463FEAC248EB8AB8BE81EB3100000000F435069679270C5BF4425EE5777402A6C8D51C620EED52DBB188378B836E2857D5C053E6DDF27FA87409AEF502CD9618AE47017C010224FD109CC0BEB21E742D44AB40CD11908743EC90EC8C40E221D517F72228E1A26E827F43DC18ED27B5F458D66508B05A2A4CC6FED178C881AFC3BC67064689BE8BB41C80ABB3C114A31F4CB03B8B64C7E0B4CE77B2399C93347858888F92239713B38DF01C4858245827A92EF334172EA636B31CBBDF2A96AD5D035F66AA38F1A2D97D4BBA99622E6B5F18789CECB2DFB3937D9F3E17F8B472098E6563238F37528374809836002AEA6E7012D2ADFAA7` (`401` bytes) — within `ciphered-content`: `81EB` (length 235) then `3100000000` (SC `31`, suite 1, A+E, IC `00000000`) + ciphertext + 12-byte tag, i.e. `3100000000F435069679270C5BF4425EE5777402A6C8D51C620EED52DBB188378B836E2857D5C053E6DDF27FA87409AEF502CD9618AE47017C010224FD109CC0BEB21E742D44AB40CD11908743EC90EC8C40E221D517F72228E1A26E827F43DC18ED27B5F458D66508B05A2A4CC6FED178C881AFC3BC67064689BE8BB41C80ABB3C114A31F4CB03B8B64C7E0B4CE77B2399C93347858888F92239713B38DF01C4858245827A92EF334172EA636B31CBBDF2A96AD5D035F66AA38F1A2D97D4BBA99622E6B5F18789CECB2DFB3937D9F3E17F8B472098E6563238F37528374809836002AEA6E7012D2ADFAA7` (**note the SC byte here is `0x31`, not `0x30`**, because suite Id 1 occupies bits 3..0).

**Source for §8.3–§8.4:** `ch9-9-2` §9.2.7.2.4.10, Table 48 (p.255–259) and Table 49 (p.257–258); `chC C.2` (line 113).

**UNCERTAIN / NOT FOUND:** (a) the files never give a byte-offset table or explicitly state the `Len` semantics; §8.4 is a derivation from the printed hex lengths. (b) The `tag` numbers `[219] [220] [221]` are given (Table 47) and the ASN.1 gives `general-glo-ciphering [219]`, `general-ded-ciphering [220]`, `general-ciphering [221]`, `general-signing [223]`, plus all the glo-/ded- service-specific tags, but the mapping of those tags to the encoded octet values (`0xC8`, `0xDD`, …) is a BER consequence, not stated in these files. (c) No worked `general-ded-ciphering` / `general-glo-ciphering` / `general-signing` hex example appears in these files.

---

## 9. Classical authentication mechanisms (suite 0 in practice): LLS, HLS and variants

### "No security suite" / suite 0 — what it is in practice

- Suite 0 = `AES-GCM-128` + `AES-128 key wrap` only; **no hash, no ECDSA, no ECDH, no compression** (Table 27 dashes; Table 21 `Suite 0 – –`).
- Suite 0 does **not** mean "no protection": it means symmetric-only protection. `AES-GCM-128` provides `authentication and encryption` and 96-bit tags; classical (non-GCM) mechanisms MD5/SHA-1 HLS also fall outside the suites.
- **Authentication mechanisms are independent of the security suite and of message security:** `The security of the message exchange (in Phase 2) is independent of the client-server authentication during AA establishment (Phase 1). Even in the case where no client-server authentication takes place, cryptographically protected APDUs can be used to ensure message security.`

**Source:** `ch9-9-2` §9.2.3.7 Table 27 (p.228), §9.2.2.2.2.1 (p.205)

### The three mechanisms

1. **No security (Lowest Level Security)** — `This authentication mechanism does not require any authentication; the client can access the COSEM object attributes and methods within the security context and access rights prevailing in the given AA.` Identifier `mechanism_id(0)`. In COSEM-OPEN: `in the case of Lowest Level Security authentication it shall not be present; only the Kernel functional unit is used` (referring to ACSE_Requirements). `NOTE 3 In pre-established AAs no authentication takes place.`
2. **LLS** — `the server requires that the client authenticates itself by supplying a password that is known by the server. The password is held by the current "Association SN / LN" object modelling the AA to be established. The "Association SN / LN" objects provide means to change the secret.` … `the client transmits a "secret" (a password) to the server, using the COSEM-OPEN.request service primitive;`. Identity `mechanism_id(1)`; COSEM-OPEN `ACSE_Requirements … shall indicate authentication (bit 0 set)`. **Keys involved: a shared secret only — a password / LLS secret, not a cryptographic key.**
3. **HLS** — `both the client and the server have to successfully authenticate themselves to establish an AA. HLS authentication is a four-pass process that is supported by the COSEM-OPEN service and the reply_to_HLS_authentication method of the "Association SN / LN" interface class`: Pass 1 `The client transmits a "challenge" CtoS and – depending on the authentication mechanism – additional information to the server`; Pass 2 `The server transmits a "challenge" StoC and – depending on the authentication mechanism – additional information to the client` (with `If StoC is the same as CtoS, the client shall reject it and shall abort the AA establishment process.`); Pass 3 `The client processes StoC … and sends the result to the server`; Pass 4 `The server processes then CtoS …`.

**Source:** `ch9-9-2` §9.2.2.2.2.2–§9.2.2.2.2.4 (p.207); `ch9-9-3 ...\ch9-9-3-dlms-cosem-application-layer-service-specificati.md` §9.3.2 (line 219–236)

### The HLS variants, their "2-pass/4-pass" nature and the keys involved

All HLS variants are **four-pass**: challenges are exchanged in AARQ (Pass 1) and AARE (Pass 2), then the responses in Pass 3 (client) and Pass 4 (server) via `reply_to_HLS_authentication`. **There is no separate "2-pass HLS" mechanism in these files.**

Table 50 — DLMS/COSEM HLS authentication mechanisms (verbatim formulae; `II` = concatenation):

| mechanism_id | Name | Pass 1 C→S | Pass 2 S→C | Pass 3 C→S `f(StoC)` | Pass 4 S→C `f(CtoS)` |
|---|---|---|---|---|---|
| 2 | `HLS man. Spec.` | `CtoS: Random string 8-64 octets` | `StoC: Random string 8-64 octets` | `Man. Spec.` | `Man. Spec.` |
| 3 | `HLS MD5` | ditto | ditto | `MD5(StoC \|\| HLS Secret)` | `MD5(CtoS \|\| HLS Secret)` |
| 4 | `HLS SHA-1` | ditto | ditto | `SHA-1(StoC \|\| HLS Secret)` | `SHA-1(CtoS \|\| HLS Secret)` |
| 5 | `HLS GMAC` | `CtoS: Random string 8-64 octets` optionally `System-Title-C in calling-AP-title` | `StoC: Random string 8-64 octets` optionally `System-Title-S in responding-AP-title` | `SC \|\| IC \|\| GMAC (SC \|\| AK \|\| StoC)` | `SC \|\| IC \|\| GMAC (SC \|\| AK \|\| CtoS)` |
| 6 | `HLS SHA-256` | ditto (mechanism 5's CtoS row) | ditto | `SHA-256 (HLS_Secret \|\| SystemTitle-C \|\| SystemTitle-S \|\| StoC \|\| CtoS)` | `SHA-256 (HLS_Secret \|\| SystemTitle-S \|\| SystemTitle-C \|\| CtoS \|\| StoC)` |
| 7 | `HLS ECDSA` | `CtoS: Random string 32 to 64 octets` optionally `System-Title-C in calling-AP-title, Cert-Sign-Client in calling-AE-qualifier` | `StoC: Random string 32 to 64 octets` optionally `System-Title-S in responding-AP-title, Cert-Sign-Server responding-AE-qualifier` | `ECDSA( SystemTitle-C \|\| SystemTitle-S \|\| StoC \|\| CtoS)` | `ECDSA( SystemTitle-S \|\| SystemTitle-C \|\| CtoS \|\| StoC)` |

Notes verbatim: `NOTE 1 With mechanism_id(2), the method of processing the challenge is secret.` and `NOTE 2 The use of authentication mechanisms 3 and 4 are not recommended for new implementations.` and `NOTE The system titles and the Certificates have to be sent only if not already known by the other party.`

**Keys involved:**
- Mechanisms 3, 4, 6 use the **HLS secret** (`HLS Secret` / `HLS_Secret`): `In some HLS authentication mechanisms, the processing of the challenges involves the use of an HLS secret.` The `"Association SN / LN" interface class provides a method to change the HLS "secret": change_HLS_secret.`
- Mechanism 5 (GMAC) uses the **authentication key AK** as AAD together with the security control byte, and returns `SC || IC || tag` — i.e. it uses suite-appropriate symmetric material (for suite 0 that AK is 128-bit; example AK `D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF`).
- Mechanism 7 (ECDSA) uses the **digital signature key pair** and certificates (`Cert-Sign-Client` / `Cert-Sign-Server` carried in `calling-AE-qualifier` / `responding-AE-qualifier`), curve P-256 (suite 1) or P-384.
- Mechanisms 3/4 hash the secret with the challenge; note the direction-specific order (`StoC || HLS Secret` vs `CtoS || HLS Secret`), while mechanism 6 prepends the secret and includes both system titles and both challenges.

**Source:** `ch9-9-2` §9.2.7.4, Table 50 (p.260–261); §9.2.2.2.2.4 (p.207); `ch9-9-4` §9.4.2.2.3 Table 83 (p.313) for the names.

### Worked HLS examples

- **Table 51 (mechanism 5, GMAC)** — full vector, quoted in §5 above; security suite field reads `GCM-AES-128`; `CtoS = 4B35366956616759 "K56iVagY"`, `StoC = 503677524A323146 "P6wRJ21F"` (8 octets each, within the documented `8-64 octets` range).
- **Table 52 (mechanism 7, ECDSA)** — `Security Suite ECDH-ECDSA-AES-128-GCM`, `Curve P-256`, `System Title Client 4D4D4D0000BC614E`, `System Title Server 4D4D4D0000000001`, `Private Key Client E9A045346B2057F1820318AB125493E9AB36CE590011C0FF30090858A118DD2E` (32 B), `Private Key Server B582D8C910018302BA3131BAB9BB6838108BB9408C30B2E49285985256A59038` (32 B), 64-byte public keys as `FE2OS(xp)II FE2OS(yp)`, 32-byte challenges, 64-byte signatures. Note: Table 52's system titles are **swapped** relative to Table 51 (Table 51's server is `4D4D4D0000BC614E`; Table 52's *client* is `4D4D4D0000BC614E` and its *server* is `4D4D4D0000000001`) — this is what the file says.

**UNCERTAIN / NOT FOUND:** no "2-pass HLS" variant is defined anywhere in these files; the four-pass structure is the only one described. `mechanism_id(2)`'s challenge processing is explicitly secret/out of scope (`Man. Spec.`). The files do not state that MD5/SHA-1 HLS are "deprecated" using that word here — they say `not recommended for new implementations`, which is the definition given for **deprecated** in `ch3-3-2`: `deprecated — not recommended for new implementations`.

---

## 10. Mandatory / optional, deprecation, backward compatibility

| Statement | Source |
|---|---|
| `The DLMS/COSEM security suites – see Table 27 – are based on NSA Suite B` (no suite declared mandatory or optional anywhere in §9.2) | §9.2.3.7 |
| `All other reserved` for suite Ids other than 0/1/2 | Table 27 |
| Suite Id is carried in `Bit 3…0: Security_Suite_Id`, so only 16 values can be encoded, of which 0–2 are defined | Table 45 |
| `NOTE 2 The use of authentication mechanisms 3 and 4 are not recommended for new implementations.` | §9.2.7.4 Table 50; and `ch9-9-4` §9.4.2.2.3 Table 83 (`NOTE 2 The use of authentication mechanisms 3 and 4 are not recommended for new implementations.`) |
| `deprecated — not recommended for new implementations` (definition of *deprecated*) | `ch3-3-2 ...\ch3-3-2-definitions-related-to-cryptographic-security.md` (p.27) |
| `This Technical Report specifies minimum requirements. Project specific companion specifications may specify more strict requirements, for example a field specified in this Technical Report as optional may be made mandatory or an extension designated as non-critical may be designated as critical.` | §9.2.6.4.1 |
| `m (mandatory): the field must be filled` / `o (optional): the field is optional` | §9.2.6.4.1 |
| `Every DLMS server must use X.509 v3 format and contain either: - aP-256 or P-384 ECDSA-capable signing key; or - aP-256 or P-384 ECDH-capable key agreement key.` | §9.2.6.5 (note the file's typo `aP-256`) |
| `Depending on the security policy, the following X.509 v3 certificates shall be handled by DLMS/COSEM end entities` | §9.2.6.5 |
| `Unless specified otherwise in a project specific companion specification, the C(1e, 1s ECC CDH) scheme shall be used.` | §9.2.5.5 |
| `In DLMS/COSEM none of the services or options are mandatory: the ones to be used are negotiated via the COSEM-OPEN service` … conformance bit 1 = `general-protection`, with `-- The actual list of general protection services depends on the security suite` | `ch9-9-4` §9.4.6.1 (p.322) + Table 85; `ch9-9-5` `Conformance` ASN.1 |
| `-- The actual list of general protection services depends on the security suite` | `ch9-9-5 ...\ch9-9-5-abstract-syntax-of-cosem-pdus.md` (line 274) |
| `Ciphered xDLMS APDUs can be used in a ciphered application context only. On the other hand, in a ciphered application context, both ciphered and unciphered APDUs may be used.` | §9.2.7.2.3 |
| `Attention is drawn to a correction to this table where the encoded values were erroneous in versions of the Green Book prior to Ed. 8.2.` (about Table 26 algorithm IDs) | §9.2.3.4.6.5, Table 26 |
| `For older versions, see their specification in DLMS UA 1000-1, the "Blue Book".` (about Association LN ver 3 / SN ver 4 access rights) | §9.2.7.2.2 |
| `The use of compression is indicated by bit 7 of the Security Control Byte` — compression is optional and per-APDU | §9.2.3.6 |
| Backward compatibility, but **only about ACSE, not security**: `In ISO/IEC 15954, protocol-version is mandatory in the AARQ and optional in the AARE. In DLMS/COSEM it is kept as mandatory for backward compatibility;` | `ch9-9-4` (line 171) |
| `NOTE 3 In pre-established AAs no authentication takes place.` | §9.2.2.2.2.1 |

**UNCERTAIN / NOT FOUND:** the chapter never declares a *default* mandatory security suite, and never uses the word "deprecated" for a suite or for a security level. There is **no** statement that suite 0 is legacy/optional or that suites 1/2 are mandatory. The word `deprecated` appears only in the definitions file (`ch3-3-2`), and its practical application in these files is the "not recommended for new implementations" note on authentication mechanisms 3 (MD5) and 4 (SHA-1).

---

## Summary of explicit gaps in these files

1. No enumerated "security level" type with numeric codes (NONE/AUTHENTICATION/ENCRYPTION/AUTHENTICATION_ENCRYPTION); only the SC A/E bits, the "Three authentication security levels", and the security-policy bit map.
2. Security policy version 0 values are delegated to the Blue Book (`DLMS UA 1000-1 Part 2 Ed.15:2021, 5.4.8`) and are not present.
3. No explicit rule pairing security levels with suites; only per-suite algorithm capabilities (Table 27 / Table 21).
4. No worked AES key wrap (RFC 3394) test vector; the only wrapped-key bytes are `agreed-key` ephemeral public keys.
5. No `general-glo-ciphering` / `general-ded-ciphering` / `general-signing` hex example.
6. No byte-offset table; offsets in §8.4 are derived from the printed lengths of Table 48.
7. No A-XDR/BER length-encoding rule in these files (the `Len` semantics in §8.4 are derived).
8. Superscript exponents in §9.2.3.3.7.2 and §9.2.3.4.6.5 were lost in conversion (`239-256`, `264-1`, `2128`), so those length limits are quoted as-printed and flagged UNCERTAIN.
