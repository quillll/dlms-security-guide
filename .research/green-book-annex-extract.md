# DLMS/COSEM security suites: ECC curves, certificates, key agreement, and the configuring interface classes

Extraction from local Green Book Ed. 11 and Blue Book Ed. 17 Part 2 Markdown conversions.
Every fact below is taken from the listed files; nothing is supplied from memory of the standards.
Where the files do not support a claim it is marked **UNCERTAIN / NOT FOUND**.

Source files used (absolute paths):

| Label used in `Source:` lines | Absolute path |
|---|---|
| `channex-a-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\channex-a-normative-nsa-suite-b-elliptic-curves-an\markdown\channex-a-normative-nsa-suite-b-elliptic-curves-an-annex-a-normative-nsa-suite-b-elliptic-curves-an.md` |
| `channex-b-…-b-1-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\channex-b-informative-example-of-an-root-ca-and-en\markdown\channex-b-informative-example-of-an-root-ca-and-en-b-1-fields-of-public-key-certificates.md` |
| `channex-b-…-b-2-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\channex-b-informative-example-of-an-root-ca-and-en\markdown\channex-b-informative-example-of-an-root-ca-and-en-b-2-example-of-a-root-ca-certificate-using-p-256.md` |
| `channex-b-…-b-3-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\channex-b-informative-example-of-an-root-ca-and-en\markdown\channex-b-informative-example-of-an-root-ca-and-en-b-3-example-of-an-end-entity-digital-signature-c.md` |
| `channex-c-…-c-1-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\channex-c-normative-use-of-key-agreement-schemes-i-c-1-ephemeral-unified-model-c-2e-0s-ecc-cdh-sche.md` |
| `channex-c-…-c-2-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\channex-c-normative-use-of-key-agreement-schemes-i-c-2-one-pass-diffie-hellman-c-1e-1s-ecc-cdh-sche.md` |
| `channex-c-…-c-3-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\channex-c-normative-use-of-key-agreement-schemes-i-c-3-static-unified-model-c-0e-2s-ecc-cdh-scheme.md` |
| `ch9-9-2-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md` |
| `ch9-9-3-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-3-dlms-cosem-application-layer-service-specificati.md` |
| `ch9-9-4-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-4-dlms-cosem-application-layer-protocol-specificat.md` |
| `ch9-9-5-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-5-abstract-syntax-of-cosem-pdus.md` |
| `ch2-2-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\ch2\markdown\ch2-2-normative-references.md` |
| `ch3-3-2-….md` | `D:\project\personal\dlms\GreenBook\output\book\ai\ch3\markdown\ch3-3-2-definitions-related-to-cryptographic-security.md` |
| `ch4-4-4-….md` (BB v2 AI) | `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md` |
| `ch5-5-4-….md` (BB v2 AI) | `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch5\markdown\ch5-5-4-previous-versions-of-interface-classes-for-acces.md` |
| `ch6-6-2-….md` (BB v2 AI) | `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch6\markdown\ch6-6-2-abstract-cosem-objects.md` |
| `Blue-Book-Ed-17-part-2-V1.0.md` | `D:\project\personal\dlms\GreenBook\output\blue-book\human\Blue-Book-Ed-17-part-2-V1.0.md` |

Note on rendering: the Markdown conversions of Annex C and of Tables 22–24 have OCR/line-wrapping artefacts. Where a quote is unavoidably garbled, that is flagged inline. Tables below reproduce the file content; superscripts (`2^224`) are conventional mathematical notation where the source lost formatting.

---

## 1. Annex A (normative) – NSA Suite B elliptic curves and domain parameters

### 1.1 What Annex A contains

Annex A is a normative annex titled "NSA Suite B elliptic curves and domain parameters". It contains **only domain parameters for two curves** – it does **not** assign a DLMS security-suite number and does **not** mention any DLMS suite id.

> `Domain parameters D for ECC schemes are of the form: (q, FR, a, b{, SEED}, G, n, h), where q is the field size; FR is an indication of the basis used; a and b are two field elements that define the equation of the curve; SEED is an optional bit string that is included if the elliptic curve was randomly generated in a verifiable fashion; G is a generating point consisting of (xG, yG) of prime order on the curve; n is the order of the point G; and h is the cofactor`
>
> `Suite B requires the use of one of the following two sets of domain parameters, see Table A. 1 and Table A. 2`

Source: `channex-a-….md` §Annex A, p.582 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-a-normative-nsa-suite-b-elliptic-curves-an\markdown\channex-a-normative-nsa-suite-b-elliptic-curves-an-annex-a-normative-nsa-suite-b-elliptic-curves-an.md`

The annex also carries a provenance note: `NOTE This information is reproduced from NSA2.` (same source and section; `NSA2` is defined in ch2 as `Suite B Implementer's Guide to NIST SP800-56A, 28th July 2009`).

Source: `ch2-2-….md` §2 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch2\markdown\ch2-2-normative-references.md`

### 1.2 Table A.1 – `ECC_P256_Domain_Parameters`

| Parameter | Symbol | Value (verbatim, spaces as in source) |
|---|---|---|
| Field size | q | `FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF` (`=2^224(2^32-1)+2^192+2^96-1`, source renders as `=(2224(232-1)+2192+296-1`) |
| Field representation indicator | FR | `NULL` |
| Curve parameter | a | `FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC` |
| Curve parameter | b | `5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B` |
| Seed used to generate parameter b | SEED | `C49D3608 86E70493 6A6678E1 139D26B7 819F7E90` |
| x-coordinate of base point G | xG | `6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296` |
| y-coordinate base point G | yG | `4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5` |
| Order of point G | n | `FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551` |
| Cofactor | h | `1` |

Source: `channex-a-….md` §Annex A, Table A.1, p.582 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-a-normative-nsa-suite-b-elliptic-curves-an\markdown\channex-a-normative-nsa-suite-b-elliptic-curves-an-annex-a-normative-nsa-suite-b-elliptic-curves-an.md`

### 1.3 Table A.2 – `ECC_P384_Domain_Parameters`

| Parameter | Symbol | Value (verbatim) |
|---|---|---|
| Field size | q | `FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFF` (`=2^384-2^128-2^96+2^32-1`, source renders as `=2384-2128-296+232-1`) |
| Field representation indicator | FR | `NULL` |
| Curve parameter | a | `FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFC` |
| Curve parameter | b | `B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 0314088F 5013875A C656398D 8A2ED19D 2A85C8ED D3EC2AEF` |
| Seed used to generate parameter b | SEED | `A335926A A319A27A 1D00896A 6773A482 7ACDAC73` |
| x-coordinate of base point G | xG | `AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98 59F741E0 82542A38 5502F25D BF55296C 3A545E38 72760AB7` |
| y-coordinate base point G | yG | `3617DE4A 96262C6F 5D9E98BF 9292DC29 F8F41DBD 289A147C E9DA3113 B5F0B8C0 0A60B1CE 1D7E819D 7A431D7C 90EA0E5F` |
| Order of point G | n | `FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C7634D81 F4372DDF 581A0DB2 48B0A77A ECEC196A CCC52973` |
| Cofactor | h | `1` |

Source: `channex-a-….md` §Annex A, Table A.2, p.582 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-a-normative-nsa-suite-b-elliptic-curves-an\markdown\channex-a-normative-nsa-suite-b-elliptic-curves-an-annex-a-normative-nsa-suite-b-elliptic-curves-an.md`

### 1.4 Key sizes / field sizes stated in Annex A

* P-256: field size `q` is 256 bits (8 × 32-bit words); cofactor `h = 1`.
* P-384: field size `q` is 384 bits (12 × 32-bit words); cofactor `h = 1`.
* Annex A states no other key sizes, no symmetric key sizes, and no algorithm list.

**UNCERTAIN / NOT FOUND** in Annex A: any statement about which DLMS security suite these curves belong to, any "NSAA" naming, any AES/SHA key sizes.

### 1.5 How Annex A maps onto the DLMS security suites

Annex A itself gives no mapping. The mapping is in Green Book 9.2.3.4.2.2 (Table 21) and 9.2.3.7 (Table 27):

> `FIPS PUB 186-4:2013 recommends five prime field elliptic curves over a prime field GF(p). Of these, the curves P-256 and P-384 have been selected for DLMS/COSEM as shown in Table 21.`

Table 21 – "Elliptic curves in DLMS/COSEM security suites":

| DLMS security suite | Curve name in FIPS PUB 186-4:2013 | ASN.1 Object Identifier |
|---|---|---|
| `Suite 0` | `–` | `–` |
| `Suite 1` | `NIST curve P-256` | `1.2.840.10045.3.1.7` |
| `Suite 2` | `NIST curve P-384` | `1.3.132.0.34` |

> `NOTE The ASN.1 Object Identifier appears in the Certificate under AlgorithmIdentifier: Parameters. See 9.2.6.4.2.`

Source: `ch9-9-2-….md` §9.2.3.4.2.2, Table 21, p.219 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

Table 27 – "DLMS/COSEM security suites" (suite ids 0/1/2 only):

| Security Suite Id | Security suite name | Authenticated encryption | Digital signature | Key agreement | Hash | Key-transport | Compression |
|---|---|---|---|---|---|---|---|
| `0` | `AES-GCM-128` | `AES-GCM-128` | `–` | `–` | `–` | `AES-128 key wrap` | `–` |
| `1` | `ECDH-ECDSA-AES-GCM-128-SHA-256` | `AES-GCM-128` | `ECDSA with P-256` | `ECDH with P-256` | `SHA-256` | `AES-128 key wrap` | `V.44` |
| `2` | `ECDH-ECDSA-AES-GCM-256-SHA-384` | `AES-GCM-256` | `ECDSA with P-384` | `ECDH with P-384` | `SHA-384` | `AES-256 key wrap` | `V.44` |
| `All other reserved` | `–` | `–` | `–` | `–` | `–` | `–` | `–` |

Source: `ch9-9-2-….md` §9.2.3.7, Table 27, p.228 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

Relation to "NSA Suite B" naming:

> `The DLMS/COSEM security suites – see Table 27 – are based on NSA Suite B and include cryptographic algorithms for authentication, encryption, key agreement, digital signature and hashing specifically:`
> `- authentication and encryption: the Advanced Encryption Standard (AES) shall be used as specified in FIPS PUB 197, with key sizes of 128 and 256 bits. AES shall be used with the Galois/Counter Mode (GCM) of operation specified in NIST SP 800-38D:2007;`
> `- digital signature: the Elliptic Curve Digital Signature Algorithm (ECDSA) shall be used as specified FIPS PUB 186-4:2013 and in NSA1, using the curves P-256 or P-384;`
> `- key agreement: the Ephemeral Unified Model C(2e, 0s, ECC CDH) scheme … the One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) scheme … and the Static Unified Model C(0e, 2s, ECC CDH) scheme … shall be used using the elliptic curves P-256 or P-384.`
> `- hashing: the Secure Hash Algorithms (SHA) SHA-256 and SHA-384 shall be used as specified in FIPS PUB 180-4:2012.`

Source: `ch9-9-2-….md` §9.2.3.7, p.228 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

Green Book 9.2.6.5 is titled `Suite B end entity certificate types to be supported by DLMS servers`:

> `Every DLMS server must use X.509 v3 format and contain either: - a P-256 or P-384 ECDSA-capable signing key; or - a P-256 or P-384 ECDH-capable key agreement key.`
> `Every certificate must be signed using ECDSA. The signing CA's key must be P-256 or P-384 if the certificate contains a key on P-256. The signing CA's key must be P-384 if the certificate contains a key on P-384.`

Source: `ch9-9-2-….md` §9.2.6.5, p.243 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

The three NSA documents referenced (Green Book 9.2.6.3.1, p.233) are:

* `NSA1` — `Suite B Implementer's Guide to FIPS 186-3 (ECDSA), Feb 3rd 2010`
* `NSA2` — `Suite B Implementer's Guide to NIST SP800-56A, 28th July 2009`
* `NSA3` — `NSA Suite B Base Certificate and CRL Profile, 27th May 2008`

and 9.2.6.3.1 states the certificate profile `is based on … NSA3 specifying the NSA Suite B Base Certificate and CRL Profile.`

Source: `ch2-2-….md` §2 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch2\markdown\ch2-2-normative-references.md`; and `ch9-9-2-….md` §9.2.6.3.1, p.233 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

**UNCERTAIN / NOT FOUND**: the string `NSAA` (or any spelling of it) does not occur in any of the searched files. The only Suite-B-related acronyms found are `NSA1`, `NSA2`, `NSA3`, and the phrase `NSA Suite B`.

---

## 2. Annex C (normative) – use of the key-agreement schemes in DLMS/COSEM

### 2.0 Shared framework (from Green Book 9.2.3.4.6)

> `For DLMS/COSEM three elliptic curve key agreement schemes have been selected from NIST SP 800-56A Rev. 2: 2013: - the Ephemeral Unified Model C(2e, 0s, ECC CDH) scheme - the One-Pass Diffie-Hellman C(1e,1s, ECC CDH) scheme - the Static Unified Model C(0e, 2s, ECC CDH) scheme.`
>
> `NOTE For NSA Suite B the first two schemes have been selected.`

Source: `ch9-9-2-….md` §9.2.3.4.6.1, p.221 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

Domain parameters for all three schemes are `(q, FR, a, b{,SEED}, G, n, h)` `As determined by the security suite` (Tables 22, 23, 24). SHA-256 goes with P-256, SHA-384 with P-384:

> `the parties have agreed on using the NIST Concatenation KDF, see 9.2.3.4.6.5. SHA-256 is the hash function to use with the domain parameters for P-256 and SHA-384 is the hash function to use with the domain parameters for P-384;`

Source: `ch9-9-2-….md` §9.2.3.4.6.2/§9.2.3.4.6.3/§9.2.3.4.6.4, p.222–225 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

KDF (Green Book 9.2.3.4.6.5, "Key Derivation Function – The NIST Concatenation KDF"):

* `Function call: kdf(Z, OtherInput)` where `OtherInput consists of keydatalen and OtherInfo`.
* `hashlen` = `256 (for SHA-256) in the case of security suite 1 and 384 (for SHA-384) in the case of security suite 2`
* `H`: `SHA-256 in the case of security suite 1 and SHA-384 in the case of security suite 2`
* `keydatalen` = `128 bit for security suite 1 and 256 bit for security suite 2`
* `OtherInfo` = `AlgorithmID || PartyUInfo || PartyVInfo {||SuppPubInfo}{||SuppPrivInfo}`; SuppPubInfo and SuppPrivInfo are `Not used in DLMS/COSEM`.
* Table 25: `AlgorithmID` is `Fixed`, length `7` octets; `IDU` = `originator-system-title` (8 octets); `IDV` = `recipient-system-title` (8 octets). For `C(0e, 2s)`, `PartyUinfo` is `Variable`, length `8+n`, with `NonceU`: `Datalen = length of transaction-id, shall be 1 octet / Data = value of transaction-id`.
* Table 26 (COSEM cryptographic algorithm IDs): `AES-GCM-128` = OID `2.16.756.5.8.3.0`, encoded `60 85 74 05 08 03 00`; `AES-GCM-256` = `2.16.756.5.8.3.1`, encoded `60 85 74 05 08 03 01`; `AES-WRAP-128` = `2.16.756.5.8.3.2`, encoded `60 85 74 05 08 03 02`; `AES-WRAP-256` = `2.16.756.5.8.3.3`, encoded `60 85 74 05 08 03 03`.
* AlgorithmID rule: `When key agreement is used to agree on the GUEK and GAK, then the algorithm ID used shall be AES-GCM-128 / AES-GCM-256. When it is used to agree on the KEK then the algorithm ID used shall be AES-WRAP-128 / AES-WRAP-256.`

Source: `ch9-9-2-….md` §9.2.3.4.6.5, Tables 25 and 26, p.226–227 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

### 2.1 C.1 – Ephemeral Unified Model `C(2e, 0s, ECC CDH)` scheme

**Exact name.** `Figure C. 1 – MSC for key agreement using the Ephemeral Unified Model C(2e, 0s, ECC CDH) scheme`; section title `C.1 Ephemeral Unified Model C(2e, 0s, ECC CDH) scheme`. It is `specified in 9.2.3.4.6.2`.

Source: `channex-c-…-c-1-….md` §C.1, p.587 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\channex-c-normative-use-of-key-agreement-schemes-i-c-1-ephemeral-unified-model-c-2e-0s-ecc-cdh-sche.md`

**Prerequisite.** `Prerequisites: The initiator and the responder use the same elliptic curve and key derivation method`.

**Messages exchanged and step list (verbatim, condensed).**

> `- Step 1 (optional): the client sends to the server the certificate of its public key for digital signature by invoking the import_certificate method;`
> `- Step 2 (optional): the client retrieves from the server the certificate of the public key for digital signature by invoking the export_certificate method;`
> `- Step 3: The client generates an ephemeral key pair ( de,U , Qe,U ). It signs (key_Id, Qe,U) with its private digital signature key and sends it to the server by invoking the key_agreement method;`
> `- Step 4: The server verifies the signature and the validity of Qe,U. It computes shared secret Z from (de,v , Qe,U) and derives the secret key from Z and OtherInput;`
> `- Step 5: If the key has been successfully derived the server generates then an ephemeral key pair (de,v , Qe,v). It signs (key_id, Qe,v) and sends it to the client in the response to the invocation of the key_agreement method;`
> `- Step 5: The client computes shared secret Z from (de,U , Qe,V) and derives the secret key from Z and OtherInput.`

(The duplicate "Step 5" is as printed in the source file.)

Figure C.1 image text adds the message content shape: `agreement data = {key_id, Qe,U, ECDSA(key_id || Qe,U)}` for the client and `agreement(data) data = {key_id, Qe,V, ECDSA(key_id || Qe,V)}` for the server, plus `NOTE: key_id identifies the symmetric key to be generated`.

Source: `channex-c-…-c-1-….md` §C.1, p.587 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\channex-c-normative-use-of-key-agreement-schemes-i-c-1-ephemeral-unified-model-c-2e-0s-ecc-cdh-sche.md`

**Key pairs and shared-secret computation** (Green Book Table 22, "Ephemeral Unified Model key agreement scheme summary"):

| | Party U | Party V |
|---|---|---|
| Domain parameters | `(q, FR, a, b{,SEED}, G, n, h)` `as determined by the security suite` | same |
| Static data | `N/A` | `N/A` |
| Ephemeral data | `Ephemeral private key, de,U` / `Ephemeral public key, Qe,U` | `Ephemeral private key, de,V` / `Ephemeral public key, Qe,V` |
| Computation | `Compute Z by calling ECC CDH using de, U and Qe, V` | `Compute Z by calling ECC CDH using de, V and Qe, U` |
| Derive secret keying material | `1. Compute kdf(Z, OtherInput)` `2. Destroy Z` | same |

> `NOTE This table is based on NIST SP 800-56A Rev. 2: 2013, Table 18 and NSA2, Table 1.`

Purpose (Green Book 9.2.3.4.6.2): `This scheme is for use between a DLMS client and a server to agree on the master key, on global encryption keys and/or on the authentication key. The client plays the role of party U and the server plays the role of party V. The process is supported by the methods of the "Security setup" interface class`.

Source: `ch9-9-2-….md` §9.2.3.4.6.2, Table 22, p.222–223 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

**Test vector (Annex C Table C.1).** Key constants:

| Security material | Symbol | Contents |
|---|---|---|
| Security Suite | | `ECDH-ECDSA-AES-GCM-128-SHA-256` |
| Curve | | `P-256` |
| Domain Parameters | D | `See Annex A.` |
| System Title Client | Sys-TC | `4D4D4D0000BC614E` |
| System Title Server | Sys-TS | `4D4D4D0000000001` |
| Ephemeral Public Key Client | Epub-KC | `2914D60E10AB705F62ED6CC349D7CB99B9AB3F3978E59278C7AF595B3AF987941372DAB6D5AF1FA867E134167E6F23DE664A6693E05F43414611058D1B48F894` |
| Ephemeral Public Key Server | Epub-KS | `95F41066009B185B074F5FFFF736B71C325FCADB2BC0CF1A4F4B17BBE7AB81D62946506BC8169C7B539B39A5D8463787F449C9BD2583FA67A1075B0DBFC638BA` |
| Ephemeral Public Key Signature Client | Epub-K-Sig-C | `06F0607702AA0E2435A183E2F6B1ECD19629712E389A213610C03F77B2590860EA840AF5C3FA1F2BCDF055D4744E9A01CE9A0E55026BCAA4EEBEB764CED64BB3` + `// The key_id || Epub-KC are included in signature` |
| Ephemeral Public Key Signature Server | Epri-K-Sig-S | `A92995225CEE004ED4376057EEE9536E97EE6F5BAE43E59BDBBD515A89FB2CB83F2A270871A31B09338DCF0D1797466087908BA4A6ED8FD48B9EA067DA67DC4D` + `// The key_id || Epub-KS are included in signature` |
| Shared Secret | Z | `C1CF8FE7891AEF3617D7190795E61FE6C24EFC3CCA2E08469BAD1A225CE6EA08` |
| AlgorithmID | AlgID | `60857405080300 // AES-GCM-128` |
| KDF(Z,AlgID,Sys-TC, Sys-TS) | KDF | `C5F4512846EDE51CFB8CCF59F08A694E002EDF66B4CB1739AC26A74E49712F46` |
| Global Unicast Encryption Key | GUEK | `C5F4512846EDE51CFB8CCF59F08A694E` |

All key-type rows in the vector are marked `32` bytes (`256` bits) for private keys, `64` bytes (`512` bits) for public keys. The NOTE reads: `The values of the public keys are represented here as FE2OS(xp)II FE2OS(yp).` The action rows are `key_agreement(data) Client` / ACTION-Request with `00 40 00002B0000FF 03 // method id`, `01 // optional flag`, `0101 // array of 1`, `0202 // structure of 2`, `1600 // key_id = 0, global unicast encryption key`, then the 64-byte ephemeral public key and 64-byte signature; and `global_key_agreement(data) Server` / ACTION-Response with `00 // success`, `01 // optional Get-Data-result present`, `00 // data CHOICE`, `0101 // array of 1`, `0202 // structure of 2`, `1600 // key id = 0`, `098180`.

Source: `channex-c-…-c-1-….md` §C.1, Table C.1, p.588–589 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\channex-c-normative-use-of-key-agreement-schemes-i-c-1-ephemeral-unified-model-c-2e-0s-ecc-cdh-sche.md`

### 2.2 C.2 – One-Pass Diffie-Hellman `C(1e, 1s, ECC CDH)` scheme

**Exact name.** `C.2 One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) scheme`; `specified in 9.2.3.4.6.3`. It is used `to protect an xDLMS APDU`.

Source: `channex-c-…-c-2-….md` §C.2, p.590 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\channex-c-normative-use-of-key-agreement-schemes-i-c-2-one-pass-diffie-hellman-c-1e-1s-ecc-cdh-sche.md`

**Prerequisites (verbatim).**

> `- Party U and Party V use the same elliptic curve and key derivation method`
> `- Party U has the static public key agreement key Qs,V of party V`

**Message exchanged.** A `general-ciphering APDU`:

> `{ transaction_id, originator-system-title, recipient-system-title, date-time, other-information, key-info {key-parameters = Id. of key agreement scheme, key-ciphered-data = Qe,U , ECDSA(Qe,U)} ciphered-content }`

**Step list (verbatim, condensed).**

> `- Step 1: The originator, taking the role of the party U of the key agreement process generates an ephemeral key pair (de,U , Qe,U);`
> `- Step 2: It computes shared secret Z from de,U , Qs,V`
> `- Step 3: It derives the secret key from Z and OtherInfo`
> `- Step 4: It ciphers the xDLMS APDU as required by the security policy in force and by the access rights, using the key derived;`
> `- Step 5: It sends a general-ciphering APDU to the recipient. The use of the fields of the APDU shall be as follows (see also 9.2.3.4.6.5):`
> `  - transaction-id: as required; not needed for the key derivation process`
> `  - originator-system-title: this is used as the PartyUInfo element of OtherInfo`
> `  - recipient-system-title: this is used as the PartyVInfo element of OtherInfo`
> `  - date-time: as required; not needed for the key derivation process`
> `  - other-information: as required; not needed for the key derivation process`
> `  - key-info:`
> `    - key-parameters: Identifier of the key agreement scheme: 0x01, see Table 29`
> `    - key-ciphered-data = Qe,U signed by the digital signature private key of Party U`
> `  - ciphered-content: carries the ciphered xDLMS APDU that is protected using the key.`
> `- Step 6: The recipient, taking the role of party V of the key agreement process computes shared secret Z from ds,V , Qe,U;`
> `- Step 7: It derives the secret key from Z and OtherInfo`
> `- Step 8: It deciphers the xDLMS APDU using the key derived.`

Source: `channex-c-…-c-2-….md` §C.2, p.590–591 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\channex-c-normative-use-of-key-agreement-schemes-i-c-2-one-pass-diffie-hellman-c-1e-1s-ecc-cdh-sche.md`

**Key pairs and shared-secret computation** (Green Book Table 23):

| | Party U | Party V |
|---|---|---|
| Domain Parameters | `(q, FR, a, b{,SEED}, G, n, h)` `As determined by the security suite` | same |
| Static Data | `N/A` | `Static private key, ds,V` / `Static public key, Qs,V` |
| Ephemeral Data | `Ephemeral private key, de,U` / `Ephemeral public key, Qe,U` | `N/A` |
| Computation | `Compute Z by calling ECC CDH using de, U and Qs, V` | `Compute Z by calling ECC CDH using ds, V and Qe ,U` |
| Derive Secret Keying Material | `1. Compute kdf(Z, OtherInput)` `2. Destroy Z` | same |

> `NOTE This table is based on NIST SP 800-56A Rev. 2: 2013, Table 24 and NSA2, Table 2.`

Purpose (Green Book 9.2.3.4.6.3): `This scheme is for use by a DLMS server and another party to agree on an ephemeral encryption key to protect xDLMS APDUs or COSEM data. The party sending the message (the originator) plays the role of party U and the other party (the recipient) plays the role of party V.` and `Party U obtains Party V's static public key in a trusted manner (for example, from a certificate signed by a trusted CA)`.

Source: `ch9-9-2-….md` §9.2.3.4.6.3, Table 23, p.223–224 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

**Test vector (Annex C Table C.2).** Key constants:

| Security material | Symbol | Contents |
|---|---|---|
| Security Suite | | `ECDH-ECDSA-AES-GCM-128-SHA-256` |
| Curve | | `P-256` |
| Domain Parameters | D | `See Annex A.` |
| System Title Client / Server | Sys-TC / Sys-TS | `4D4D4D0000BC614E` / `4D4D4D0000000001` |
| Private Key Agreement Key Client | Pri-AKC | `A51C16FF5C498FCC89323D4A9267CD71BF81FD6F6A891CD240DA7F3D6F283E65` |
| Private Key Agreement Key Server | Pri-AKS | `AAD3FD0732E991CF52A74C66C1F2827DDC53522A2E0A169D7C4FFCC0FB5D6A4D` |
| Public Key Agreement Key Client | Pub-AKC | `07C56DE2DCAF0FD793EF29F019C89B4A0CC1E001CE94F4FFBE10BC05E7E66F7671A13FBCF9E662B9826FFF6A6938546D524ED6D3405F020296BDE16B04F7A7C2` |
| Public Key Agreement Key Server | Pub-AKS | `A653565B0E06070BAE9FBE140A5D2156812AEE2DD525053E3EFC850BF13BFDFFCB240BC7B77BFF5883344E7275908D2287BEFA3725017295A096989D2338290B` |
| Ephemeral Public Key Client | Epub-KC | `C323C2BD45711DE4688637D919F92E9DB8FB2DFC213A88D21C9DC8DCBA917D8170511DE1BADB360D50058F794B0960AE11FA28D392CFF907A62D13E3357B1DC0` |
| Ephemeral Public Key Signature Client | Epub-K-Sig-C | `B51BE089D0B682863B2217201E73A1A9031968A9B4121DCBC3281A69739AF87429F5B3AC5471E7B6A04A2C0F2F8A25FD772A317DF97FC5463FEAC248EB8AB8BE` + `// Epub-KC is included in signature` |
| Shared Secret GC-C | Z-GC-C | `0D4385BA0DD756CBCAB9887EB538396EE8F090A14C1079B4359F115B977F4615` |
| KDF(Z,AlgID,Sys-TC, Sys-TS) GC-C | KDF-GC-C | `59A71FD81C929A86A99438DA17A66C058C6A93FD3065F5EE16A05D775927659B` |
| Encryption Key GC-C | EK-GC-C | `59A71FD81C929A86A99438DA17A66C05` |
| Shared Secret GC-S | Z-GC-S | `2B4302DC49790E2E78D990CFB52ED6E2F273DECE441A2D95E4301B93812A9FAC` |
| KDF(Z,AlgID,Sys-TS, Sys-TC) GC-S | | `F0184BDA9466BFA4601A64A7EF46504AB1A40C4851A0A644503599DF298B2E14` |
| Encryption Key GC-S | EK-GC-S | `F0184BDA9466BFA4601A64A7EF46504A` |

The `general-ciphering (Access-Request)` row encodes `DD / 080102030405060708 // transaction-id / 08 4D4D4D0000BC614E // originator-system-title / 08 4D4D4D0000000001 // recipient-system-title / 00 // date-time not present / 00 // other-information not present / 01 // optional flag / 02 // agreed-key CHOICE / 0101 // key-parameters / 8180…// key-ciphered-data`. Note the AlgorithmID here is `60857405080300 // AES-GCM-128` in both directions but the KDF input ordering differs: `KDF(Z,AlgID,Sys-TC, Sys-TS)` for the request and `KDF(Z,AlgID,Sys-TS, Sys-TC)` for the response.

Source: `channex-c-…-c-2-….md` §C.2, Table C.2, p.591–593 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\channex-c-normative-use-of-key-agreement-schemes-i-c-2-one-pass-diffie-hellman-c-1e-1s-ecc-cdh-sche.md`

### 2.3 C.3 – Static Unified Model `C(0e, 2s, ECC CDH)` scheme

**Exact name.** `C.3 Static Unified Model C(0e, 2s, ECC CDH) scheme`; `specified in 9.2.3.4.6.4`. Used `to protect an xDLMS APDU`.

Source: `channex-c-…-c-3-….md` §C.3, p.594 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\channex-c-normative-use-of-key-agreement-schemes-i-c-3-static-unified-model-c-0e-2s-ecc-cdh-scheme.md`

**Prerequisites (verbatim).**

> `- Party U and party V use the same elliptic curve and key derivation method.`
> `- Party U and party V have the public key agreement key of the other party`

**Step list (verbatim, condensed).**

> `- Step 1: The originator, taking the role of the Party U of the key agreement process obtains a nonce, NonceU;`
> `- Step 2: It computes shared secret Z from ds,U , Qs,V`
> `  NOTE See also Note to Table 24.`
> `- Step 3: It derives the secret key from Z, and OtherInput that contains NonceU`
> `- Step 4: It ciphers the xDLMS APDU as required by the security policy in force and by the access rights, using the key derived;`
> `- Step 5: It sends a general-ciphering APDU to the recipient. The use of the fields of the APDU shall be as follows (see also 9.2.3.4.6.5):`
> `  - transaction-id: this field is used as NonceU`
> `  - originator-system-title: this is used as the PartyUInfo element of OtherInfo`
> `  - recipient-system-title: this is used as the PartyVInfo element of OtherInfo`
> `  - date-time: as required; not needed for the key derivation process`
> `  - key-info:`
> `    - key-parameters: Identifier of the key agreement scheme: 0x02, see Table 29.`
> `    - key-ciphered-data = empty`
> `  - ciphered-content carries the ciphered xDLMS APDU that is protected using the key.`
> `- Step 6: The recipient, taking the role of party V of the key agreement process computes shared secret Z from ds,V , Qs,U;`
> `- Step 7: It derives the secret key from Z and OtherInput that contains NonceU`
> `- Step 8: It deciphers the xDLMS APDU using the key derived.`

Source: `channex-c-…-c-3-….md` §C.3, p.594–595 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\channex-c-normative-use-of-key-agreement-schemes-i-c-3-static-unified-model-c-0e-2s-ecc-cdh-scheme.md`

**Key pairs and shared-secret computation** (Green Book Table 24):

| | Party U | Party V |
|---|---|---|
| Domain Parameters | `(q, FR, a, b{,SEED}, G, n, h)` `As determined by the security suite` | same |
| Static Data | `Static private key, ds,U` / `Static public key, Qs,U` | `Static private key, ds,V` / `Static public key, Qs,V` |
| Ephemeral Data | `NonceU` | (empty) |
| Computation | `Compute Z by calling ECC CDH using ds, U and Qs, V` | `Compute Z by calling ECC CDH using ds, V and Qs ,U` |
| Derive Secret Keying Material | `1. Compute DerivedKeyingMaterial using NonceU` `2. Destroy Z` | same |

> `NOTE 1 This table is based on NIST SP 800-56A Rev. 2: 2013, Table 26.`
>
> `NOTE 2 The value of Z is the same in all C(0e, 2s) key-establishment transactions between the same two parties, therefore if it is ever compromised, then all of the keying material derived in past, current, and future C(0e, 2s) key-agreement transactions between these same two entities that employ these same static key pairs may be compromised as well. Any shared secret Z that is not 'zeroized' shall be stored and used with the same security protections as private keys.`

Purpose (Green Book 9.2.3.4.6.4): `In this case, the parties use only static key pairs. Each party obtains the other party's static public key. A nonce, NonceU, is sent by party U to party V to ensure that the derived keying material is different for each key-establishment transaction.`

Source: `ch9-9-2-….md` §9.2.3.4.6.4, Table 24, p.224–226 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

**Test vector (Annex C Table C.3).** Reuses the same static key-agreement keys as C.2 (`Pri-AKC = A51C16FF…83E65`, `Pri-AKS = AAD3FD07…D6A4D`, `Pub-AKC = 07C56DE2…F7A7C2`, `Pub-AKS = A653565B…382 90B`), with:

| Security material | Symbol | Contents |
|---|---|---|
| Security Suite | | `ECDH-ECDSA-AES-GCM-128-SHA-256` |
| Curve | | `P-256` |
| Domain Parameters | D | `See Table A.1.` |
| Nonce Client | Nonce-C | `080102030405060708 // Nonce-C is transaction-id with length` |
| Nonce Server | Nonce-S | `080123456789012345 // Nonce-S is transaction-id with length` |
| Shared Secret GC-C / GC-S | Z-GC-C / Z-GC-S | `B1455B2AD5F68BCFFE6AD5412BA89548ACA7E0CBF4B1560D6A57496F15E931AD` (both) |
| AlgorithmID GC-C / GC-S | AlgID | `60857405080300 // AES-GCM-128` |
| KDF(Z,AlgID,Sys-TC, Nonce-C, Sys-TS) GC-C | KDF-GC-C | `56C46B57DF675515C31025455822514AFA2CDEB3E0BF1CADA84576159E84DE7E` |
| Encryption Key GC-C | EK-GC-C | `56C46B57DF675515C31025455822514A` |
| KDF(Z,AlgID,Sys-TS, Nonce-S, Sys-TC) GC-S | | `FC1314F7DE033B7DD19C80DBCF9FF2C5286DC8F76E87877BD90B9B7F00CD5613` |
| Encryption Key GC-S | EK-GC-S | `FC1314F7DE033B7DD19C80DBCF9FF2C5` |

The Access-Request APDU encodes `key-parameters = 0102` and `00 // key-ciphered-data not present`.

Source: `channex-c-…-c-3-….md` §C.3, Table C.3, p.595–597 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-c-normative-use-of-key-agreement-schemes-i\markdown\channex-c-normative-use-of-key-agreement-schemes-i-c-3-static-unified-model-c-0e-2s-ecc-cdh-scheme.md`

### 2.4 Which keys / suites each scheme is used for

Green Book 9.2.5.5 ("Key agreement") is explicit about the division of labour:

> `The Ephemeral Unified Model C(2e,0s, ECC CDH) scheme can be used by the client and the server to agree on the: - master key, KEK; and/or - global unicast encryption key GUEK; and/or - global broadcast encryption key GBEK; and/or - (global) authentication key, GAK.`
>
> `This scheme is supported by the key_agreement method of the "Security setup" interface class …`
>
> `To establish an ephemeral encryption key – used as the block cipher key – using key agreement, two schemes are available: - the One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) scheme specified in 9.2.3.4.6.3`
>
> `Unless specified otherwise in a project specific companion specification, the C(1e, 1s ECC CDH) scheme shall be used.`
>
> `- the Static Unified Model C(0e, 2s, ECC CDH) scheme specified in 9.2.3.4.6.4.`

Source: `ch9-9-2-….md` §9.2.5.5, p.232 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

Green Book Table 28 ("Symmetric keys types") footnotes tie each scheme to a key role:

> `3) Established using the Ephemeral Unified Model C(2e, 0s, ECC CDH) scheme, see 9.2.3.4.6.2`
> `4) Established using the One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) scheme or the Static Unified Model C(0e, 2s, ECC CDH) scheme. See 9.2.3.4.6.3 and 9.2.3.4.6.4.`

with `3)` attached to master key / GUEK / GBEK / GAK establishment, and `4)` attached to the ephemeral encryption key established by key agreement.

Source: `ch9-9-2-….md` §9.2.5.1, Table 28, p.230 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

Blue Book Security setup, `key_agreement` method:

> `Used to agree on one or more symmetric keys using the key agreement algorithm as specified by the security suite. In the case of suites 1 and 2 the ECDH key agreement algorithm is used with the Ephemeral Unified Model C(2e, 0s, ECC CDH) scheme.`

Source: `ch4-4-4-….md` §4.4.7.3.3, p.136 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`

Therefore, from these files: C(2e,0s) is the Security-setup `key_agreement` scheme used **for suites 1 and 2** (it requires ECDH/ECDSA, which suite 0 does not have – see Table 27 where suite 0's key agreement and digital signature are `–`). The test vectors in Annex C are all labelled `ECDH-ECDSA-AES-GCM-128-SHA-256` with `Curve P-256`, i.e. suite 1.

**UNCERTAIN**: no file states a per-suite restriction for C(1e,1s) or C(0e,2s) beyond "the elliptic curves P-256 or P-384"; the Green Book Table 27 gives suite 0 no key agreement at all, so all three schemes are implicitly suite 1/2 only, but that sentence is not written explicitly.

### 2.5 Numeric identifiers of the key-agreement schemes on the wire

Green Book Table 29 ("Key information with general-ciphering APDU and data protection", `agreed-key` row):

> `key-parameters … Identifier of the key agreement scheme:`
> `0x01: C(1e, 1s ECC CDH)`
> `0x02: C(0e,2s ECC CDH)`
> `All other reserved.`

and the `key-ciphered-data` row:

> `- In the case of the C(1e, 1s, ECC CDH) scheme: the public key Qe, U, of the ephemeral key agreement key pair of party U, signed with the private digital signature key of party U.`
> `- In the case of the C(0e, 2s, ECC CDH) scheme: an octet-string of length zero. In this case party U has to provide a nonce, NonceU. See 9.2.3.4.6.4 and 9.2.3.4.6.5.`

Source: `ch9-9-2-….md` §9.2.5.2, Table 29, p.231 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

ASN.1 (Green Book 9.5):

```asn1
Agreed-Key ::= SEQUENCE
{
key-parameters                     OCTET STRING,
key-ciphered-data                  OCTET STRING
}
Key-Info ::= CHOICE
{
identified-key                     [0] Identified-Key,
wrapped-key                        [1] Wrapped-Key,
agreed-key                         [2] Agreed-Key
}
```

Source: `ch9-9-5-….md` §9.5, "Key-info" — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-5-abstract-syntax-of-cosem-pdus.md`

**Note:** C(2e,0s) has **no** key-parameters code in Table 29, because it is invoked through the `key_agreement` method of "Security setup", not through the `agreed-key` CHOICE of a general-ciphering APDU.

---

## 3. Certificate profile

### 3.1 Overall structure

> `All certificates shall have the structure specified for X.509 version 3 certificates.`

Table 31 – X.509 v3 Certificate structure: `tbsCertificate` (RFC 5280 4.1.1.1, `m`), `signatureAlgorithm` (4.1.1.2, `m`), `signatureValue` (4.1.1.3, `m`).

> `The signatureValue contains a digital signature computed upon the ASN.1 DER encoded tbsCertificate. The ASN.1 DER encoded tbsCertificate is used as the input to the signature function.`

Source: `ch9-9-2-….md` §9.2.6.4.1, §9.2.6.4.2, Tables 31, p.236–237 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

### 3.2 tbsCertificate fields (Table 32)

| Certificate field | RFC 5280 ref | Clause | m/x/o | Comment |
|---|---|---|---|---|
| Version | 4.1.2.1 | – | `m` | `'v3' (value is 2)` |
| Serial Number | 4.1.2.2 | 9.2.6.4.3.2 | `m` | `Certificate serial number assigned by the CA (not longer than 20 octets)` |
| Signature | 4.1.2.3 | – | `m` | `Same algorithm identifier as the signatureAlgorithm in the Certificate` |
| Issuer | 4.1.2.4 | 9.2.6.4.3.3 | `m` | `Distinguished name (DN) of the certificate issuer.` |
| Validity | 4.1.2.5 | 9.2.6.4.3.4 | `m` | `Validity of the certificate.` |
| Subject | 4.1.2.6 | 9.2.6.4.3.3 | `m` | `Distinguished name (DN) of the certificate subject.` |
| Subject Public Key Info | 4.1.2.7 | 9.2.6.4.3.5 | `m` | |
| Issuer Unique ID | 4.1.2.8 | | `x` | `Not applicable` |
| Subject Unique ID | 4.1.2.8 | 9.2.6.4.3.6 | `o` | |
| Extensions | 4.1.2.9 | 9.2.6.4.4 | `m` | |

Source: `ch9-9-2-….md` §9.2.6.4.3.1, Table 32, p.237 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

Serial number: `Certificate users MUST be able to handle serialNumber values up to 20 octets. Conforming CAs MUST NOT use serialNumber values longer than 20 octets.`

Source: `ch9-9-2-….md` §9.2.6.4.3.2, p.238 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

### 3.3 Subject naming scheme (end entity)

Table 35 – naming scheme for the end entity instance: `Common Name` / `CN` / `m` / `<System-title>` with comment `DLMS/COSEM System title: 8 bytes represented as a 16 characters: Example: "4D4D4D0000BC614E"`. `Organization O` optional, `Organizational Unit OU` optional, `Country C` optional, `Locality L` = `x`, `State S` = `x`.

Table 33 (Root-CA): `CN = <Root-CA>` (`m`). Table 34 (Sub-CA): `CN = <XXX-CA>` (`m`) with `The CN shall finish with "CA" so that the CA function is recognized.`

Source: `ch9-9-2-….md` §9.2.6.4.3.3, Tables 33–35, p.238–239 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

### 3.4 Validity

> `In the case of CA certificates, Sub-CA certificates and end-entities other than DLMS servers notBefore and notAfter shall be well defined dates.`
> `DLMS servers may be given certificates for which no good expiration date can be assigned; such a certificate is intended to be used for the entire lifetime of the device.`
> `To indicate that a certificate has no well-defined expiration date, the notAfter SHOULD be assigned the GeneralizedTime value of 99991231235959Z.`

Source: `ch9-9-2-….md` §9.2.6.4.3.4, p.239 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

### 3.5 SubjectPublicKeyInfo, algorithm OIDs and curve names

```asn1
SubjectPublicKeyInfo ::= SEQUENCE {
Algorithm                     AlgorithmIdentifier,
subjectPublicKey             BIT STRING }
```

> `The algorithm OBJECT IDENTIFIER shall contain the value - OID value: 1.2.840.10045.2.1 - OID description: ECDSA and ECDH Public Key.`
> `The value of the parameter shall be 1.2.840.10045.3.1.7 for the curve NIST P-256 and 1.3.132.0.34 for the curve NIST P-384.`
> `ECPoint ::= OCTET STRING`
> `Implementations of Elliptic Curve Cryptography according to this Technical Report MUST support the uncompressed form and MAY support the compressed form of the ECC public key. The hybrid form of the ECC public key from [X9.62] MUST NOT be used.`
> `The uncompressed form is indicated by 0x04 and the compressed form is indicated by either 0x02 or 0x03 … The public key MUST be rejected if any other value is included in the first octet.`

Source: `ch9-9-2-….md` §9.2.6.4.3.5, p.239–240 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

### 3.6 Signature algorithm identifiers

> `The two algorithm identifiers used in DLMS/COSEM are:`
> `- ecdsa-with-SHA256, OID 1.2.840.10045.4.3.2 in the case of security suite 1`
> `- ecdsa-with-SHA384, OID 1.2.840.10045.4.3.3 in the case of security suite 2`

Source: `ch9-9-2-….md` §9.2.6.4.2, p.236 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

### 3.7 Certificate extensions (Table 36, and per-extension OIDs)

Table 36 – X.509 v3 Certificate extensions (`m`/`o`/`x` per certificate type: `C(Root)`, `C(Sub-CA)`, `C(TLS)`, `C(KeyAgree)`, `C(DataSign)`):

| # | Attribute | RFC 5280 | Clause | C(Root) | C(Sub-CA) | C(TLS) | C(KeyAgree) | C(DataSign) |
|---|---|---|---|---|---|---|---|---|
| 1 | AuthorityKeyIdentifier | 4.2.1.1 | 9.2.6.4.4.2 | `o` | `m` | `m` | `m` | `m` |
| 2 | SubjectkeyIdentifier | 4.2.1.2 | 9.2.6.4.4.3 | `m` | `m` | `o` | `o` | `o` |
| 3 | KeyUsage | 4.2.1.3 | 9.2.6.4.4.4 | `m` | `m` | `m` | `m` | `m` |
| 4 | CertificatePolicies | 4.2.1.4 | 9.2.6.4.4.5 | `o` | `m` | `m` | `o` | `o` |
| 5 | SubjectAltNames | 4.2.1.6 | 9.2.6.4.4.6 | `o` | `o` | `o` | `o` | `o` |
| 6 | IssuerAltNames | 4.2.1.7 | 9.2.6.4.4.7 | `o` | `o` | `x` | `x` | `x` |
| 7 | BasicConstraints | 4.2.1.9 | 9.2.6.4.4.8 | `m` | `m` | `x` | `x` | `x` |
| 8 | ExtendedKeyUsage | 4.2.1.12 | 9.2.6.4.4.9 | `x` | `x` | `m` | `x` | `x` |
| 9 | cRLDistributionPoints | 4.2.1.13 | 9.2.6.4.4.10 | `o` | `o` | `x` | `x` | `x` |

with the legend `C(Root): Certificate of the Root CA`, `C(Sub-CA): Certificate of a Sub-CA`, `C(TLS): Certificate for Transport Layer Security`, `C(KeyAgree): Certificate an ECDH capable key establishment key`, `C(DataSign): Certificate of an ECDSA capable signing key`.

Per-extension rules (verbatim):

* AuthorityKeyIdentifier — `Extension-ID (OID): 2.5.29.35`, `Critical: FALSE`, `the AuthorityKeyIdentifier extension MUST include the keyIdentifier field.`
* SubjectKeyIdentifier — `Extension-ID (OID): 2.5.29.14`, `Critical: FALSE`, value computed either by `method 1 defined in RFC 5280, 4.2.1.2 i.e. the keyIdentifier is composed of the 160-bit SHA-1 hash of the value of the BIT STRING SubjectPublicKey` or by `method 2 … a four-bit type field with the value 0100 followed by the least significant 60 bits of the SHA-1 hash`.
* KeyUsage — `Extension-ID (OID): 2.5.29.15`, `Critical: TRUE`. Table 37: `C(Root)` = `keyCertSign, cRLSign`; `C(Sub-CA)` = `keyCertSign, cRLSign`; `C(TLS)` = `digitalSignature keyAgreement`; `C(KeyAgree)` = `keyAgreement`; `C(DataSign)` = `digitalSignature`.
* CertificatePolicies — `Extension-ID (OID): 2.5.29.32`, `Critical: FALSE`, `Value: contains the OID for the applicable certificate policy.`
* SubjectAltNames — `Extension-ID (OID): 2.5.29.17`, `Critical: TRUE if the "subject" field of the certificate is empty (an empty sequence), else FALSE.` and `The SubjectAltName extension when used shall contain a single GeneralName of type OtherName that is further sub-typed as a HardwareModuleName (id-on-HardwareModuleName) as defined in IETF RFC 4108. The hwSerialNum field shall be set to the system title.`
* IssuerAltName — `Extension-ID (OID): 2.5.29.18`, `Critical: FALSE`.
* Basic constraints — `Extension-ID (OID): 2.5.29.19`, `Critical: TRUE`; `cA` = `TRUE` for `C(Root)` and `C(Sub-CA)`, `–` otherwise; `pathLenConstraint` depends on `the structure of the PKI`.
* Extended Key Usage — `Extension-ID (OID): 2.5.29.37`, `Critical: FALSE`, `Description: Indicates that a certificate can be used as an TLS server certificate`, `TLS server authentication OID: 1.3.6.1.5.5.7.3.1`, `TLS client authentication OID: 1.3.6.1.5.5.7.3.2.`
* cRLDistributionPoints — `Extension-ID (OID): 2.5.29.31`, `Critical: FALSE`, `This extension is not used in DLMS server certificates.`
* `All other extensions not described in this profile should be considered OPTIONAL`.

Source: `ch9-9-2-….md` §9.2.6.4.4.1–9.2.6.4.4.11, p.240–243 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

### 3.8 Certificate types handled by DLMS/COSEM end entities (Table 41)

| Security suite 1 | Security suite 2 | Role |
|---|---|---|
| `Root Certification Authority (Root-CA) Self-Signed Certificate using P-256 signed with P-256` | `Root Certification Authority (Root-CA) Self-Signed Certificate using P-384 signed with P-384` | `Trust anchor; there may be more than one.` |
| `Subordinate CA Certificate (Sub-CA) using P-256 signed with P-256` | `Subordinate CA Certificate (Sub-CA) using P-384 signed with P-384` | `Certificate of an issuing CA. Subordinate CAs may be also used as trust anchors.` |
| `Subordinate CA Certificate (Sub-CA) using P-256 signed with P-384` | `–` | (same row span) |
| `End-Entity Signature Certificate using P-256 signed with P-256` | `End-Entity Signature Certificate using P-384 signed with P-384` | `Public key for ECDSA signature generation and verification` |
| `End-Entity Signature Certificate using P-256 signed with P-384` | `–` | (same row span) |
| `End-Entity Key Establishment Certificate using P-256 signed with P-256` | `End-Entity Key Establishment Certificate using P-384 signed with P-384` | `Used with the One-Pass Diffie-Hellman C(1e, 1s) scheme or with the Static Unified Model C(0e, 2s, ECC CDH) scheme` |
| `End-Entity Key Establishment Certificate using P-256 signed with P-384` | `–` | (same row span) |
| `End-Entity TLS Certificate using P-256 signed with P-256` | `End-Entity TLS Certificate using P-384 signed with P-384` | |
| `End-Entity TLS Certificate using P-256 signed with P-384` | `–` | |

> `An example Certificate is given in Annex B.`

Source: `ch9-9-2-….md` §9.2.6.5, Table 41, p.243 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

End entity certificate kinds defined in 9.2.6.3.3.4: `digital signature key certificate C(digitalSignature), used for digital signature`; `static key agreement key certificate C(keyAgreement), used for key agreement`; `[optional] TLS-Certificate C(TLS)`.

Source: `ch9-9-2-….md` §9.2.6.3.3.4, p.236 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

### 3.9 Annex B.1 – "Fields of public key Certificates using P-256 signed with P-256" (Table B.1)

The annex says: `Table B. 1 shows the fields of public key Certificates. For details, see 9.2.6.4.2.`

| Field | Value | Comments |
|---|---|---|
| (begin tbsCertificate) | | |
| Version | `2` | `X.509 version 3` |
| Serial Number | `INTEGER` | `Assigned by the CA, up to 20 octets` |
| Signature | `1.2.840.10045.4.3.2` | `ecdsa-with-SHA256 (same as signatureAlgorithm)` |
| Issuer | `CN, O, C` | `Distinguished name (DN) of the certificate issuer` |
| Validity | `Not before <date>` / `Not after <date>` | `Validity of the Certificate. Follows RFC 5280.` |
| Subject | `CN, O, C` | `Distinguished name (DN) of the certificate subject` |
| Subject Public Key Info → AlgorithmIdentifier → algorithm | `1.2.840.10045.2.1` | `ECDSA and ECDH Public Key` |
| … parameters | `1.2.840.10045.3.1.7` | `NIST P-256 named curve` |
| … subjectPublicKey | `ECC public key bit string 528 bits` | `1st byte = 0, 2nd byte = 4 (uncompressed)` / `256 bit x, 256 bit y coordinates` |
| subjectUniqueID | `Bit string` | `Optional in end device certificates other than server certificates.` |
| BasicConstraints | `2.5.29.19` / `Boolean | Integer` / `TRUE` | `Only required for CA certificates. CA indication and maximum path length` |
| Subject Key Identifier | `2.5.29.14` / `octet string` / `FALSE` | `Optional in end entity certificates Follows RFC 5280, 8 or 20 octets.` |
| Authority Key Identifier | `2.5.29.35` / `octet string` / `FALSE` | `Mandatory in end entity certificates Follows RFC 5280, 8 or 20 octets.` |
| Key Usage | `2.5.29.15` / `DER encoded bit string` / `TRUE` | `Mandatory in all certificates. Values according to RFC 5280, 4.2.1.3: 0 digitalSignature 4 keyAgreement 5 keyCertSign 6 cRLSign At least one bit must be 1.` |
| CertificatePolicies | `2.5.29.32` / `OID` / `FALSE` | `Optional in end entity certificates` |
| Subject Alt Names | `2.5.29.17` / `To be assigned by the PKI or the CA` / `TRUE when Subject is absent.` | `Optional in end entity certificates` |
| (end tbsCertificate) | | |
| signatureAlgorithm | `1.2.840.10045.4.3.2` | `ecdsa-with-SHA256` |
| signatureValue | `Bit string` | `Encoded bit string value of a DER encoded sequence of 2 integers; each a maximum of 33 bytes.` |

Source: `channex-b-…-b-1-….md` §B.1, Table B.1, p.584 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-b-informative-example-of-an-root-ca-and-en\markdown\channex-b-informative-example-of-an-root-ca-and-en-b-1-fields-of-public-key-certificates.md`

### 3.10 Annex B.2 – example Root-CA certificate (P-256 signed with P-256)

Verbatim highlights:

```text
Version: 3 (0x2)
Serial Number: 156 (0x9c)
Signature Algorithm: ecdsa-with-SHA256
Issuer: C=CH, O=DLMS USER ASSOCIATION, CN=Root_CA
Validity
Not Before: Jan  1 00:00:00 2010 GMT
Not After : Dec 31 23:59:59 2049 GMT
Subject: C=CH, O=DLMS USER ASSOCIATION, CN=Root_CA
Subject Public Key Info:
Public Key Algorithm: id-ecPublicKey
Public-Key: (256 bit)
ASN1 OID: prime256v1
NIST CURVE: P-256
X509v3 extensions:
X509v3 Basic Constraints: critical
CA:TRUE, pathlen:1
X509v3 Subject Key Identifier:
D3:72:AB:23:C7:E0:A4:2C:49:71:EA:B7:D1:B8:3F:20:AB:52:4F:CC
X509v3 Key Usage: critical
Certificate Sign, CRL Sign
Signature Algorithm: ecdsa-with-SHA256
30:46:02:21:00:aa:d4:0b:10:8d:98:b7:08:4b:a4:ab:9c:f4:
95:f2:0f:39:c5:0d:1f:32:88:41:36:a7:1c:99:05:ea:67:3d:
21:02:21:00:ad:f3:67:b0:66:d3:72:53:67:09:ad:26:3f:b8:
4c:38:73:ae:d8:a7:fd:55:d8:15:14:d4:11:31:6a:20:ad:40
```

The public key is printed as a 65-byte uncompressed point starting `04:09:5d:5d:…`. The sample signature is a DER `SEQUENCE` of two INTEGERs (`30:46:02:21:00:aa:d4…` / `02:21:00:ad:f3…`), each 33 bytes.

Source: `channex-b-…-b-2-….md` §B.2, p.585 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-b-informative-example-of-an-root-ca-and-en\markdown\channex-b-informative-example-of-an-root-ca-and-en-b-2-example-of-a-root-ca-certificate-using-p-256.md`

### 3.11 Annex B.3 – example end-entity digital signature certificate (P-256 signed with P-256)

```text
Version: 3 (0x2)
Serial Number: 170 (0xaa)
Signature Algorithm: ecdsa-with-SHA256
Issuer: C=CH, O=DLMS USER ASSOCIATION, CN=Root_CA
Validity
Not Before: Jan  1 00:00:00 2010 GMT
Not After : Dec 31 23:59:59 2049 GMT
Subject: C=CH, O=DLMS USER ASSOCIATION, CN=4354543030303030
Subject Public Key Info:
Public Key Algorithm: id-ecPublicKey
Public-Key: (256 bit)
ASN1 OID: prime256v1
NIST CURVE: P-256
X509v3 extensions:
X509v3 Authority Key Identifier:
keyid:D3:72:AB:23:C7:E0:A4:2C:49:71:EA:B7:D1:B8:3F:20:AB:52:4F:CC
X509v3 Key Usage: critical
Digital Signature
Signature Algorithm: ecdsa-with-SHA256
30:46:02:21:00:96:fe:e8:56:dd:53:68:d9:c7:70:c0:da:d5:
2f:4f:a4:97:12:9a:b7:2c:52:3a:35:66:0e:b6:91:e5:ce:97:
89:02:21:00:8d:f5:9e:87:58:21:24:7b:ca:6f:18:a2:b3:34:
aa:39:7b:b8:c0:c4:81:25:7a:f6:17:f5:bb:04:a3:8d:75:a9
```

Notable: the subject CN is the system title encoded as 16 hex characters (`4354543030303030` = "CTD00000"), matching 9.2.6.4.3.3 Table 35; the Authority Key Identifier equals the Root-CA Subject Key Identifier; Key Usage is `Digital Signature` only; there is no `Basic Constraints` extension.

Source: `channex-b-…-b-3-….md` §B.3, p.586 — `D:\project\personal\dlms\GreenBook\output\book\ai\channex-b-informative-example-of-an-root-ca-and-en\markdown\channex-b-informative-example-of-an-root-ca-and-en-b-3-example-of-an-end-entity-digital-signature-c.md`

### 3.12 Conflict worth flagging: certificate signature encoding vs. "plain format"

* For ECDSA in general, 9.2.3.4.5 mandates concatenated fixed-length octet strings (see §4.2 below).
* For certificates, Annex B.1 specifies `signatureValue … Encoded bit string value of a DER encoded sequence of 2 integers; each a maximum of 33 bytes` and the Annex B.2/B.3 samples are DER SEQUENCEs.

The files do not reconcile these two statements.

**UNCERTAIN**: whether the "plain format" rule of 9.2.3.4.5 is intended to apply to certificate `signatureValue` as well. The files contain both rules without cross-reference. Treat certificate signatures as DER-encoded `SEQUENCE` of two INTEGERs (per Annex B.1 and the samples) and the plain `R || S` format as the rule for the ECDSA uses described in 9.2.3.4.5 / HLS ECDSA.

---

## 4. ECDSA in DLMS application authentication

### 4.1 Algorithm and curve/hash selection

> `For DLMS/COSEM the elliptic curve digital signature (ECDSA) algorithm as specified in FIPS PUB 186-4:2013 has been selected. NSA1 provides an implementation guide.`
> `In DLMS/COSEM the elliptic curves and algorithms used shall be:`
> `- in the case of Security Suite 1, the elliptic curve P-256 with the SHA-256 hash algorithm`
> `- in the case of Security Suite 2, the elliptic curve P-384 with the SHA-384 hash algorithm.`

Source: `ch9-9-2-….md` §9.2.3.4.5, p.221 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

### 4.2 Signature format

> `The inputs to ECDSA digital signature generation are the following: - the message M to be signed`
> `NOTE 1 In the DLMS/COSEM context "Message" may be an xDLMS APDU, see 9.2.7.2 or COSEM data, see 9.2.7.5.`
> `- the private key of the signatory, d.`
> `The output is the ECDSA signature (r, s) over M.`
> `In DLMS/COSEM the plain format shall be used: the signature ( r, s) is encoded as octet string R II S, i.e. as concatenation of the octet strings R = I2OS(r, l) and S = I2OS(s, l) with l = [log n]. Thus, the signature has a fixed length of 2 l octets.` *(the converted text inserts a stray "256" before "signature": "Thus, the 256 signature has a fixed length of 2 l octets")*
> `NOTE 2 Here, n is the order of the base point G of the elliptic curve. I2OS is the Integer to Octet String Conversion Primitive.`

So: **raw `R || S`, fixed 2l octets — 64 octets for P-256, 96 octets for P-384** (l = bit length of n). This is confirmed by every ECDSA signature value in the test vectors (64 bytes).

Source: `ch9-9-2-….md` §9.2.3.4.5, p.221 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

Verification inputs: `the signed message M'`, `the received ECDSA signature (r', s')`, `the authentic public key of the signatory, Q.` and `The process of generating and verifying the signatures shall be as specified in NSA1, 3.4.`

### 4.3 HLS authentication with ECDSA (mechanism_id(7)) – what is signed

The four-pass HLS process (Green Book 9.2.2.2.2.4):

> `- Pass 1: The client transmits a "challenge" CtoS and – depending on the authentication mechanism – additional information to the server;`
> `- Pass 2: The server transmits a "challenge" StoC and – depending on the authentication mechanism – additional information to the client;`
> `If StoC is the same as CtoS, the client shall reject it and shall abort the AA establishment process.`
> `- Pass 3: The client processes StoC and the additional information according to the rules of the HLS authentication mechanism valid for the given AA and sends the result to the server. The server checks if f(StoC) is the result of correct processing and – if so – it accepts the authentication of the client;`
> `- Pass 4: The server processes then CtoS and the additional information according to the rules of the HLS authentication mechanism valid for the given AA and sends the result to the client. The client checks if f(CtoS) is the result of correct processing and – if so – it accepts the authentication of the server.`

Source: `ch9-9-2-….md` §9.2.2.2.2.4, p.207 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

Table 50 – "DLMS/COSEM HLS authentication mechanisms", row `mechanism_id(7) HLS ECDSA`:

| Pass 1: C→S | Pass 2: S→C | Pass 3: C→S f(StoC) | Pass 4: S→C f(CtoS) |
|---|---|---|---|
| `CtoS: Random string 32 to 64 octets` `Optionally: System-Title-C in calling-AP-title, Cert-Sign-Client in calling-AE-qualifier` | `StoC: Random string 32 to 64 octets` `Optionally: System-Title-S in responding-AP-title, Cert-Sign-Server responding-AE-qualifier` | `ECDSA( SystemTitle-C || SystemTitle-S || StoC II CtoS)` | `ECDSA( SystemTitle-S || SystemTitle-C || CtoS II StoC)` |

Same table, surrounding rows and legends:

* `mechanism_id(2) HLS man. Spec.` — `CtoS: Random string 8-64 octets`, `StoC: Random string 8-64 octets`
* `mechanism_id(5) HLS GMAC` / `mechanism_id(6) HLS SHA-256`: `CtoS: Random string 8-64 octets Optionally: System-Title-C in calling-AP-title`, `SC II IC II GMAC(SC || AK || StoC)`, `SHA-256 (HLS_Secret || SystemTitle-C || SystemTitle-S || StoC II CtoS)`, `SHA-256 (HLS_Secret || SystemTitle-S || SystemTitle-C || CtoS || StoC)`
* Legend: `C: Client, S: Server, CtoS: Challenge client to server, StoC: Challenge server to client`; `IC: Invocation counter`; `xx.request / .response: xDLMS service primitives used to access the reply_to_HLS authentication method of the "Association SN / LN" object.`
* `1 The use of authentication mechanisms 3 and 4 are not recommended for new implementations.`
* `NOTE The system titles and the Certificates have to be sent only if not already known by the other party.`

> `Where the system titles and the certificates for the digital signature key are also needed, these may be transported in the AARQ / AARE APDUs, carrying the COSEM-OPEN service .request / .response, see Figure 89. The System_Title and Cert-Sign may be already known; in this case they do not have to be transported. If these elements are not available, the result of the processing of the challenge fails and the AA shall not be established.`

Source: `ch9-9-2-….md` §9.2.7.4, Table 50, p.260–261 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

ACSE carrier fields (Green Book 9.4.4.1): `calling-AE-qualifier: This field can be used to transport the public key certificate of the digital signature key of the client.` and `Responding_AE_Qualifier: This field can be used to transport the public key certificate of the digital signature key of the server`. Mechanism OID: `COSEM_high_level_security_mechanism_name_using_ECDSA ::= mechanism_id(7)`.

Source: `ch9-9-4-….md` §9.4.4.1, p.316, and §9.4.2.2.3, Table 83, p.313 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-4-dlms-cosem-application-layer-protocol-specificat.md`

The method that carries pass 3 is `reply_to_HLS_authentication (data)` of Association SN/LN, with `data ::= octet-string client's response to the challenge` and the response `data ::= octet-string server's response to the challenge`.

Source: `ch4-4-4-….md` §4.4.4.3.1, p.119 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`

**Hash used for HLS ECDSA.** Table 50 writes `ECDSA(...)` without naming the hash. The hash is determined indirectly by 9.2.3.4.5 (SHA-256 for suite 1 / P-256, SHA-384 for suite 2 / P-384). **UNCERTAIN**: no file states the hash for HLS ECDSA in the same sentence as the mechanism.

### 4.4 Test vector – Table 52 "HLS example using authentication-mechanism 7 with ECDSA"

| Security Material | X | Contents | LEN (Bytes) |
|---|---|---|---|
| Security Suite | | `ECDH-ECDSA-AES-128-GCM` | |
| Curve | | `P-256` | |
| Domain Parameters | D | `See Table A. 1.` | |
| System Title Client | Sys-TC | `4D4D4D0000BC614E` | 8 |
| System Title Server | Sys-TS | `4D4D4D0000000001` | 8 |
| Private Key Client | Pri-KC | `E9A045346B2057F1820318AB125493E9AB36CE590011C0FF30090858A118DD2E` | 32 |
| Private Key Server | Pri-KS | `B582D8C910018302BA3131BAB9BB6838108BB9408C30B2E49285985256A59038` | 32 |
| Public Key Client | Pub-KC | `917DBFECA43307375247989F07CC23F53D4B963AF8026C749DB33852011056DFDBE8327BD69CC149F018A8E446DDA6C55BCD78E596A56D403236233F93CC89B3` | 64 |
| Public Key Server | Pub-KS | `E4D07CEB0A5A6DA9D2228B054A1F5E295E1747A963974AF75091A0B0BC2FB92DA7D2ABD9FDD41579F36A1C8171A0CB638221DF1949FD95C8FAE148896920450D` | 64 |
| Challenge Client To Server | CtoS | `2CA1FC2DE9CD03B5E8E234CEA16F2853F6DC5F54526F4F4995772A50FB7E63B3` | 32 |
| Challenge Server To Client | StoC | `18E95FFE3AD0DCABDC5D0D141DC987E270CB0A395948D4231B09DE6579883657` | 32 |
| `ECDSA(SystemTitle-C || SystemTitle-S ||StoC || CtoS)` (calculated with Pri-KC) | f(StoC) | `C5C6D6620BDB1A39FCE50F4D64F0DB712D6FB57A64030B0C297E1250DC859660D3B1FA334AD80411807369F5DD3BC17B59894C9E9C11C59376580D15A2646D16` | 64 |
| `ECDSA(SystemTitle-S || SystemTitle-C || CtoS || StoC)` (calculated with Pri-KS) | f(CtoS) | `946C2E3E4F18291571F4A45ACB7086100574694A3BAF67D2D147FE8F92481A5AB2186C5CBC3F80E94482D9388B85C6A73E5FD687F09773C1F615AA2A905ED057` | 64 |
| `NOTE The values of the public keys are represented here as FE2OS(xp)II FE2OS(yp).` | | | |

Both signature values are exactly 64 bytes, consistent with the plain `R || S` format for P-256.

Source: `ch9-9-2-….md` §9.2.7.4, Table 52, p.262 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

A second, non-ECDSA test vector is provided in the same section: Table 51 – "HLS example using authentication-mechanism 5 with GMAC" (Security suite `GCM-AES-128`, `SC = 10`, `CtoS = 4B35366956616759`, `StoC = 503677524A323146`, `T = GMAC (SC II AK II StoC) = 1A52FE7DD3E72748973C1E28`, `f(StoC) = SC II IC II T = 10000000011A52FE7DD3E7274893C1E28`).

Source: `ch9-9-2-….md` §9.2.7.4, Table 51, p.261 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

### 4.5 ECDSA for protecting xDLMS APDUs and COSEM data

> `The algorithm is the elliptic curve digital signature algorithm (ECDSA) as specified in 9.2.3.4.5. The structure of the general-signing APDU is shown in Figure 110. For the additional fields, see Table 47 and 9.3.5.`

ASN.1 of the APDU carrying the signature:

```asn1
General-Signing ::= SEQUENCE
{
transaction-id                      OCTET STRING,
originator-system-title             OCTET STRING,
recipient-system-title              OCTET STRING,
date-time                           OCTET STRING,
other-information                   OCTET STRING,
content                             OCTET STRING,
signature                           OCTET STRING
}
```

Source: `ch9-9-5-….md` §9.5, "General APDUs" — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-5-abstract-syntax-of-cosem-pdus.md`

> `The Protection_Element parameter is conditional: it shall be present if the APDU has been authenticated or digitally signed. It may be present in all type of service invocations, but it may be empty if it is not yet available (this may occur in the case when general block transfer is used). It contains: - in the case of General_Ciphering, the Invocation_Counter, holding the invocation field of the initialization vector, see 9.2.3.3.7.3; - in the case when the APDU has been authenticated, the authentication tag - in the case when the APDU has been signed, the digital signature.`

Source: `ch9-9-3-….md` §9.3.5 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-3-dlms-cosem-application-layer-service-specificati.md`

> `- to apply digital signature, the general-signing APDU is used.`
> `Both the general-ciphering and general-signing APDUs may include the Originator_System_Title and the Recipient_System_Title. This allows the party that applied the protection to be identified and the party that shall check / remove the protection.`

Source: `ch9-9-2-….md` §9.2.7.3, p.259 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

For COSEM data (9.2.7.5): `"Data protection" objects allow applying or removing protection when reading or writing a list of attributes, or when invoking methods of COSEM objects. Protection to be applied / removed may include any combination of authentication, encryption and digital signature.` The "Data protection" IC is at `DLMS UA 1000-1 Part 2 Ed.15:2021, 4.4.9`.

Source: `ch9-9-2-….md` §9.2.7.5, p.262 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

**UNCERTAIN / NOT FOUND**: the exact byte layout of the signed data for `general-signing` (what exactly `content` includes relative to the `signature`) is only given by Figure 110, which is an image in the Markdown conversion and contains no extractable text. No verbatim rule such as "signature = ECDSA(transaction-id || originator-system-title || …)" for general-signing was found in the text. The only explicit ECDSA-over-a-defined-string formula found in these files is the HLS ECDSA one in Table 50 and the key_agreement one (`ECDSA(key_id || Qe,U)`).

---

## 5. COSEM interface classes that configure security

### 5.1 "Security setup" — `class_id = 64, version = 1` (current)

Green Book reference: `DLMS UA 1000-1 Part 2 Ed.15:2021, 4.4.7`. Blue Book Ed. 17 part 2 clause `4.4.7`.

> `Instances of the "Security setup" IC contain the necessary information on the security suite in use and the security policy applicable between a client and a server identified by their respective system title. They also provide methods to increase the level of security and to manage symmetric keys, asymmetric key pairs and certificates.`

Attributes (index, name, data type, short name):

| Index | Attribute | Data type | Short name |
|---|---|---|---|
| 1 | `logical_name (static)` | `octet-string` | `x` |
| 2 | `security_policy (static)` | `enum` | `x + 0x08` |
| 3 | `security_suite (static)` | `enum` | `x + 0x10` |
| 4 | `client_system_title (dyn.)` | `octet-string` | `x + 0x18` |
| 5 | `server_system_title (static)` | `octet-string` | `x + 0x20` |
| 6 | `certificates (dyn.)` | `array` | `x + 0x28` |

Specific methods:

| Index | Method | m/o | Short name |
|---|---|---|---|
| 1 | `security_activate (data)` | `o` | `x + 0x30` |
| 2 | `key_transfer (data)` | `o` | `x + 0x38` |
| 3 | `key_agreement (data)` | `o` | `x + 0x48` |
| 4 | `generate_key_pair (data)` | `o` | `x + 0x50` |
| 5 | `generate_certificate_request (data)` | `o` | `x + 0x58` |
| 6 | `import_certificate (data)` | `o` | `x + 0x60` |
| 7 | `export_certificate (data)` | `o` | `x + 0x68` |
| 8 | `remove_certificate (data)` | `o` | `x + 0x70` |

(Note: the attribute table in this IC has empty Min./Max./Def. columns in both Markdown conversions; only the legacy version 0 gives numeric Min./Max. — see §5.2 and §6.3.)

Source: `ch4-4-4-….md` §4.4.7.1, p.133 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`

**`security_policy` (attribute 2)** —

> `Enforces authentication and/or encryption and/or digital signature using the security algorithms available within the security suite.`
> `It applies independently for requests and responses.`
> `enum: When the enum value is interpreted as an unsigned, the meaning of each bit is as shown below:`
> `Bit Security policy / 0 unused, shall be set to 0, / 1 unused, shall be set to 0, / 2 authenticated request, / 3 encrypted request, / 4 digitally signed request, / 5 authenticated response, / 6 encrypted response, / 7 digitally signed response`
> `NOTE With this, the value (0) means that no cryptographic protection is required, as in version 0 of the "Security setup" IC.`

Source: `ch4-4-4-….md` §4.4.7.2.2, p.133 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`; identical in `ch9-9-2-….md` §9.2.7.2.2, Table 42, p.248 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

**`security_suite` (attribute 3)** — see §6.1.

**`client_system_title` (attribute 4)** — `Carries the (current) client system title`, `during confirmed or unconfirmed AA establishment, it is carried by the calling-AP-title field of the AARQ APDU`, `in a pre-established AA, it can be written by the client using an unsecured service.`

**`server_system_title` (attribute 5)** — `Carries the server system title.`, `during confirmed AA establishment, it is carried by the responding-AP-title field of the AARE APDU.`, `This attribute shall be read only.`

Source: `ch4-4-4-….md` §4.4.7.2.4–§4.4.7.2.5, p.134 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`

**`certificates` (attribute 6)** —

> `Carries information on X.509 v3 certificates available and stored in the server.`
> `array certificate_info certificate_info::= structure { certificate_entity: enum: (0) server, (1) client, (2) certification authority, (3) other certificate_type: enum: (0) digital signature, (1) key agreement, (2) TLS, (3) other serial_number: octet-string, issuer: octet-string, subject: octet-string, subject_alt_name: octet-string }`
> `For the elements serial_number, issuer, subject, subject_alt_name see DLMS UA 1000-2 Ed.11:2021, 9.2.6.4.`
> `The octet-strings that hold the serial_number, issuer, subject, and subject_alt_name shall include the tag, length and value (TLV) of the corresponding field of the Certificate.`

which certificates are stored: `For the server: – Digital Signature Certificate, – Static Key Agreement Certificate, – TLS Certificate.` / `For each client and third party: – Digital Signature Certificate, – Static Key Agreement Certificate, – TLS Certificate.` / `For Certification Authorities: – Certification Authority Certificate.`

Source: `ch4-4-4-….md` §4.4.7.2.6, p.134 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`

**Methods relevant to suites and keys** (all verbatim summaries):

* `security_activate (data)` — `Activates and strengthens the security policy:` / `data ::= enum, as specified at the security_policy attribute.` / `Strengthening the security policy means that another kind of protection is added.` / `Once a kind of protection is added, it cannot be removed. If the method is invoked with a value indicating a security policy that is weaker than the value of the security_policy attribute, the method invocation fails.` / `The new security policy applies as soon as the method invocation has been confirmed with success.`
* `key_transfer (data)` — `Used to transfer one or more symmetric keys.` / `data ::= array key_transfer_data key_transfer_data ::= structure { key_id: enum: (0) global unicast encryption key, (1) global broadcast encryption key, (2) authentication key, (3) master key (KEK) key_wrapped: octet-string }` / `The key wrap algorithm is as specified by the security suite. In suites 0, 1, and 2 the AES key wrap algorithm is used.` / `The KEK is the master key.`
* `key_agreement (data)` — `Used to agree on one or more symmetric keys using the key agreement algorithm as specified by the security suite. In the case of suites 1 and 2 the ECDH key agreement algorithm is used with the Ephemeral Unified Model C(2e, 0s, ECC CDH) scheme.` / `data ::= array key_agreement_data key_agreement_data ::= structure { key_id: enum: (0) global unicast encryption key, (1) global broadcast encryption key, (2) authentication key, (3) master key (KEK) key_data: octet-string }` / `The element key_data is the public key of ephemeral key pair right concatenated with digital signature, which is calculated over the key_id value and public key of ephemeral key pair value using the digital signature private key: Qe,U II ECDSA(key_id II Qe,U).`
* `generate_key_pair (data)` — `Generates an asymmetric key pair as required by the security suite. The data parameter identifies the usage of the key pair to be generated.` / `data ::= enum: (0) digital signature key pair, (1) key agreement key pair, (2) TLS key pair` / `NOTE 2 Key agreement key pair is the static key used with the One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) scheme when the server takes the role of Party V or with the Static Unified Model C(0e, 2s, ECC CDH) scheme.`
* `generate_certificate_request (data)` — `the server sends the Certificate Signing Request (CSR) data that is necessary for a CA to generate a certificate for a server public key`, `response data ::= octet-string`, `The octet-string contains the DER encoding of the CSR as specified in PKCS #10 (RFC 2986).`
* `import_certificate (data)` — `Imports an X.509 v3 certificate of a public key.` / `data ::= octet-string`
* `export_certificate (data)` — `Exports an X.509 v3 certificate in the server.` / `data ::= certificate_identification certificate_identification ::= structure { certificate_identification_type: enum: (0) certificate_identification_entity, (1) certificate_identification_serial certification_identification_options: CHOICE {…} }` with `certificate_identification_by_entity` carrying `certificate_entity`, `certificate_type`, `system_title` and `certificate_identification_by_serial` carrying `serial_number`, `issuer`; `response data octet-string is formatted as X.509 v3 DER format.`
* `remove_certificate (data)` — `Removes X.509 v3 certificate in the server.` / `The certificates of the server for digital signature, key agreement and TLS cannot be removed from the server.`

Source: `ch4-4-4-….md` §4.4.7.3.1–§4.4.7.3.8, p.135–139 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`

### 5.2 "Security setup" — `class_id = 64, version = 0` (previous version)

> `Instances of this IC contain the necessary information on the security policy applicable and the security suite in use within a particular AA, between two systems identified by their client system title and server system title respectively. They also contain methods to increase the level of security and to transfer the global keys. See DLMS UA 1000-2 Ed. 10:2020, Clause 5.`

| Index | Attribute | Data type | Min. | Max. | Def. | Short name |
|---|---|---|---|---|---|---|
| 1 | `logical_name (static)` | `octet-string` | | | | `x` |
| 2 | `security_policy (static)` | `enum` | `0` | `3` | `0` | `x + 0x08` |
| 3 | `security_suite (static)` | `enum` | `0` | `0` | `0` | `x + 0x10` |
| 4 | `client_system_title (dyn.)` | `octet-string` | | | | `x + 0x18` |
| 5 | `server_system_title (static)` | `octet-string` | | | | `x + 0x20` |

Methods: `1. security_activate (data)` (`o`, `x + 0x28`), `2. global_key_transfer (data)` (`o`, `x + 0x30`).

Version 0 `security_policy`: `enum: (0) nothing, (1) all messages to be authenticated, (2) all messages to be encrypted, (3) all messages to be authenticated and encrypted (4) …(15) reserved`.
Version 0 `security_suite`: `Specifies authentication, encryption and key transport algorithm.` / `enum: (0) AES-GCM-128 for authenticated encryption and AES-128 for key wrapping (1) …(15) reserved`.
Version 0 `global_key_transfer (data)`: `{ key_id: enum: (0) global unicast encryption key, (1) global broadcast encryption key, (2) authentication key key_wrapped: octet-string }` — note: **no master key (KEK) entry** in version 0.

Source: `ch5-5-4-….md` §5.4.8, p.493–494 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch5\markdown\ch5-5-4-previous-versions-of-interface-classes-for-acces.md`; also `Blue-Book-Ed-17-part-2-V1.0.md` §5.4.8 — `D:\project\personal\dlms\GreenBook\output\blue-book\human\Blue-Book-Ed-17-part-2-V1.0.md`

### 5.3 "Association LN" — `class_id = 15, version = 3`

| Index | Attribute | Data type | Short name |
|---|---|---|---|
| 1 | `logical_name (static)` | `octet-string` | `x` |
| 2 | `object_list (static)` | `object_list_type` | `x + 0x08` |
| 3 | `associated_partners_id` | `associated_partners_type` | `x + 0x10` |
| 4 | `application_context_name` | `context_name_type` | `x + 0x18` |
| 5 | `xDLMS_context_info` | `xDLMS_context_type` | `x + 0x20` |
| 6 | `authentication_mechanism_name` | `mechanism_name_type` | `x + 0x28` |
| 7 | `secret` | `octet-string` | `x + 0x30` |
| 8 | `association_status` | `enum` | `x + 0x38` |
| 9 | `security_setup_reference (static)` | `octet-string` | `x + 0x40` |
| 10 | `user_list (static)` | `array` | `x + 0x48` |
| 11 | `current_user` | `structure` | `x + 0x50` |

Methods: `1. reply_to_HLS_authentication (data)` `x + 0x60`, `2. change_HLS_secret (data)` `x + 0x68`, `3. add_object (data)` `x + 0x70`, `4. remove_object (data)` `x + 0x78`, `5. add_user (data)` `x + 0x80`, `6. remove_user (data)` `x + 0x88`.

Key definitions:

* `object_list` — `Contains the list of visible COSEM objects with their class_id, version, logical_name and the access rights to their attributes and methods within the given AA.` Its `access_right`/`attribute_access_descriptor`/`method_access_descriptor` bit meanings are the same bit list as Table 43 (bits 0 read-access, 1 write-access, 2 authenticated request, 3 encrypted request, 4 digitally signed request, 5 authenticated response, 6 encrypted response, 7 digitally signed response; for methods bit 0 = access, bit 1 = not-used).
* `xDLMS_context_info` — `xDLMS_context_type ::= structure { conformance: bit-string, max_receive_pdu_size: long-unsigned, max_send_pdu_size: long-unsigned, dlms_version_number: unsigned, quality_of_service: integer, cyphering_info: octet-string }` with `the cyphering_info element – in an active AA – contains the dedicated key parameter of the xDLMS initiateRequest APDU.`
* `authentication_mechanism_name` — `The authentication mechanism name is specified as an OBJECT IDENTIFIER in DLMS UA 1000-2 Ed.11:2021, 9.5.` Example for `mechanism_id(1)`: `09 07 60 85 74 05 08 02 01`.
* `secret` — `Contains the secret for the LLS or HLS authentication process.` `NOTE In the case of HLS with GMAC, the (HLS) secret is held by the "Security setup" object referenced in attribute 9, security_setup_reference`.
* `association_status` — `enum: (0) non-associated, (1) association-pending, (2) associated`
* `security_setup_reference` — `References a "Security setup" object by its logical name. The referenced object manages security for a given "Association LN" object instance.`

Source: `ch4-4-4-….md` §4.4.4.1–§4.4.4.3.6, p.113–120 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`

### 5.4 "Association SN" — `class_id = 12, version = 4`

| Index | Attribute | Data type | Short name |
|---|---|---|---|
| 1 | `logical_name (static)` | `octet-string` | `x` |
| 2 | `object_list (static)` | `objlist_type` | `x + 0x08` |
| 3 | `access_rights_list (static)` | `access_rights_type` | `x + 0x10` |
| 4 | `security_setup_reference (static)` | `octet-string` | `x + 0x18` |
| 5 | `user_list (static)` | `array` | `x + 0x20` |
| 6 | `current_user` | `structure` | `x + 0x28` |

Methods: 1, 2 reserved; `3. read_by_logicalname (data)` `x + 0x30`; 4 reserved; `5. change_secret (data)` `x + 0x40`; 6, 7 reserved; `8. reply_to_HLS_authentication (data)` `x + 0x58`; `9. add_user (data)` `x + 0x60`; `10. remove_user (data)` `x + 0x68`.

* `access_rights_list` — `access_rights_element ::= structure { base_name: long, attribute_access: attribute_access_descriptor, method_access: method_access_descriptor }`, sorted by `base_name`; the attribute/method `access_mode` bit meanings are as in §5.3 (bits 0/1 access kinds, 2–7 protection).
* `security_setup_reference` — `References the "Security setup" object by its logical_name. The referenced object manages security for a given "Association SN" object instance.` — datatype `octet-string`.
* `reply_to_HLS_authentication` — same semantics as in Association LN.

Source: `ch4-4-4-….md` §4.4.3.1–§4.4.3.3.8, p.108–113 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`

### 5.5 "Data protection" — `class_id = 30, version = 0`

`### 4.4.9 COSEM data protection (class_id = 30, version = 0)`. Relevant statements:

> `The security suite is determined by the "Security setup" object referenced from the current "Association SN" / "Association LN" object.`
> `APDUs carrying service invocations to access attributes and methods of "Data protection" objects are protected as stipulated by access rights to these attributes and methods, and by "Security setup" security_suite and security_policy.`
> `The master key and Certificates – as required by the security suite – are held by "Security setup".`
> `f) prerequisites: protection_object_list, protection_parameters_get, master key, key agreement and digital signature certificates as needed;`

Attributes include (from the clause's headings): `logical_name` (`4.4.9.2.1`), `protection_buffer` (`4.4.9.2.2`), `protection_object_list` (`4.4.9.2.3`), `protection_parameters_get` (`4.4.9.2.4`), `protection_parameters_set` (`4.4.9.2.5`), `required_protection` (`4.4.9.2.6`). Methods: `get_protected_attributes`, `set_protected_attributes`, `invoke_protected_method`.

Source: `ch4-4-4-….md` §4.4.9.1, §4.4.9.4 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`

### 5.6 "Attestation" (also security-related, mentioned in the same OBIS table)

`Instances of the IC "Attestation" model the request to the server to generate an Attestation Token, see 4.20.` — listed with `170, Attestation` and OBIS `0-b:43.3.e.255`.

Source: `ch6-6-2-….md` §6.2.36, p.656 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch6\markdown\ch6-6-2-abstract-cosem-objects.md`

### 5.7 OBIS naming of the "Security setup" instances

> `Instances of the IC "Security setup" – see 4.4.7 – are used to set up the message security features. For each Association object, there is one Security setup object managing security within that AA. See 5.4.2 and 5.4.3. Value group E numbers the instances.`

OBIS code table ("Security setup objects"):

| Object | IC | A | B | C | D | E | F |
|---|---|---|---|---|---|---|---|
| Security setup | `64, Security setup` | `0` | `0` | `43` | `0` | `e` | `255` |
| Attestation | `170, Attestation` | `0` | `b` | `43` | `3` | `e` | `255` |

i.e. Security setup instances are `0-0:43.0.e.255`.

Source: `ch6-6-2-….md` §6.2.36, p.656 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch6\markdown\ch6-6-2-abstract-cosem-objects.md`

### 5.8 Class id list — where 64 and 30 sit

The IC overview diagram in the Blue Book lists (extract): `Association SN class_id = 12`, `Association LN class_id = 15`, `SAP Assignment class_id = 17`, `Image transfer class_id = 18`, `Data protection class_id = 30`, `Push setup class_id = 40`, `Security setup class_id = 64`, `Function control class_id = 122`, `Array manager class_id = 123`, `Comm. port protection class_id = 124`.

Source: `ch4-4-2-iso-iec-14908-….md` §4.4 overview figure p.107 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-2-iso-iec-14908-overview-of-the-cosem-interface-cl.md`

### 5.9 `GLO_...` objects

**NOT FOUND in these files.** No occurrence of `GLO_`, `GLO `, `GBEK`, `GUEK` (as object names), or `0.0.43`/`0-0:43` outside the Security-setup OBIS table was found in:
`D:\project\personal\dlms\GreenBook\output\blue-book-v2\` (all Markdown), `D:\project\personal\dlms\GreenBook\output\blue-book\human\Blue-Book-Ed-17-part-2-V1.0.md`, or `D:\project\personal\dlms\GreenBook\output\blue-book-v2\human\`.

The only `GUEK`/`GBEK`/`Global Unicast Encryption Key` identifiers found in the sources are the *key* names used in Green Book ch. 9 (Table 28, Table 29, Annex C test vectors) and in the `Key-Id` ASN.1 enumeration. The `glo-ciphering` APDUs (`general-glo-ciphering`, service-specific `glo-ciphering`) exist as APDU types, but the files contain **no** COSEM object naming of the form `GLO_…`. The `key_id` enum values `(0) global unicast encryption key`, `(1) global broadcast encryption key` are the closest documented identifiers for those keys.

Source (for the absence, i.e. searched coverage): `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\` (all Markdown), `D:\project\personal\dlms\GreenBook\output\blue-book\human\Blue-Book-Ed-17-part-2-V1.0.md`; and for the key names: `ch9-9-2-….md` §9.2.5.1–§9.2.5.2, `ch9-9-5-….md` §9.5 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`, `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-5-abstract-syntax-of-cosem-pdus.md`

Also **NOT FOUND**: any occurrence of the literal string `KEK` used as an *attribute name* of Security setup; the master key is only reachable through the `key_id` enum value `(3) master key (KEK)` in the `key_transfer` / `key_agreement` parameters and through footnotes such as `1) Held by a "Security setup" object.`

---

## 6. The numeric "security suite" value in the association configuration

### 6.1 The `security_suite` attribute — Security setup, attribute index 3, data type `enum`

> `Specifies the security algorithms available.`
> `enum:`
> `(0) AES-GCM-128 authenticated encryption and AES-128 key wrap,`
> `(1) AES-GCM-128 authenticated encryption, ECDSA P-256 digital signature, ECDH P-256 key agreement, SHA-256 hash, V.44 compression and AES-128 key wrap,`
> `(2) AES-GCM-256 authenticated encryption, ECDSA P-384 digital signature, ECDH P-384 key agreement, SHA-384 hash, V.44 compression and AES-256 key wrap,`
> `(3) … (15) reserved`

Attribute index `3`, short name `x + 0x10`, data type `enum`.

Source: `ch4-4-4-….md` §4.4.7.2.3, p.134 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`; identical text in `Blue-Book-Ed-17-part-2-V1.0.md` §4.4.7.2.3 — `D:\project\personal\dlms\GreenBook\output\blue-book\human\Blue-Book-Ed-17-part-2-V1.0.md`

So the permitted values are **0, 1, 2**; **3…15** are reserved.

### 6.2 The `Security_Suite_Id` field in the Security Control Byte (on the wire)

> `The security header SH includes the security control byte concatenated with the invocation counter: SH = SC II IC. The security control byte is shown in Table 45 where:`
> `- Bit 3…0: Security_Suite_Id, see 9.2.3.7`
> `- Bit 4: "A" subfield: indicates that authentication is applied`
> `- Bit 5: "E" subfield: indicates that encryption is applied`
> `- Bit 6: Key_Set subfield: 0 = Unicast, 1 = Broadcast;`
> `- Bit 7: Indicates the use of compression.`

Table 45 – Security control byte: `Bit 7 = Compression`, `Bit 6 = Key_Set`, `Bit 5 = E`, `Bit 4 = A`, `Bit 3..0 = Security_Suite_Id`. Its footnote: `The Key_Set bit is not relevant and shall be set to 0 when the service-specific dedicated ciphering, the general-ded-ciphering or the general-ciphering APDUs are used.`

The allowed values of `Security_Suite_Id` are the suite ids of Table 27 (`0`, `1`, `2`), because `Security_Suite_Id, see 9.2.3.7` and Table 27 lists `0`, `1`, `2` with `All other reserved`.

Source: `ch9-9-2-….md` §9.2.7.2.4.2, Table 45, p.251 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

Related: 9.2.7.2.4.9 Table 46's row description — `Provides information on the protection applied, the key-set and the security suite used. See Table 45. 1)`

Source: `ch9-9-2-….md` §9.2.7.2.4.9, p.254 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

### 6.3 The legacy range (Security setup version 0)

`security_suite (static)` in `class_id = 64, version = 0` has `Min. 0`, `Max. 0`, `Def. 0` and value list `enum: (0) AES-GCM-128 for authenticated encryption and AES-128 for key wrapping (1) …(15) reserved`. So in version 0 the only defined value is **0**.

Source: `ch5-5-4-….md` §5.4.8.1, §5.4.8.2.3, p.493 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch5\markdown\ch5-5-4-previous-versions-of-interface-classes-for-acces.md`

### 6.4 Where the suite id is *not* encoded

* **UNCERTAIN / NOT FOUND**: no security-suite field in the AARQ/AARE APDU is documented in these files. The AARQ carries `application-context-name`, `calling-AP-title` (system title), `calling_AE_invocation_identifier`, `calling-AE-qualifier` (certificate) and the authentication functional unit fields; the suite is not among them.
  Source: `ch9-9-4-….md` §9.4.4.1, p.315–316 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-4-dlms-cosem-application-layer-protocol-specificat.md`
* The "security suite" is part of the security context, and the security context is held by "Security setup" objects: `The security context defines security attributes relevant for cryptographic transformations and includes the following elements: - the security suite, determining the security algorithms available, see 9.2.3.7 …` / `The security context is managed by "Security setup" objects`.

  Source: `ch9-9-2-….md` §9.2.2.3, p.208 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`

---

## 7. Suite 3 and beyond; mandatory / optional / deprecated

### 7.1 Suite 3 or any suite beyond 0/1/2

**NOT FOUND.** No occurrence of `Suite 3`, `suite 3`, `Suite 4`, or `security suite 3` exists in any of the searched Markdown (Green Book `output\book\ai` and ch9 outputs, Blue Book `output\blue-book-v2` and `output\blue-book`). The highest defined suite is **2**.

The files state only:

* Table 27: rows `0`, `1`, `2`, then `All other reserved`.
* Security setup v1 `security_suite`: `(3) … (15) reserved`.
* Security setup v0 `security_suite`: `(1) …(15) reserved`.
* Security setup v0 `security_policy`: `(4) …(15) reserved`.

Source: `ch9-9-2-….md` §9.2.3.7, Table 27 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`; `ch4-4-4-….md` §4.4.7.2.3 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`; `ch5-5-4-….md` §5.4.8.2.3 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch5\markdown\ch5-5-4-previous-versions-of-interface-classes-for-acces.md`

### 7.2 Mandatory / optional for suites

**UNCERTAIN / NOT FOUND.** The searched files contain no statement of the form "suite X is mandatory", "suite Y is optional", or "support of suite Z is required". What the files *do* say that constrains suite choice:

* Suite 0 supports only `AES-GCM-128` plus `AES-128 key wrap` — its Digital signature, Key agreement and Hash columns are `–` (Table 27). Consequence stated elsewhere: `In the case of suites 1 and 2 the ECDH key agreement algorithm is used…` (Security setup `key_agreement`) and the AES key sizes: `- for security suite 0 and 1, 128 bits (16 octets): len(EK) = 128 - for security suite 2, 256 bits (32 octets): len(EK) = 256` and the same for KEK.
* `The bit length of the authentication tag, denoted t, is a security parameter. In security suites 0, 1 and 2 its value shall be 96 bits.`
* AARQ note: `NOTE 2 The elements (System_Title), (Certificate) and (Client_User_Id) are optional.`

Source: `ch9-9-2-….md` §9.2.3.7 Table 27; §9.2.3.3.7.4 (`len(EK)`), §9.2.3.3.8 (`len(KEK)`), §9.2.3.3.7.6 (tag length); §9.2.2.2.2.1 NOTE 2 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`; `ch4-4-4-….md` §4.4.7.3.3 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`

### 7.3 What the files *do* mark as deprecated / not recommended

The word "deprecated" is defined in ch3 as `not recommended for new implementations`. The only security mechanism flagged with that exact wording in the searched files is **not** a security suite but an HLS authentication mechanism:

> `1 The use of authentication mechanisms 3 and 4 are not recommended for new implementations.`

(mechanism_id(3) = `COSEM_high_level_security_mechanism_name_using_MD5`, mechanism_id(4) = `COSEM_high_level_security_mechanism_name_using_SHA-1`.)

Source: `ch9-9-2-….md` §9.2.7.4, Table 50 footnote 1 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-2-information-security-in-dlms-cosem.md`; and `ch3-3-2-….md` §3.2 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch3\markdown\ch3-3-2-definitions-related-to-cryptographic-security.md`; `ch9-9-4-….md` §9.4.2.2.3, Table 83 — `D:\project\personal\dlms\GreenBook\output\book\ai\ch9\markdown\ch9-9-4-dlms-cosem-application-layer-protocol-specificat.md`

Also relevant, and not a deprecation: security *policies* can only be strengthened, never weakened —

> `Once a kind of protection is added, it cannot be removed. If the method is invoked with a value indicating a security policy that is weaker than the value of the security_policy attribute, the method invocation fails.`

Source: `ch4-4-4-….md` §4.4.7.3.1, p.135 — `D:\project\personal\dlms\GreenBook\output\blue-book-v2\ai\ch4\markdown\ch4-4-4-interface-classes-for-access-control-and-managem.md`

---

## 8. Consolidated "UNCERTAIN / NOT FOUND" list

| Item | Status |
|---|---|
| `NSAA` naming / any spelling of it | **NOT FOUND** in any searched file |
| Security suite number inside Annex A | **NOT FOUND** – Annex A defines only curves/domain parameters |
| Security suite 3 or any suite > 2 | **NOT FOUND** – Table 27 ends at 2 with `All other reserved`; `(3) … (15) reserved` |
| Explicit mandatory/optional/deprecated statement about suites | **NOT FOUND** |
| `GLO_...` object names | **NOT FOUND** |
| Master key (KEK) as a Security setup *attribute* | **NOT FOUND** – only as `key_id (3) master key (KEK)` method parameter, plus footnotes `Held by a "Security setup" object` |
| Exact hash function for HLS ECDSA in Table 50 | **UNCERTAIN** – Table 50 writes only `ECDSA(...)`; hash follows from suite (SHA-256 for suite 1 / SHA-384 for suite 2) per 9.2.3.4.5 |
| Exact signed-byte-layout for the `general-signing` APDU | **UNCERTAIN / NOT FOUND** – Figure 110 is an image; no verbatim formula in text |
| Reconciliation of certificate `signatureValue` (DER SEQUENCE of 2 INTEGERs) with the 9.2.3.4.5 "plain format" `R II S` rule | **UNCERTAIN** – both rules present, no cross-reference |
| Per-suite restriction for C(1e,1s) and C(0e,2s) | **UNCERTAIN** – only "using the elliptic curves P-256 or P-384" is stated; suite 0 has no key agreement at all in Table 27 |
| Security suite field in AARQ/AARE | **NOT FOUND** – only in Security setup attribute 3 and in the Security Control Byte bits 3..0 |
| Key sizes for the curves other than field size 256/384 bits in Annex A | Annex A states the field size q and cofactor h = 1 only; no "key size" wording |

---

## 9. Quick-reference constant table

| Constant | Value | Where |
|---|---|---|
| Curve P-256 OID | `1.2.840.10045.3.1.7` | ch9-9-2 §9.2.3.4.2.2 Table 21; §9.2.6.4.3.5 |
| Curve P-384 OID | `1.3.132.0.34` | ch9-9-2 §9.2.3.4.2.2 Table 21; §9.2.6.4.3.5 |
| Public key algorithm OID | `1.2.840.10045.2.1` (`ECDSA and ECDH Public Key`) | ch9-9-2 §9.2.6.4.3.5; Annex B.1 |
| ecdsa-with-SHA256 OID | `1.2.840.10045.4.3.2` | ch9-9-2 §9.2.6.4.2 |
| ecdsa-with-SHA384 OID | `1.2.840.10045.4.3.3` | ch9-9-2 §9.2.6.4.2 |
| Suite 0 | `AES-GCM-128` + `AES-128 key wrap`; no ECDSA/ECDH/SHA | ch9-9-2 §9.2.3.7 Table 27 |
| Suite 1 | `ECDH-ECDSA-AES-GCM-128-SHA-256` | ch9-9-2 §9.2.3.7 Table 27 |
| Suite 2 | `ECDH-ECDSA-AES-GCM-256-SHA-384` | ch9-9-2 §9.2.3.7 Table 27 |
| Key agreement scheme ids | `0x01: C(1e, 1s ECC CDH)`, `0x02: C(0e,2s ECC CDH)` | ch9-9-2 §9.2.5.2 Table 29 |
| AlgorithmID AES-GCM-128 | `2.16.756.5.8.3.0` = `60 85 74 05 08 03 00` (7 octets) | ch9-9-2 §9.2.3.4.6.5 Table 26 |
| AlgorithmID AES-GCM-256 | `2.16.756.5.8.3.1` = `60 85 74 05 08 03 01` | ch9-9-2 §9.2.3.4.6.5 Table 26 |
| AlgorithmID AES-WRAP-128 | `2.16.756.5.8.3.2` = `60 85 74 05 08 03 02` | ch9-9-2 §9.2.3.4.6.5 Table 26 |
| AlgorithmID AES-WRAP-256 | `2.16.756.5.8.3.3` = `60 85 74 05 08 03 03` | ch9-9-2 §9.2.3.4.6.5 Table 26 |
| ECDSA signature encoding | `R II S`, `l = [log n]`, fixed `2l` octets (64 B for P-256) | ch9-9-2 §9.2.3.4.5 |
| HLS ECDSA mechanism id | `mechanism_id(7)` `COSEM_high_level_security_mechanism_name_using_ECDSA` | ch9-9-4 §9.4.2.2.3 Table 83 |
| HLS ECDSA signed strings | `ECDSA(SystemTitle-C \|\| SystemTitle-S \|\| StoC II CtoS)` / `ECDSA(SystemTitle-S \|\| SystemTitle-C \|\| CtoS II StoC)` | ch9-9-2 §9.2.7.4 Table 50 |
| Security setup class id / version | `class_id = 64, version = 1` (current), `version = 0` (previous) | ch4-4-4 §4.4.7; ch5-5-4 §5.4.8 |
| Association LN class id / version | `class_id = 15, version = 3` | ch4-4-4 §4.4.4 |
| Association SN class id / version | `class_id = 12, version = 4` | ch4-4-4 §4.4.3 |
| Data protection class id / version | `class_id = 30, version = 0` | ch4-4-4 §4.4.9 |
| Security setup OBIS | `0-0:43.0.e.255` | ch6-6-2 §6.2.36 |
| Authentication tag length | `96 bits` in suites 0, 1 and 2 | ch9-9-2 §9.2.3.3.7.6 |
| EK length | 128 bits for suites 0 and 1; 256 bits for suite 2 | ch9-9-2 §9.2.3.3.7.4 |
| KEK length | 128 bits for suites 0 and 1; 256 bits for suite 2 | ch9-9-2 §9.2.3.3.8 |
