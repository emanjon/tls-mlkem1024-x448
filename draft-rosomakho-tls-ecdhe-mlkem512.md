---
title: "Post-Quantum Hybrid ML-KEM-1024/X448 Key Agreement for TLS 1.3"
abbrev: "ML-KEM-1024/X448 Hybrid"
category: info

docname: draft-preuss_mattsson-tls-mlkem1024-x448-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: false
v: 3
area: "Security"
workgroup: "Transport Layer Security"
keyword:
 - tls
 - mlkem
 - hybrid
venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "emanjon/tls-mlkem1024-x448"
  latest: "https://yaroslavros.github.io/tls-ecdhe-mlkem512/draft-rosomakho-tls-ecdhe-mlkem512.html"

author:
- name: John | Preuß Mattsson
  organization: Ericsson
  country: Sweden
  email: john.mattsson@ericsson.com

normative:
  FIPS203: DOI.10.6028/NIST.FIPS.203
  RFC7748:

informative:

--- abstract

This document defines two post-quantum hybrid key exchange groups for TLS 1.3
that combine ML-KEM-512 with ECDHE: MLKEM512X25519 and SecP256r1MLKEM512.
These groups provide lower-overhead hybrid key exchange options for deployments
where ClientHello size, fragmentation risk, constrained-device performance, or
compatibility with existing network infrastructure are important
considerations. The groups defined in this document are intended for use with
TLS 1.3 and DTLS 1.3 and follow the hybrid key exchange construction used by
ECDHE-MLKEM key agreement for TLS 1.3.

--- middle

# Introduction

The transition to post-quantum cryptography requires new key exchange
mechanisms for TLS 1.3 {{!TLS=I-D.ietf-tls-rfc8446bis}}. Hybrid key exchange
combines a post-quantum key encapsulation mechanism with a traditional
elliptic-curve Diffie-Hellman key exchange, allowing deployments to gain
protection against future cryptographically relevant quantum computers while
retaining the security properties of widely deployed classical key exchange
mechanisms.

{{!TLS-HYBRID=I-D.ietf-tls-hybrid-design}} describes the general design for
hybrid key exchange in TLS 1.3, and
{{!TLS-ECDHE-MLKEM=I-D.ietf-tls-ecdhe-mlkem}} defines several ECDHE-MLKEM
hybrid groups based on ML-KEM-768 and ML-KEM-1024.

This document defines two additional ECDHE-MLKEM hybrid groups that use
ML-KEM-512:

* MLKEM512X25519
* SecP256r1MLKEM512

This document follows the construction and terminology of {{TLS-HYBRID}}. It
defines only additional TLS NamedGroup values and their associated key share
encodings. It does not modify the TLS 1.3 handshake, key schedule, or
negotiation mechanisms.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the terminology of TLS 1.3 {{TLS}} and hybrid key exchange
for TLS 1.3 {{TLS-HYBRID}}.

The term "ML-KEM" refers to the Module-Lattice-Based Key-Encapsulation
Mechanism defined in {{FIPS203}}.

# Motivation and Applicability

The ECDHE-MLKEM hybrid groups defined in {{TLS-ECDHE-MLKEM}} are appropriate
for general-purpose post-quantum hybrid deployments and provide higher
post-quantum security categories than ML-KEM-512. However, the use of
ML-KEM-768 or ML-KEM-1024 increases the size of TLS key shares.

Larger key shares increase the size of TLS handshake messages. In particular,
larger client key shares increase the size of the ClientHello, which can
increase the likelihood of fragmentation and may expose interoperability
problems in deployments involving legacy network devices, middleboxes, or other
network infrastructure with limitations around larger TLS ClientHello messages.
Larger key shares can also increase bandwidth, memory, and computational costs
for constrained endpoints or for deployments operating over lossy or
bandwidth-constrained networks.

The groups defined in this document use ML-KEM-512 in combination with
classical ECDHE key exchange. This provides hybrid post-quantum and classical
key exchange with lower bandwidth, memory, and computational overhead than
corresponding hybrid groups based on ML-KEM-768 or ML-KEM-1024.

The following table shows the key share sizes for the groups defined in this
document:

Group | Client key share size | Server key share size
--- | --- | ---
MLKEM512X25519 | 832 bytes | 800 bytes
SecP256r1MLKEM512 | 865 bytes | 833 bytes

ML-KEM-512 provides a lower post-quantum security category than ML-KEM-768 and
ML-KEM-1024. Deployments that can support hybrid groups based on ML-KEM-768 or
ML-KEM-1024 SHOULD generally prefer those groups. The groups defined in this
document are intended for constrained, compatibility-sensitive,
bandwidth-sensitive, or otherwise policy-selected deployments.

# Hybrid Group Definitions

This document defines two additional TLS NamedGroup values for use with the
TLS 1.3 `key_share` extension:

* MLKEM512X25519
* SecP256r1MLKEM512

Each group combines an ML-KEM-512 key exchange with an elliptic-curve
Diffie-Hellman key exchange. The hybrid key exchange values are encoded as the
concatenation of the component key exchange values. The component encodings are
fixed length and are therefore unambiguous.

For ML-KEM-512, the encapsulation key and ciphertext are encoded as defined in
{{FIPS203}}. The ML-KEM-512 encapsulation key is 800 octets, and the ML-KEM-512
ciphertext is 768 octets.

For X25519 and secp256r1, the public key encodings used in the `key_share`
extension are those defined in {{Section 4.2.8.2 of TLS}}. The X25519 public
key is the 32-octet public value for X25519 defined in
{{Section 5 of !ELLIPTIC-CURVES=RFC7748}}. The secp256r1 public key is encoded
as the `UncompressedPointRepresentation` and is 65 octets.

The server MUST perform the encapsulation key check described
in Section 7.2 of {{FIPS203}} on the client's ML-KEM-512 encapsulation key and
abort with an `illegal_parameter` alert if it fails.

The client MUST check that the ML-KEM-512 ciphertext length is
768 octets and abort with an `illegal_parameter` alert if it fails. If ML-KEM
decapsulation fails for any other reason, the connection MUST be aborted with
an `internal_error` alert.

Both client and server MUST process the ECDHE component as described in
{{Section 4.2.8.2 of TLS}}, including all validity checks, and abort with an
`illegal_parameter` alert if it fails.

## MLKEM512X25519

For MLKEM512X25519, the client key_exchange value contains the ML-KEM-512
encapsulation key followed by the X25519 public key:

~~~
struct {
    opaque kem_key[800];
    opaque ecdhe_key[32];
} MLKEM512X25519ClientShare;
~~~

The server key_exchange value contains the ML-KEM-512 ciphertext followed by
the X25519 public key:

~~~
struct {
    opaque kem_ciphertext[768];
    opaque ecdhe_key[32];
} MLKEM512X25519ServerShare;
~~~

The name MLKEM512X25519 reflects the order of the component algorithms in the
NamedGroup definition. This is the ordering convention specified by
{{Section 3.2 of TLS-HYBRID}}, which requires the order of shares in the
concatenated `key_exchange` value to match the order of algorithms indicated in
the definition of the NamedGroup. Accordingly, the ML-KEM-512 component appears
first in both the name and the encoded `key_exchange` value, followed by the
X25519 component.

This differs from the name X25519MLKEM768 defined in {{TLS-ECDHE-MLKEM}}.
That name is retained for historical compatibility reasons and is explicitly
documented by {{TLS-ECDHE-MLKEM}} as not following the naming convention in
{{Section 3.2 of TLS-HYBRID}}. This document follows the convention from
{{TLS-HYBRID}} for the new MLKEM512X25519 NamedGroup.

## SecP256r1MLKEM512

For SecP256r1MLKEM512, the client key_exchange value contains the secp256r1
ECDHE public key followed by the ML-KEM-512 encapsulation key:

~~~
struct {
    opaque ecdhe_key[65];
    opaque kem_key[800];
} SecP256r1MLKEM512ClientShare;
~~~

The server key_exchange value contains the secp256r1 ECDHE public key followed
by the ML-KEM-512 ciphertext:

~~~
struct {
    opaque ecdhe_key[65];
    opaque kem_ciphertext[768];
} SecP256r1MLKEM512ServerShare;
~~~

The component order for SecP256r1MLKEM512 follows the convention used by
{{TLS-ECDHE-MLKEM}} for NIST elliptic curves.

# Shared Secret Calculation

For each group defined in this document, the hybrid shared secret is the
concatenation of the component shared secrets. The resulting hybrid shared
secret is used as the ECDHE shared secret input to the TLS 1.3 key schedule.

For MLKEM512X25519, the ML-KEM shared secret is produced by ML-KEM-512
encapsulation and decapsulation, and the X25519 shared secret is produced by
the X25519 Diffie-Hellman operation. The hybrid shared secret is the
concatenation of the ML-KEM shared secret followed by the X25519 shared secret:

~~~
MLKEM512X25519_shared_secret =
    MLKEM512_shared_secret || X25519_shared_secret
~~~

The ML-KEM-512 shared secret is 32 octets, and the X25519 shared secret is 32
octets. The resulting hybrid shared secret is therefore 64 octets.

For SecP256r1MLKEM512, the ECDHE shared secret is produced by the secp256r1
Diffie-Hellman operation, and the ML-KEM shared secret is produced by
ML-KEM-512 encapsulation and decapsulation. The hybrid shared secret is the
concatenation of the ECDHE shared secret followed by the ML-KEM shared secret:

~~~
SecP256r1MLKEM512_shared_secret =
    SecP256r1_shared_secret || MLKEM512_shared_secret
~~~

The secp256r1 shared secret is the x-coordinate of the ECDH shared secret
elliptic curve point represented as an octet string, as described in
{{Section 7.4.2 of TLS}}. The secp256r1 shared secret is 32 octets, and the
ML-KEM-512 shared secret is 32 octets. The resulting hybrid shared secret is
therefore 64 octets.

Both client and server MUST calculate the ECDHE component of the shared secret
as described in {{Section 7.4.2 of TLS}}, including the all-zero shared secret
check for X25519. If this computation or validation fails, the endpoint MUST
abort the connection with an `illegal_parameter` alert.

# Regulatory Context

The regulatory considerations related to component ordering and the use of
hybrid ECDHE-MLKEM key exchange are discussed in
{{Section 5 of TLS-ECDHE-MLKEM}} and apply to the groups defined in this
document.

# Security Considerations

The security considerations outlined in {{Section 6 of TLS-HYBRID}} and
{{Section 6 of TLS-ECDHE-MLKEM}} apply to the groups defined in this document.
This document defines additional ECDHE-MLKEM hybrid groups and does not change
the TLS 1.3 handshake, key schedule, authentication mechanisms, or the general
hybrid key exchange construction.

The groups defined in this document use ML-KEM-512. ML-KEM-512 provides a lower
post-quantum security category than ML-KEM-768 and ML-KEM-1024. As a result,
the groups defined in {{TLS-ECDHE-MLKEM}} provide stronger post-quantum
security properties and are generally preferred when their larger key shares
and implementation costs are acceptable.

The groups defined in this document are intended for constrained,
compatibility-sensitive, bandwidth-sensitive, or otherwise policy-selected
deployments where the lower overhead of ML-KEM-512 is considered an acceptable
trade-off.

# IANA Considerations

This document requests/registers two new entries to the
[TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8),
according to the procedures in {{Section 6 of ?IANA-TLS=RFC9847}}.

## MLKEM512X25519

 Value:
 : 4586 (0x11EA)

 Description:
 : MLKEM512X25519

 DTLS-OK:
 : Y

 Recommended:
 : N

 Reference:
 : This document

 Comment:
 : Combining ML-KEM-512 with X25519 ECDH
{: spacing="compact"}

## SecP256r1MLKEM512

 Value:
 : 4585 (0x11E9)

 Description:
 : SecP256r1MLKEM512

 DTLS-OK:
 : Y

 Recommended:
 : N

 Reference:
 : This document

 Comment:
 : Combining secp256r1 ECDH with ML-KEM-512
 {: spacing="compact"}

--- back

# Acknowledgments
{:numbered="false"}

The author thanks the authors and contributors of {{TLS-HYBRID}} and
{{TLS-ECDHE-MLKEM}}, whose work this document builds on.
