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

author:
- name: John | Preuß Mattsson
  organization: Ericsson
  country: Sweden
  email: john.mattsson@ericsson.com

normative:
  FIPS203: DOI.10.6028/NIST.FIPS.203
  RFC7748:
  RFC9846:
  RFC9954:

informative:

  RFC10024:
  I-D.ietf-tls-mlkem:
  I-D.rosomakho-tls-ecdhe-mlkem512:
  I-D.yang-tls-hybrid-sm2-mlkem:  

--- abstract

This document defines a post-quantum/traditional hybrid key exchange algorithm for TLS 1.3 that combines ML-KEM-1024 with X448: MLKEM1024X448. The algorithm provides a hybrid key exchange option targeting a high security level. Compared with P-curves offering a similar security level, X448 is significantly faster and provides greater implementation robustness. Most importantly, a FIPS-validated implementation of MLKEM1024X448 guarantees that the ML-KEM-1024 component is FIPS-validated. This is not the case for SecP384r1MLKEM1024. The algorithm defined in this document is intended for use with TLS 1.3 and DTLS 1.3 and follows the hybrid key exchange construction used by ECDHE-MLKEM key agreement for TLS 1.3.

--- middle

# Introduction

The transition to post-quantum cryptography requires new key exchange mechanisms for TLS 1.3 {{RFC9846}}. Post-Quantum/Traditional (PQ/T) hybrid key exchange combines a post-quantum key algorithm such as ML-KEM {{FIPS203}} with a traditional key exchange algorithms such as X448 {{RFC7748}}, allowing deployments to gain protection against future Cryptanalytically Relevant Quantum Computers (CRQC) while retaining the security properties of previously trusted traditional key exchange algorithms.

{{RFC9954}} describes the general design for hybrid key exchange in TLS 1.3, and {{RFC10024}}{{I-D.rosomakho-tls-ecdhe-mlkem512}}{{I-D.yang-tls-hybrid-sm2-mlkem}} defines several Post-quantum/traditional hybrid algorithm based on ML-KEM-512, ML-KEM-768, and ML-KEM-1024. {{I-D.ietf-tls-mlkem}} defines several standalone algorithm based on ML-KEM-512, ML-KEM-768, and ML-KEM-1024

This document defines a PQ/T hybrid key exchange algorithm for TLS 1.3 that combines ML-KEM-1024 with X448: MLKEM1024X448. The algorithm provides a hybrid key exchange option targeting a high security level. Compared with P-curves offering a similar security level, X448 is significantly faster and provides greater implementation robustness. Most importantly, a FIPS-validated implementation of MLKEM1024X448 guarantees that the ML-KEM-1024 component is FIPS-validated. This is not the case for SecP384r1MLKEM1024 {{RFC10024}}.

The algorithm defined in this document is intended for use with TLS 1.3 and DTLS 1.3 and follows the hybrid key exchange construction used by ECDHE-MLKEM key agreement for TLS 1.3 {{RFC9954}}. It defines only additional TLS NamedGroup values and its associated key share encodings. It does not modify the TLS 1.3 handshake, key schedule, or negotiation mechanisms.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the terminology of TLS 1.3 {{RFC9846}} and hybrid key exchange for TLS 1.3 {{RFC9954}}. The term "ML-KEM" refers to the Module-Lattice-Based Key-Encapsulation Mechanism defined in {{FIPS203}}.

# Motivation and Applicability

{{TLS-ECDHE-MLKEM}} defines X25519MLKEM768, which combines ML-KEM-768 with the
Montgomery curve X25519, and SecP384r1MLKEM1024, which combines ML-KEM-1024
with the NIST curve secp384r1. It does not define a group combining
ML-KEM-1024 with a Montgomery curve.

The group defined in this document combines ML-KEM-1024 with X448
{{!ELLIPTIC-CURVES=RFC7748}}. This pairs the highest ML-KEM security category
with a traditional component of comparable strength, and provides a
high-security hybrid option for deployments that prefer X448 over the NIST
elliptic curves, for example due to its simpler and more robust implementation
properties or for consistency with existing use of X448 and Ed448.

The following table shows the key share sizes for the group defined in this
document:

Group | Client key share size | Server key share size
--- | --- | ---
MLKEM1024X448 | 1624 bytes | 1624 bytes

The key shares of MLKEM1024X448 are larger than those of hybrid groups based
on ML-KEM-768. Larger client key shares increase the size of the ClientHello,
which increases the likelihood of fragmentation and may expose
interoperability problems with legacy network devices, middleboxes, or other
network infrastructure with limitations around larger TLS ClientHello
messages. Larger key shares also increase bandwidth, memory, and computational
costs. Deployments using MLKEM1024X448 should take these costs into account.

# Hybrid Group Definition

This document defines one additional TLS NamedGroup value for use with the
TLS 1.3 `key_share` extension:

* MLKEM1024X448

The group combines an ML-KEM-1024 key exchange with an X448 elliptic-curve
Diffie-Hellman key exchange. The hybrid key exchange values are encoded as the
concatenation of the component key exchange values. The component encodings
are fixed length and are therefore unambiguous.

For ML-KEM-1024, the encapsulation key and ciphertext are encoded as defined
in {{FIPS203}}. The ML-KEM-1024 encapsulation key is 1568 octets, and the
ML-KEM-1024 ciphertext is 1568 octets.

For X448, the public key encoding used in the `key_share` extension is that
defined in {{Section 4.2.8.2 of TLS}}. The X448 public key is the 56-octet
public value for X448 defined in {{Section 5 of ELLIPTIC-CURVES}}.

The server MUST perform the encapsulation key check described
in Section 7.2 of {{FIPS203}} on the client's ML-KEM-1024 encapsulation key and
abort with an `illegal_parameter` alert if it fails.

The client MUST check that the ML-KEM-1024 ciphertext length is
1568 octets and abort with an `illegal_parameter` alert if it fails. If ML-KEM
decapsulation fails for any other reason, the connection MUST be aborted with
an `internal_error` alert.

Both client and server MUST process the ECDHE component as described in
{{Section 4.2.8.2 of TLS}}, including all validity checks, and abort with an
`illegal_parameter` alert if it fails.

## MLKEM1024X448

For MLKEM1024X448, the client key_exchange value contains the ML-KEM-1024
encapsulation key followed by the X448 public key:

~~~
struct {
    opaque kem_key[1568];
    opaque ecdhe_key[56];
} MLKEM1024X448ClientShare;
~~~

The server key_exchange value contains the ML-KEM-1024 ciphertext followed by
the X448 public key:

~~~
struct {
    opaque kem_ciphertext[1568];
    opaque ecdhe_key[56];
} MLKEM1024X448ServerShare;
~~~

The name MLKEM1024X448 reflects the order of the component algorithms in the
NamedGroup definition. This is the ordering convention specified by
{{Section 3.2 of TLS-HYBRID}}, which requires the order of shares in the
concatenated `key_exchange` value to match the order of algorithms indicated in
the definition of the NamedGroup. Accordingly, the ML-KEM-1024 component
appears first in both the name and the encoded `key_exchange` value, followed
by the X448 component.

This differs from the name X25519MLKEM768 defined in {{TLS-ECDHE-MLKEM}}.
That name is retained for historical compatibility reasons and is explicitly
documented by {{TLS-ECDHE-MLKEM}} as not following the naming convention in
{{Section 3.2 of TLS-HYBRID}}. This document follows the convention from
{{TLS-HYBRID}} for the new MLKEM1024X448 NamedGroup. As with X25519MLKEM768,
the ML-KEM component is placed first in the concatenation.

# Shared Secret Calculation

For MLKEM1024X448, the ML-KEM shared secret is produced by ML-KEM-1024
encapsulation and decapsulation, and the X448 shared secret is produced by
the X448 Diffie-Hellman operation. The hybrid shared secret is the
concatenation of the ML-KEM shared secret followed by the X448 shared secret:

~~~
MLKEM1024X448_shared_secret =
    MLKEM1024_shared_secret || X448_shared_secret
~~~

The ML-KEM-1024 shared secret is 32 octets, and the X448 shared secret is 56
octets. The resulting hybrid shared secret is therefore 88 octets. The hybrid
shared secret is used as the ECDHE shared secret input to the TLS 1.3 key
schedule.

Both client and server MUST calculate the ECDHE component of the shared secret
as described in {{Section 7.4.2 of TLS}}, including the all-zero shared secret
check for X448. If this computation or validation fails, the endpoint MUST
abort the connection with an `illegal_parameter` alert.

# Regulatory Context

The regulatory considerations related to component ordering and the use of
hybrid ECDHE-MLKEM key exchange are discussed in
{{Section 5 of TLS-ECDHE-MLKEM}} and apply to the group defined in this
document. In particular, MLKEM1024X448 places the ML-KEM shared secret first
in the concatenation, as X25519MLKEM768 does.

# Security Considerations

The security considerations outlined in {{Section 6 of TLS-HYBRID}} and
{{Section 6 of TLS-ECDHE-MLKEM}} apply to the group defined in this document.
This document defines an additional ECDHE-MLKEM hybrid group and does not
change the TLS 1.3 handshake, key schedule, authentication mechanisms, or the
general hybrid key exchange construction.

ML-KEM-1024 provides the highest post-quantum security category of the ML-KEM
parameter sets defined in {{FIPS203}}. X448 provides approximately 224 bits of
classical security {{ELLIPTIC-CURVES}}. The hybrid construction remains secure
as long as at least one of the component key exchanges remains secure.

# IANA Considerations

This document requests/registers one new entry in the
[TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8),
according to the procedures in {{Section 6 of ?IANA-TLS=RFC9847}}.

## MLKEM1024X448

 Value:
 : TBD

 Description:
 : MLKEM1024X448

 DTLS-OK:
 : Y

 Recommended:
 : N

 Reference:
 : This document

 Comment:
 : Combining ML-KEM-1024 with X448 ECDH
{: spacing="compact"}

--- back

# Acknowledgments
{:numbered="false"}

The author thanks the authors of {{TLS-HYBRID}} and {{TLS-ECDHE-MLKEM}}, whose work this document builds on.
