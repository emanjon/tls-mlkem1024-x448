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
  SP800-227: DOI.10.6028/NIST.SP.800-227
  RFC7748:
  RFC9846:
  RFC9847:
  RFC9954:

informative:
  SP800-12: DOI.10.6028/NIST.SP.800-12r1
  RFC10024:
  I-D.ietf-tls-mlkem:
  I-D.rosomakho-tls-ecdhe-mlkem512:
  I-D.yang-tls-hybrid-sm2-mlkem:
  EU25:
    target: https://ec.europa.eu/newsroom/dae/redirection/document/117507
    title: "A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography"
    date: June 2025
  EU26:
    target: https://certification.enisa.europa.eu/document/download/a845662b-aee0-484e-9191-890c4cfa7aaa_en
    title: "EU Roadmap on PQC – Frequently Asked Questions"
    date: April 2026
  NCSC26:
    target: https://www.ncsc.se/siteassets/publikationer/nationella-rekommendationer-for-overgangen-till-kvantsaker-kryptografi-2026_tga.pdf
    title: "Nationella rekommendationer för övergången till kvantsäker kryptografi"
    date: May 2026
  EO14412:
    target: https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/
    title: "Securing the Nation Against Advanced Cryptographic Attacks"
    date: June 2026

--- abstract

This document defines a post-quantum/traditional hybrid key exchange algorithm for TLS 1.3 that combines ML-KEM-1024 with X448: MLKEM1024X448. The algorithm provides a hybrid key exchange option targeting a high security level. Compared with P-curves offering a similar security level, X448 is significantly faster and provides greater implementation robustness. Most importantly, a FIPS-validated implementation of MLKEM1024X448 guarantees that the ML-KEM-1024 component is FIPS-validated. This is not the case for SecP384r1MLKEM1024. The algorithm defined in this document is intended for use with TLS 1.3, DTLS 1.3, and QUIC and follows the general hybrid key exchange construction defined for TLS 1.3.

--- middle

# Introduction

The transition to post-quantum cryptography requires new key exchange mechanisms for TLS 1.3 {{RFC9846}}. Post-Quantum/Traditional (PQ/T) hybrid key exchange combines a post-quantum key algorithm such as ML-KEM {{FIPS203}} with a traditional key exchange algorithm such as X448 {{RFC7748}}, allowing deployments to gain protection against future Cryptanalytically Relevant Quantum Computers (CRQC) while retaining the security of previously trusted traditional key exchange algorithms.

{{RFC9954}} specifies the general design for hybrid key exchange in TLS 1.3. {{RFC10024}}, {{I-D.rosomakho-tls-ecdhe-mlkem512}}, and {{I-D.yang-tls-hybrid-sm2-mlkem}} apply this design to define PQ/T hybrid key exchange algorithms based on ML-KEM-512, ML-KEM-768, and ML-KEM-1024, respectively. {{I-D.ietf-tls-mlkem}} defines standalone TLS 1.3 key exchange algorithms based on ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

This document applies the hybrid key exchange design specified in {{RFC9954}} to define MLKEM1024X448, a PQ/T hybrid key exchange algorithm for TLS 1.3 that combines ML-KEM-1024 with X448. The algorithm provides a hybrid key exchange option targeting a high security level. Compared with P-curves offering a similar security level, X448 is significantly faster and provides greater implementation robustness. Most importantly, a FIPS-validated implementation of MLKEM1024X448 ensures that the ML-KEM-1024 component is FIPS-validated. This is not the case for SecP384r1MLKEM1024 defined in {{RFC10024}}.

The algorithm defined in this document is intended for use with TLS 1.3, DTLS 1.3, and QUIC and follows the hybrid key exchange construction defined in {{RFC9954}}. It defines only an additional TLS NamedGroup value and its associated key share and shared secret encodings. It does not modify the TLS 1.3 handshake, key schedule, or negotiation mechanisms.

# Terminlogy

{::boilerplate bcp14-tagged}

This document uses the terminology of TLS 1.3 {{RFC9846}}, hybrid key exchange in TLS 1.3 {{RFC9954}}, and ML-KEM {{FIPS203}}.

# The MLKEM1024X448 Key Exchange Algorithm

This document defines one additional TLS NamedGroup value, MLKEM1024X448, for use with the TLS 1.3 `key_share` extension. The key shares and shared secret values are encoded as the concatenation of the component values. The encodings are fixed length.

## Client and Server Key Shares

For MLKEM1024X448, the client key_exchange value contains the ML-KEM-1024 encapsulation key followed by the X448 public key:

~~~
struct {
    opaque kem_key[1568];
    opaque ecdhe_key[56];
} MLKEM1024X448ClientShare;
~~~

The server key_exchange value contains the ML-KEM-1024 ciphertext followed by the X448 public key:

~~~
struct {
    opaque kem_ciphertext[1568];
    opaque ecdhe_key[56];
} MLKEM1024X448ServerShare;
~~~

The name MLKEM1024X448 follows the naming convention from {{RFC9954}}. As with X25519MLKEM768, which is not folowing the naming convention, the ML-KEM component is placed first in the concatenation.

The server MUST perform the encapsulation key check described in Section 7.2 of {{FIPS203}} on the client's ML-KEM-1024 encapsulation key and abort with an `illegal_parameter` alert if it fails.

The client MUST check that the ML-KEM-1024 ciphertext length is 1568 octets and abort with an `illegal_parameter` alert if it fails. If ML-KEM decapsulation fails for any other reason, the connection MUST be aborted with an `internal_error` alert.

Both client and server MUST process the X448 component as described in {{Section 4.2.8.2 of RFC9846}}, including all validity checks, and abort with an `illegal_parameter` alert if it fails.

## Shared Secret

For MLKEM1024X448, the 32 bytes ML-KEM shared secret is produced by ML-KEM-1024 encapsulation and decapsulation as specified in {{FIPS203}}, and the 56 bytes X448 shared secret is produced as specified in in {{Section 7.4.2 of RFC9846}} by the X448 Diffie-Hellman operation. The 88 bytes asymmetric shared secret input to the TLS 1.3 key schedule is the concatenation of the ML-KEM shared secret followed by the X448 shared secret:

~~~
asymmetric shared secret =
    MLKEM1024_shared_secret || X448_shared_secret
~~~

Both client and server MUST calculate the X448 part of the shared secret as described in Section 7.4.2 of [RFC9846], including the all-zero shared secret check, and abort the connection with an illegal_parameter alert if it fails.

# Security Considerations

This document defines an ephemeral quantum-resistant ML-KEM-ECDH PQ/T hybrid using the construction in {{RFC10024}} and does not modify the TLS 1.3 handshake, key schedule, or authentication mechanisms of TLS 1.3, DTLS 1.3, or QUIC. The security considerations in {{RFC9846}}, {{FIPS203}}, {{SP800-227}}, {{RFC7748}}, {{RFC9954}}, and {{RFC10024}} apply to the algorithm defined in this document. Note that TLS 1.3 {{RFC9846}} prohibits reuse of key shares. 

ML-KEM-1024 provides the highest security among the ML-KEM parameter sets defined in {{FIPS203}}, namely post-quantum security category 5. X448 provides approximately 224 bits of classical security {{RFC7748}} and negligible quantum resistance. Compared with P-curves offering a comparable security level, X448 is significantly faster and provides greater implementation robustness. Compared with X25519MLKEM768 {{RFC10024}}, which is RECOMMENDED = Y, MLKEM1024X448 provides stronger security properties at the cost of slightly lower performance. ML-KEM-1024, with its security category 5, provides a larger security margin against future advances in the cryptanalysis of lattice-based cryptography than ML-KEM-768.

A fundamental requirement of hybrid constructions is that their security is at least as high as that of their strongest component; that is, the construction preserves the cryptographic security properties of its components {{EU25}}, {{EU26}}, {{NCSC26}}, {{SP800-227}}. The PQ/T hybrid key exchange algorithm defined in this document is designed to meet this requirement. In particular, it preserves the quantum-resistance and indistinguishability under adaptive chosen-ciphertext attack (IND-CCA2) security of ML-KEM {{FIPS203}}.

Similar to X25519MLKEM768 {{RFC10024}} and MLKEM512X25519 {{I-D.rosomakho-tls-ecdhe-mlkem512}}, a FIPS-validated implementation of MLKEM1024X448 guarantees that the ML-KEM component is FIPS-validated. This is not the case for SecP256r1MLKEM768 and SecP384r1MLKEM1024 {{RFC10024}}, whose primary design goal was to enable vendors to sell existing FIPS-validated implementations of P-256 and P-384 as “quantum-resistant,” even though only the quantum-vulnerable components are FIPS validated. FIPS-validated implementations of SecP256r1MLKEM768 and SecP384r1MLKEM1024 might already be disallowed by 2030 {{EO14412}}. Users seeking a FIPS-validated key exchange in TLS should therefore use FIPS-validated MLKEM512X25519, X25519MLKEM768, MLKEM1024X448, MLKEM512, MLKEM768, or MLKEM1024.

Availability is a fundamental security property and part of the CIA triad in information security {{SP800-12}}. Large key shares are known to cause problems with non-compliant or buggy legacy TLS implementations, as well as with middleboxes and other network infrastructure that impose non-compliant limitations on large TLS ClientHello messages. Large key shares also increase bandwidth, memory, and computational costs for constrained endpoints or deployments operating over lossy or bandwidth-constrained networks, potentially reducing availability.

Implementations MUST NOT use MLKEM1024X448 with TLS 1.2 or DTLS 1.2. TLS 1.2 and DTLS 1.2 are obsolete and should be phased out as soon as possible. 3GPP already mandates that TLS 1.2 be disabled by default.

# IANA Considerations

This document requests that IANA register one new entry in the [TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8), according to the procedures in {{Section 6 of RFC9847}}.

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
 : PQ/T hybrid combining ML-KEM-1024 with X448

--- back

# Acknowledgments
{:numbered="false"}

The authors thank the authors of previous drafts from which this draft borrowed text. The authors thank someone for their valuable comments and feedback on this draft.
