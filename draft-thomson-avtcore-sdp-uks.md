---
title: "Unknown Key Share Attacks on uses of Transport Layer Security with the Session Description Protocol (SDP)"
abbrev: "SDP UKS"
docname: draft-thomson-avtcore-sdp-uks-latest
date: 2016
category: info
ipr: trust200902

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: M. Thomson
    name: Martin Thomson
    org: Mozilla
    email: martin.thomson@gmail.com
 -
    ins: E. Rescorla
    name: Eric Rescorla
    org: Mozilla
    email: ekr@rftm.com

normative:
  FIPS180-2:
    title: NIST FIPS 180-2, Secure Hash Standard
    author:
      name: NIST
      ins: National Institute of Standards and Technology, U.S. Department of Commerce
    date: 2002-08

informative:
  UKS:
    title: "Unknown Key-Share Attacks on the Station-to-Station (STS) Protocol"
    author:
      - ins: S. Blake-Wilson
      - ins: A. Menezes
    date: 1999
    seriesinfo: Lecture Notes in Computer Science 1560, Springer, pp. 154–170
  SIGMA:
    title: "SIGMA: The ‘SIGn-and-MAc’approach to authenticated Diffie-Hellman and its use in the IKE protocols"
    author:
      - ins: H. Krawczyk
    date: 2003
    seriesinfo: Annual International Cryptology Conference, Springer, pp. 400-425
  WEBRTC:
    title: "WebRTC 1.0: Real-time Communication Between Browsers"
    author:
      - ins: A. Bergkvist
      - ins: D. Burnett
      - ins: A. Narayanan
      - ins: C. Jennings
      - ins: B. Aboba
    date: 2016-05-31
    seriesinfo: W3C WD-webrtc-30160531


--- abstract

Unknown key-share attacks on the use of Datagram Transport Layer Security for
the Secure Real-Time Transport Protocol (DTLS-SRTP) and its use with Web
Real-Time Communications (WebRTC) identity assertions are described.  Simple
mitigation techniques are defined.


--- middle

# Introduction

The use of Transport Layer Security (TLS) {{!RFC5246}} with the Session
Description Protocol (SDP) {{!RFC4566}} is defined in {{!RFC4572}}.  Further use
with Datagram Transport Layer Security (DTLS) {{!RFC6347}} and the Secure
Real-time Transport Protocol (SRTP) {{!RFC3711}} is defined as DTLS-SRTP
{{!RFC5763}}.

In these specifications, key agreement is performed using the TLS or DTLS
handshaking protocol, with authentication being tied back to the session
description (or SDP) through the use of certificate fingerprints.
Communication peers check that a hash, or fingerprint, provided in the SDP
matches the certificate that is used in the TLS (or DTLS) handshake.  This
is defined in {{!RFC4572}}.

The design of DTLS-SRTP relies on the integrity of the signaling channel.
Certificate fingerprints are assumed to be provided by the communicating peers
and carried by the signaling channel without being subject to modification.
However, this design is vulnerable to an unknown key-share (UKS) attack where a
misbehaving endpoint is able to advertise a key that it does not control.  This
leads to the creation of sessions where peers are confused about the identify of
the participants.

An extension to TLS is defined that can be used to mitigate this attack.

A similar attack is possible with sessions that use WebRTC identity (see Section
5.6 of {{!I-D.ietf-rtcweb-security-arch}}).  This issue and a mitigation for it
is discussed in more detail in {{webrtc}}.


# Unknown Key-Share Attack

In an unknown key-share attack {{UKS}}, a malicious participant in a protocol
claims to control a key that is in reality controlled by some other actor.  This
arises when the identity associated with a key is not properly bound to the key.

In DTLS-SRTP, an endpoint is able to acquire the certificate fingerprint another
entity.  By advertising that fingerprint in place of one of its own, the
malicious endpoint can cause its peer to communicate with a different peer, even
though it believes that it is communicating with the malicious endpoint.

When the identity of communicating peers is established by higher-layer
signaling constructs, such as those in SIP {{?RFC4474}} or WebRTC
{{!I-D.ietf-rtcweb-security-arch}}, this allows an attacker to bind their own
identity to a session with any other entity.

By substituting the the fingerprint of one peer for its own, an attacker is able
to cause a session to be established where one endpoint has an incorrect value
for the identity of its peer.  However, the peer does not suffer any such
confusion, resulting in each peer involved in the session having a different
view of the nature of the session.

This attack applies to any communications established based on the
`a=fingerprint` SDP attribute {{!RFC4572}}.


## Attack Overview

This vulnerability can be used by an attacker to create a call where
there is confusion about the communicating endpoints.

A SIP endpoint or WebRTC endpoint that is configured to reuse a certificate can
be attacked if it is willing to conduct two concurrent calls, one of which is
with an attacker.  The attacker can arrange for the victim to incorrectly
believe that is calling the attacker when it is in fact calling a second party.
The second party correctly believes that it is talking to the victim.

In a related attack, a single call using WebRTC identity can be attacked so that
it produces the same outcome.  This attack does not require a concurrent call.


## Limits on Attack Feasibility

The use of TLS with SDP depends on the integrity of session signaling.  Assuming
signaling integrity limits the capabilities of an attacker in several ways.  In
particular:

1. An attacker can only modify the parts of the session signaling for a session
   that they are part of, which is limited to their own offers and answers.

2. No entity will complete communications with a peer unless they are willing to
   participate in a session with that peer.

The combination of these two constraints make the spectrum of possible attacks
quite limited.  An attacker is only able to switch its own certificate
fingerprint for a valid certificate that is acceptable to its peer.  Attacks
therefore rely on joining two separate sessions into a single session.

The second condition is not necessary with WebRTC identity if the victim has or
is configured with a target peer identity (this is defined in {{WEBRTC}}).
Furthermore, any identity displayed by a browser could be different to the
identity used by the application, since the attack affects the browser's
understanding of the peer's identity.


## Example

In this example, two outgoing sessions are created by the same endpoint.  One of
those sessions is initiated with the attacker, another session is created toward
another honest endpoint.  The attacker convinces the endpoint that their session
has completed, and that the session with the other endpoint has succeeded.

~~~
  Norma               Mallory             Patsy
  (fp=N)               -----              (fp=P)
    |                    |                  |
    +---Offer1 (fp=N)--->|                  |
    +-----Offer2 (fp=N)-------------------->|
    |<--------------------Answer2 (fp=P)----+
    |<--Answer1 (fp=P)---+                  |
    |                    |                  |
    |======DTLS1====>(Forward)====DTLS1====>|
    |<=====DTLS2=====(Forward)<===DTLS2=====|
    |======Media1===>(Forward)====Media1===>|
    |<=====Media2====(Forward)<===Media2====|
    |                    |                  |
    |======DTLS2===========>(Drop)          |
    |                    |                  |
~~~

In this case, Norma is willing to conduct two concurrent sessions.  The first
session is established with Mallory, who falsely uses Patsy's certificate
fingerprint.  A second session is initiated between Norma and Patsy.  Signaling
for both sessions is permitted to complete.

Once complete, the session that is ostensibly between Mallory and Norma is
completed by forwarding packets between Norma and Patsy.  This requires that
Mallory is able to intercept DTLS and media packets from Patsy so that they can
be forwarded to Norma at the transport addresses that Norma associates with the
first session.

The second session - between Norma and Patsy - is permitted to continue to the
point where Patsy believes that it has succeeded.  This ensures that Patsy
believes that she is communicating with Norma.  In the end, Norma believes that
she is communicating with Mallory, when she is actually communicating with
Patsy.

Though Patsy needs to believe that the second session is successful, Mallory has
no real interest in seeing that session complete.  Mallory only needs to ensure
that Patsy does not abandon the session prematurely.  For this reason, it might
be necessary to permit the answer from Patsy to reach Norma to allow Patsy to
receive a call completion signal, such as a SIP ACK.  Once the second session
completes, Mallory causes any DTLS packets sent by Norma to Patsy to be dropped.

For the attacked session to be sustained beyond the point that Norma detects
errors in the second session, Mallory also needs to block any signaling that
Norma might send to Patsy asking for the call to be abandoned.  Otherwise, Patsy
might receive a notice that the call is failed and thereby abort the call.

This attack creates an asymmetry in the beliefs about the identity of peers.
However, this attack is only possible if the victim (Norma) is willing to
conduct two sessions concurrently, and if the same certificate - and therefore
`a=fingerprint` value - is used in both sessions.


## Interactions with Key Continuity {#continuity}

Systems that use key continuity might be able to detect an unknown key-share
attack if a session with the actual peer (i.e., Patsy in the example) was
established in the past.  Whether this is possible depends on how key continuity
is implemented.

Implementations that maintain a single database of identities with an index on
peer keys could discover that the identity saved for the peer key does not match
the claimed identity.  Such an implementation could notice the disparity between
the actual keys (Patsy) and the expected keys (Mallory).

In comparison, implementations that first match based on peer identity could
treat an unknown key-share attack as though their peer had used a
newly-configured device.  The apparent addition of a new device could generate
user-visible notices (e.g., "Mallory appears to have a new device").  However,
such an event is not always considered alarming; some implementations might
silently save a new key.


# Adding a Session Identifier {#sess-id}

An attack on DTLS-SRTP is possible because the identity of peers involved is not
established prior to establishing the call.  Endpoints use certificate
fingerprints as a proxy for authentication, but as long as fingerprints are used
in multiple calls, they are vulnerable to attacks of the sort described.

The solution to this problem is to assign a new identifier to communicating
peers.  Each endpoint assigns their peer a unique identifier during call
signaling.  The peer echoes that identifier in the TLS handshake, binding that
identity into the session.  Including this new identity in the TLS handshake
means that it will be covered by the TLS Finished message, which is necessary to
authenticate it (see {{SIGMA}}).  Validating that peers use the correct
identifier then means that the session is established between the correct two
endpoints.

Rather than define a new identifier and means for signaling it, the `sess-id`
field of the o= line in the SDP is used.  This field is already required to be
unique, thus, no two offers or answers from the same client will have the same
value.

The `sess-id` is defined as a decimal sequence {{!RFC4566}}.  {{!RFC3264}}
subsequently limits `sess-id` to a 63-bit value.  Endpoints MUST include a
unique 63-bit value in every session description (offer or answer) they
generate.  Endpoints SHOULD generate this value using a cryptographically-secure
random process {{!RFC4086}}.

Note:

: We could define a new attribute for this purpose, but that just makes things
  harder to deploy.  This design limits the protocol changes to the TLS
  extension and its validation.

A new `sdp_session_id` extension is added to the TLS or DTLS handshake for
connections that are established as part of the same call or real-time session.


## The sdp_session_id TLS Extension {#sdp_session_id}

The `sdp_session_id` TLS extension carries the unique identifier that an
endpoint selects.  The value includes the `sess-id` field from the SDP that the
endpoint generated when negotiating the session.

The `extension_data` for the `sdp_session_id` extension contains a SdpSessionId
struct, described below using the syntax defined in {{!RFC5246}}:

~~~
   struct {
      uint64 sess_id;
      uint16 m_line;
   } SdpSessionId;
~~~

The `sess_id` field of the extension includes the value of the `sess-id` field
from the `o=` line of the SDP offer or answer that the endpoint generates.

The `m_line` field of the extension includes the index of the `m=` section of
the session description that the TLS connection is generated for, starting at
index 0.  Bundled media sections {{!I-D.ietf-mmusic-sdp-bundle-negotiation}} are
identified by the index of the `m=` section associated with the Answerer
BUNDLE-tag.  This prevents an attacker from rearranging `m=` sections within the
same session.

Where RTP and RTCP {{?RFC3550}} are not multiplexed, it is possible that the two
separate DTLS connections carrying RTP and RTCP can be switched.  This is
considered benign since these protocols are often distinguishable.  RTP/RTCP
multiplexing is advised to address this problem.

The `sdp_session_id` extension is included in a ClientHello and either ServerHello
(for TLS and DTLS versions less than 1.3) or EncryptedExtensions (for TLS 1.3).
In TLS 1.3, the extension MUST NOT be included in a ServerHello.

Endpoints MUST check that the `sess_id` parameter in the extension that they
receive includes the `sess-id` value that they received in their peer's session
description.  Endpoints MUST also check that the `m_line` parameter matches
their expectations.  An endpoint that has receives a `sdp_session_id` extension
that is not identical to the value that it expects MUST abort the connection
with a fatal `handshake_failure` alert.

An endpoint that is communicating with a peer that does not support this
extension will receive a ClientHello, ServerHello or EncryptedExtensions that
does not include this extension.  An endpoint MAY choose to continue a session
without this extension in order to interoperate with peers that do not implement
this specification.

In TLS 1.3, the `sdp_session_id` extension MUST be sent in the
EncryptedExtensions message.


# WebRTC Identity Binding {#webrtc}

The identity assertion used for WebRTC is bound only to the certificate
fingerprint of an endpoint and can therefore be copied by an attacker along with
the `a=fingerprint` attributes.

The problem is compounded by the fact that an identity provider is not required
to verify that the entity requesting an identity assertion controls the keys.
Nor is it currently able to perform this validation.  Note however that this
verification is not a necessary condition for a secure protocol, as established
in {{SIGMA}}.

A simple solution to this problem is suggested by {{SIGMA}}.  The identity of
endpoints is included under a message authentication code (MAC) during the
cryptographic handshake.  Endpoints are then expected to validate that their
peer has provided an identity that matches their expectations.

In TLS, the Finished message provides a MAC over the entire handshake, so that
including the identity in a TLS extension is sufficient to implement this
solution.  Rather than include a complete identity assertion, a hash of the
identity assertion is included in a TLS extension.  Peers then need only
validate that the extension contains a hash of the identity assertion they
received in signaling in addition to validating the identity assertion.

Endpoints MAY use the `sdp_session_id` extension in addition to this so that two
calls between the same parties can't be altered by an attacker.


## The webrtc_id_hash TLS Extension {#webrtc_id_hash}

The `webrtc_id_hash` TLS extension carries a hash of the identity assertion that
communicating peers have exchanged.

The `extension_data` for the `webrtc_id_hash` extension contains a
WebrtcIdentityHash struct, described below using the syntax defined in
{{!RFC5246}}:

~~~
   struct {
      opaque assertion_hash[32];
   } WebrtcIdentityHash;
~~~

A WebRTC identity assertion is provided as a JSON {{?RFC7159}} object that is
encoded into a JSON text.  The resulting string is then encoded using UTF-8
{{!RFC3629}}.  The content of the `webrtc_id_hash` extension are produced by
hashing the resulting octets with SHA-256 {{FIPS180-2}}.  This produces the 32
octets of the assertion_hash parameter, which is the sole contents of the
extension.

The `a=identity` attribute includes the base64 {{?RFC4648}} encoding of the same
octets that were input to the hash.  The `webrtc_id_hash` extension is validated
by performing base64 decoding on the value of the `a=identity` attribute,
hashing the resulting octets using SHA-256, and comparing the results with the
content of the extension.

Identity assertions might be provided by only one peer.  An endpoint that does
not produce an identity assertion MUST generate an empty `webrtc_id_hash`
extension in its ClientHello.  This allows its peer to include a hash of its
identity assertion.  An endpoint without an identity assertion MUST omit the
`webrtc_id_hash` extension from its ServerHello or EncryptedExtensions message.

A peer that receives a `webrtc_id_hash` extension that is not equal to the value
of the identity assertion from its peer MUST immediately fail the TLS handshake
with an error.  This includes cases where the `a=identity` attribute is not
present in the SDP.

A peer that receives an identity assertion, but does not receive a
`webrtc_id_hash` extension MAY choose to fail the connection, though it is
expected that implementations that were written prior to the existence of this
document will not support these extensions for some time.

In TLS 1.3, the `webrtc_id_hash` extension MUST be sent in the
EncryptedExtensions message.


# Security Considerations

This entire document contains security considerations.


# IANA Considerations

This document registers two extensions in the TLS "ExtensionType Values" registry
established in {{!RFC5246}}:

* The `sdp_session_id` extension has been assigned a code point of TBD; it is
  recommended and is marked as "Encrypted" in TLS 1.3.

* The `webrtc_id_hash` extension has been assigned a code point of TBD; it is
  recommended and is marked as "Encrypted" in TLS 1.3.


--- back

# Acknowledgements

This problem would not have been discovered if it weren't for discussions with
Sam Scott, Hugo Krawczyk, and Richard Barnes.  A solution similar to the one presented here
was first proposed by Karthik Bhargavan.  Thyla van der Merwe assisted with
a formal model of the solution.  Adam Roach provided useful input.
