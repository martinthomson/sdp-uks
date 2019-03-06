---
title: "Unknown Key Share Attacks on uses of TLS with the Session Description Protocol (SDP)"
abbrev: "SDP UKS"
docname: draft-ietf-mmusic-sdp-uks-latest
category: std
ipr: trust200902
updates: 8122

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: M. Thomson
    name: Martin Thomson
    org: Mozilla
    email: mt@lowentropy.net
 -
    ins: E. Rescorla
    name: Eric Rescorla
    org: Mozilla
    email: ekr@rftm.com

normative:

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
      - ins: T. Brandstetter
      - ins: J. Bruaroey
    date: 2018-11-08
    seriesinfo: W3C Editor's Draft


--- abstract

This document describes unknown key-share attacks on the use of Datagram
Transport Layer Security for the Secure Real-Time Transport Protocol
(DTLS-SRTP). Similar attacks are described on the use of DTLS-SRTP with the
identity bindings used in Web Real-Time Communications (WebRTC) and SIP
identity.  These attacks are difficult to mount, but they cause a victim to be
mislead about the identity of a communicating peer.  Simple mitigation
techniques are defined for each.


--- middle

# Introduction

The use of Transport Layer Security (TLS) {{!TLS13=RFC8446}} with the Session
Description Protocol (SDP) {{!SDP=RFC4566}} is defined in
{{!FINGERPRINT=RFC8122}}.  Further use with Datagram Transport Layer Security
(DTLS) {{!DTLS=RFC6347}} and the Secure Real-time Transport Protocol (SRTP)
{{!SRTP=RFC3711}} is defined as DTLS-SRTP {{!DTLS-SRTP=RFC5763}}.

In these specifications, key agreement is performed using TLS or DTLS, with
authentication being tied back to the session description (or SDP) through the
use of certificate fingerprints.  Communication peers check that a hash, or
fingerprint, provided in the SDP matches the certificate that is used in the TLS
or DTLS handshake.

WebRTC identity (see Section 7 of {{!WEBRTC-SEC=I-D.ietf-rtcweb-security-arch}})
and SIP identity {{?SIP-ID=RFC8224}} both provide a mechanism that binds an
external identity to the certificate fingerprints from a session description.
However, this binding is not integrity-protected and therefore vulnerable to an
identity misbinding attack - or unknown key-share (UKS) attack - where the
attacker binds their identity to the fingerprint of another entity.  A
successful attack leads to the creation of sessions where peers are confused
about the identify of the participants.

This document describes a TLS extension that can be used in combination with
these identity bindings to prevent this attack.

A similar attack is possible with the use of certificate fingerprints alone.
Though attacks in this setting are likely infeasible in existing deployments due
to the narrow conditions necessary (see {{limits}}), this document also
describes mitigations for this attack.

The mechanisms defined in this document are intended to strengthen the protocol
by preventing the use of unknown key shares in combination with other protocol
or implementation vulnerabilities.

This document assumes that signaling is integrity protected.  However, as
Section 7 of {{!FINGERPRINT}} explains, many deployments that use SDP do not
guarantee integrity of session signaling and so are vulnerable to other attacks.
{{!FINGERPRINT}} offers key continuity mechanisms as a potential means of
reducing exposure to attack in the absence of integrity protection.
{{continuity}} provides some analysis of the effect of key continuity in
relation to the described attacks.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.


# Unknown Key-Share Attack {#uks}

In an unknown key-share attack {{UKS}}, a malicious participant in a protocol
claims to control a key that is in reality controlled by some other actor.  This
arises when the identity associated with a key is not properly bound to the key.

An endpoint that can acquire the certificate fingerprint of another entity can
advertise that fingerprint as their own in SDP.  An attacker can use a copy of
that fingerprint to cause a victim to communicate with another unaware victim,
even though it believes that it is communicating with the attacker.

When the identity of communicating peers is established by higher-layer
signaling constructs, such as those in SIP identity {{?SIP-ID}} or WebRTC
{{!WEBRTC-SEC}}, this allows an attacker to bind their own identity to a session
with any other entity.

The attacker obtains an identity assertion for an identity it controls, but
binds that to the fingerprint of one peer.  The attacker is then able to cause a
TLS connection to be established where two endpoints communicate.  The victim
that has its fingerprint copied by the attack correctly believes that it is
communicating with the other victim; however, the other victim incorrectly
believes that it is communicating with the attacker.

A similar attack can be mounted without any communications established based on
the SDP `fingerprint` attribute {{!FINGERPRINT}}.

This attack is an aspect of SDP-based protocols that the technique known as
third-party call control (3PCC) {{?RFC3725}} relies on.  3PCC exploits the
potential for the identity of a signaling peer to be different than the media
peer, allowing the media peer to be selected by the signaling peer.
{{byebye-3pcc}} describes the consequences of the mitigations described here for
systems that use 3PCC.


## Limits on Attack Feasibility {#limits}

The use of TLS with SDP depends on the integrity of session signaling.  Assuming
signaling integrity limits the capabilities of an attacker in several ways.  In
particular:

1. An attacker can only modify the parts of the session signaling for a session
   that they are part of, which is limited to their own offers and answers.

2. No entity will successfully establish a session with a peer unless they are
   willing to participate in a session with that peer.

The combination of these two constraints make the spectrum of possible attacks
quite limited.  An attacker is only able to switch its own certificate
fingerprint for a valid certificate that is acceptable to its peer.  Attacks
therefore rely on joining two separate sessions into a single session.

Systems that rely on strong identity bindings, such as those defined in
{{WEBRTC}} or {{!SIP-ID}}, have a different threat model, which admits the
possibility of attack by an entity with access to the signaling channel.
Attacks under these conditions are more feasible as an attacker is assumed to be
able to both observe and modify signaling messages.


## Interactions with Key Continuity {#continuity}

Systems that use key continuity (as defined in Section 15.1 of {{?ZRTP=RFC6189}}
or as recommended in Section 7 of {{?FINGERPRINT}}) might be able to detect an
unknown key-share attack if a session with either the attacker or the genuine
peer (i.e., the victim whose fingerprint was copied by an attacker) was
established in the past.  Whether this is possible depends on how key continuity
is implemented.

Implementations that maintain a single database of identities with an index on
peer keys could discover that the identity saved for the peer key does not match
the claimed identity.  Such an implementation could notice the disparity between
the actual keys (those copied from a victim) and the expected keys (those of the
attacker).

In comparison, implementations that first match based on peer identity could
treat an unknown key-share attack as though their peer had used a
newly-configured device.  The apparent addition of a new device could generate
user-visible notices (e.g., "Mallory appears to have a new device").  However,
such an event is not always considered alarming; some implementations might
silently save a new key.


## Third-Party Call Control {#byebye-3pcc}

Third-party call control (3PCC) {{?RFC3725}} is a technique where a signaling
peer establishes a call that is terminated by a different entity.  This attack
is very similar to the 3PCC technique, except where the TLS peers are aware of
the use of 3PCC.

For 3PCC to work with the proposed mechanisms, TLS peers need to be aware of the
signaling so that they can correctly generate (and check) the extension.  Peers
need access to any identity assertions present in signaling in order to perform
the checks in {{external_id_hash}}.  For a connection to be successfully
established, a controller needs to forward all fields that contain identity
assertions, including any fields outside of SDP that are used, such as the SIP
Identity header field {{?SIP-ID}}.  A controller that follows the best practices
in RFC 3725 is expected to forward the necessary information contained in SDP,
such as the WebRTC `identity` attribute, thus ensuring the necessary information
is present.

To perform the checks in {{external_session_id}}, a 3PCC system needs to ensure
that guarantee that peers use the same SDP `tls-id` attribute value.  A
controller that follows the best practices in RFC 3725 will produce SDP with
consistent `tls-id` values, but other forms of modification might not.

It is understood that this technique will prevent the use of 3PCC if peers have
different views of the involved identities, or the value of SDP `tls-id`
attributes.


# Attack on Identity Bindings {#id}

The identity assertions used for WebRTC (Section 7 of {{!WEBRTC-SEC}}) and the
SIP PASSPoRT using in SIP identity ({{!SIP-ID}}, {{!PASSPoRT=RFC8225}}) are
bound to the certificate fingerprint of an endpoint.  An attacker causes an
identity binding to be created that binds an identity they control to the
fingerprint of a first victim.

An attacker can thereby cause a second victim to believe that they are
communicating with an attacker-controlled identity, when they are really talking
to the first victim.  The attacker only needs to create an identity assertion
that covers a certificate fingerprint of the first victim.

A variation on the same technique can be used to cause both victims to both
believe they are talking to the attacker when they are talking to each other.
In this case, the attacker performs the identity misbinding once for each
victim.

The problem might appear to be caused by the fact that the authority that certifies
the identity binding is not required to verify that the entity requesting the
binding controls the keys associated with the fingerprints.  Both SIP and WebRTC
identity providers are not required to perform this validation.  This is not an
issue because verifying control of the associated keys is not a necessary
condition for a secure protocol, nor would it be sufficient to prevent attack
{{SIGMA}}.

A simple solution to this problem is suggested by {{SIGMA}}.  The identity of
endpoints is included under a message authentication code (MAC) during the
cryptographic handshake.  Endpoints then validate that their peer has provided
an identity that matches their expectations.  In TLS, the Finished message
provides a MAC over the entire handshake, so that including the identity in a
TLS extension is sufficient to implement this solution.

Rather than include a complete identity binding - which could be
sizeable - a collision- and pre-image-resistant hash of the binding is included
in a TLS extension.  Endpoints then need only validate that the extension
contains a hash of the identity binding they received in signaling.  If the
identity binding is successfully validated, the identity of a peer is verified
and bound to the session.

This attack works without compromising signaling integrity, unless the defenses
described in {{fp}} are also employed.  However, the mechanism described in
{{external_id_hash}} is the only one effective against an attacker that is able
rewrite `tls-id` values.

Endpoints MUST use the `external_session_id` extension (see
{{external_session_id}}) in addition to the `external_id_hash`
({{external_id_hash}}) so that two calls between the same parties can't be
altered by an attacker.


## Example {#id-example}

In the example shown in {{identity-attack}}, it is assumed that the attacker
also controls the signaling channel.

Mallory (the attacker) presents two victims, Norma and Patsy, with two separate
sessions.  In the first session, Norma is presented with the option to
communicate with Mallory; a second session with Norma is presented to Patsy.

~~~
  Norma                   Mallory                   Patsy
  (fp=N)                   -----                    (fp=P)
    |                        |                        |
    |<---- Signaling1 ------>|                        |
    |   Norma=N Mallory=P    |                        |
    |                        |<---- Signaling2 ------>|
    |                        |   Norma=N Patsy=P      |
    |                                                 |
    |<=================DTLS (fp=N,P)=================>|
    |                                                 |
  (peer = Mallory!)                         (peer = Norma)
~~~
{: #identity-attack title="Example Attack on Identity Bindings"}

The attack requires that Mallory obtain an identity binding for her own identity
with the fingerprints presented by Patsy (P).  This false binding is then
presented to Norma (Signaling1 in the figure).

Patsy could be similarly duped, but in this example, a correct binding between
Norma's identity and fingerprint (N) is faithfully presented by Mallory.  This
session (Signaling2 in the figure) can be entirely legitimate.

A DTLS session is established directly between Norma and Patsy.  In order for
this to happen Mallory can substitute transport-level information in both
sessions to facilitate this, though this is not necessary if Mallory is on the
network path between Norma and Patsy.

As a result, Patsy correctly believes that she is communicating with Norma.
However, Norma incorrectly believes she is talking to Mallory.


## The external_id_hash TLS Extension {#external_id_hash}

The `external_id_hash` TLS extension carries a hash of the identity assertion
that communicating peers have exchanged.

The `extension_data` for the `external_id_hash` extension contains a
`ExternalIdentityHash` struct, described below using the syntax defined in
Section 3 of {{!TLS13}}:

~~~
   struct {
      opaque binding_hash<0..32>;
   } ExternalIdentityHash;
~~~

A WebRTC identity assertion is provided as a JSON {{?JSON=RFC8259}} object that
is encoded into a JSON text.  The resulting string is then encoded using UTF-8
{{!UTF8=RFC3629}}.  The content of the `external_id_hash` extension are produced
by hashing the resulting octets with SHA-256
{{!SHA=DOI.10.6028/NIST.FIPS.180-4}}.  This produces the 32 octets of the
`binding_hash` parameter, which is the sole contents of the extension.

The SDP `identity` attribute includes the base64 {{?BASE64=RFC4648}} encoding of
the UTF-8 encoding of the same JSON text.  The `external_id_hash` extension is
validated by performing base64 decoding on the value of the SDP `identity`
attribute, hashing the resulting octets using SHA-256, and comparing the results
with the content of the extension.  In pseudocode form, using the
`identity-assertion-value` field from the `identity` attribute grammar as
defined in {{!WEBRTC-SEC}}:

```
external_id_hash = SHA256(b64decode(identity-assertion-value))
```

Note:

: The base64 is decoded to avoid capturing variations in padding.  The
  base64-decoded identity assertion could include leading or trailing whitespace
  octets.  WebRTC identity assertions are not canonicalized; all octets are
  hashed.

Where a PASSPoRT is used, the compact form of the PASSPoRT MUST be expanded into
the full form.  The base64 encoding used in the Identity (or 'y') header field
MUST be decoded then used as input to SHA-256.  This produces the 32 octet
`binding_hash` value used for creating or validating the extension.  In
pseudocode, using the `signed-identity-digest` field from the `Identity` grammar
defined {{!SIP-ID}}:

```
external_id_hash = SHA256(b64decode(signed-identity-digest))
```

Note:

: Should SHA-256 prove to be inadequate at some point in the future (see
  {{?AGILITY=RFC7696}}), a new TLS extension can be defined that uses a
  different hash function.

Identity bindings in either form might be provided by only one peer.  An
endpoint that does not produce an identity binding MUST generate an empty
`external_id_hash` extension in its ClientHello.  An empty extension has a
zero-length binding_hash field.  This allows its peer to include a hash of its
identity binding.  An endpoint without an identity binding MUST include an empty
`external_id_hash` extension in its ServerHello or EncryptedExtensions message,
to indicate support for the extension.

A peer that receives an `external_id_hash` extension that does not match the
value of the identity binding from its peer MUST immediately fail the TLS
handshake with an error.  This includes cases where the binding is absent, in
which case the extension MUST be present and empty.

An `external_id_hash` extension that is any length other than 0 or 32 is invalid
and MUST cause the receiving endpoint to generate a fatal `decode_error` alert.

A peer that receives an identity binding, but does not receive an
`external_id_hash` extension MAY choose to fail the connection, though it is
expected that implementations written prior to the definition of the extensions
in this document will not support both for some time.

In TLS 1.3, the `external_id_hash` extension MUST be sent in the
EncryptedExtensions message.


# Unknown Key-Share with Fingerprints {#fp}

An attack on DTLS-SRTP is possible because the identity of peers involved is not
established prior to establishing the call.  Endpoints use certificate
fingerprints as a proxy for authentication, but as long as fingerprints are used
in multiple calls, they are vulnerable to attack.

Even if the integrity session signaling can be relied upon, an attacker might
still be able to create a session where there is confusion about the
communicating endpoints by substituting the fingerprint of a communicating
endpoint.

An endpoint that is configured to reuse a certificate can be attacked if it is
willing to initiate two calls at the same time, one of which is with an
attacker.  The attacker can arrange for the victim to incorrectly believe that
it is calling the attacker when it is in fact calling a second party.  The
second party correctly believes that it is talking to the victim.

As with the attack on identity bindings, this can be used to cause two victims
to both believe they are talking to the attacker when they are talking to each
other.


## Example {#fp-example}

To mount this attack, two sessions need to be created with the same endpoint at
almost precisely the same time.  One of those sessions is initiated with the
attacker, the second session is created toward another honest endpoint.  The
attacker convinces the endpoint that their session has completed, and that the
session with the other endpoint has succeeded.

In addition to the constraints described in {{limits}}, the attacker in this
example also needs the ability to view and drop packets between victims.
That is, the attacker is on-path.

The attack shown in {{implausible-attack}} depends on a somewhat implausible set
of conditions.  It is intended to demonstrate what sort of attack is possible
and what conditions are necessary to exploit this weakness in the protocol.

~~~
  Norma                   Mallory                 Patsy
  (fp=N)                   -----                  (fp=P)
    |                        |                      |
    +---Signaling1 (fp=N)--->|                      |
    +-----Signaling2 (fp=N)------------------------>|
    |<-------------------------Signaling2 (fp=P)----+
    |<---Signaling1 (fp=P)---+                      |
    |                        |                      |
    |=======DTLS1=======>(Forward)======DTLS1======>|
    |<======DTLS2========(Forward)<=====DTLS2=======|
    |=======Media1======>(Forward)======Media1=====>|
    |<======Media2=======(Forward)<=====Media2======|
    |                       |                       |
    |=======DTLS2========>(Drop)                    |
    |                       |                       |
~~~
{: #implausible-attack title="Example Attack Scenario using Fingerprints"}

In this scenario, there are two sessions initiated at the same time by Norma.
Signaling is shown with single lines ('-'), DTLS and media with double lines
('=').

The first session is established with Mallory, who falsely uses Patsy's
certificate fingerprint (denoted with 'fp=P').  A second session is initiated
between Norma and Patsy.  Signaling for both sessions is permitted to complete.

Once signaling is complete on the first session, a DTLS connection is
established. Ostensibly, this connection is between Mallory and Norma but
Mallory forwards DTLS and media packets sent to her by Norma to Patsy.  These
packets are denoted 'DTLS1' because Norma associates these with the first
signaling session ('signaling1').

Mallory also intercepts packets from Patsy and forwards those to Norma at the
transport address that Norma associates with Mallory.  These packets are denoted
'DTLS2' to indicate that Patsy associates these with the second signaling
session ('signaling2'), however Norma will interpret these as being associated
with the first signaling session ('signaling1').

The second signaling exchange - 'signaling2', between Norma and Patsy - is
permitted to continue to the point where Patsy believes that it has succeeded.
This ensures that Patsy believes that she is communicating with Norma.  In the
end, Norma believes that she is communicating with Mallory, when she is really
communicating with Patsy.

Though Patsy needs to believe that the second signaling session has been
successfully established, Mallory has no real interest in seeing that session
also be established.  Mallory only needs to ensure that Patsy maintains the
active session and does not abandon the session prematurely.  For this reason,
it might be necessary to permit the signaling from Patsy to reach Norma to allow
Patsy to receive a call setup completion signal, such as a SIP ACK.  Once the
second session is established, Mallory might cause DTLS packets sent by Norma to
Patsy to be dropped.  It is likely that these DTLS packets will be discarded by
Patsy as Patsy will already have a successful DTLS connection established.

For the attacked session to be sustained beyond the point that Norma detects
errors in the second session, Mallory also needs to block any signaling that
Norma might send to Patsy asking for the call to be abandoned.  Otherwise, Patsy
might receive a notice that the call is failed and thereby abort the call.

This attack creates an asymmetry in the beliefs about the identity of peers.
However, this attack is only possible if the victim (Norma) is willing to
conduct two sessions nearly simultaneously, if the attacker (Mallory) is on the
network path between the victims, and if the same certificate - and therefore
SDP `fingerprint` attribute value - is used in both sessions.

Where ICE {{?ICE=RFC8445}} is used, Mallory also needs to ensure that
connectivity checks between Patsy and Norma succeed, either by forwarding checks
or answering and generating the necessary messages.


## Unique Session Identity Solution {#sess-id}

The solution to this problem is to assign a new identifier to communicating
peers.  Each endpoint assigns their peer a unique identifier during call
signaling.  The peer echoes that identifier in the TLS handshake, binding that
identity into the session.  Including this new identity in the TLS handshake
means that it will be covered by the TLS Finished message, which is necessary to
authenticate it (see {{SIGMA}}).

Successful validation that the identifier matches the expected value means that
the connection corresponds to the signaled session and is therefore established
between the correct two endpoints.

This solution relies on the unique identifier given to DTLS sessions using the
SDP `tls-id` attribute {{!DTLS-SDP=I-D.ietf-mmusic-dtls-sdp}}.  This field is
already required to be unique.  Thus, no two offers or answers from the same
client will have the same value.

A new `external_session_id` extension is added to the TLS or DTLS handshake for
connections that are established as part of the same call or real-time session.
This carries the value of the `tls-id` attribute and provides integrity
protection for its exchange as part of the TLS or DTLS handshake.


## The external_session_id TLS Extension {#external_session_id}

The `external_session_id` TLS extension carries the unique identifier that an
endpoint selects.  When used with SDP, the value MUST include the `tls-id`
attribute from the SDP that the endpoint generated when negotiating the session.
This document only defines use of this extension for SDP; other methods of
external session negotiation can use this extension to include a unique session
identifier.

The `extension_data` for the `external_session_id` extension contains an
ExternalSessionId struct, described below using the syntax defined in
{{!TLS13}}:

~~~
   struct {
      opaque session_id<20..255>;
   } ExternalSessionId;
~~~

For SDP, the `session_id` field of the extension includes the value of the
`tls-id` SDP attribute as defined in {{!DTLS-SDP=I-D.ietf-mmusic-dtls-sdp}}
(that is, the `tls-id-value` ABNF production).  The value of the `tls-id`
attribute is encoded using ASCII {{!ASCII=RFC0020}}.

Where RTP and RTCP {{?RTP=RFC3550}} are not multiplexed, it is possible that the
two separate DTLS connections carrying RTP and RTCP can be switched.  This is
considered benign since these protocols are usually distinguishable.  RTP/RTCP
multiplexing is advised to address this problem.

The `external_session_id` extension is included in a ClientHello and either
ServerHello (for TLS and DTLS versions less than 1.3) or EncryptedExtensions
(for TLS 1.3).  In TLS 1.3, the `external_session_id` extension MUST NOT be
included in a ServerHello.

Endpoints MUST check that the `session_id` parameter in the extension that they
receive includes the `tls-id` attribute value that they received in their peer's
session description.  Endpoints can perform string comparison by ASCII decoding
the TLS extension value and comparing it to the SDP attribute value, or compare
the encoded TLS extension octets with the encoded SDP attribute value.  An
endpoint that receives a `external_session_id` extension that is not identical
to the value that it expects MUST abort the connection with a fatal
`handshake_failure` alert.

An endpoint that is communicating with a peer that does not support this
extension will receive a ClientHello, ServerHello or EncryptedExtensions that
does not include this extension.  An endpoint MAY choose to continue a session
without this extension in order to interoperate with peers that do not implement
this specification.

In TLS 1.3, the `external_session_id` extension MUST be sent in the
EncryptedExtensions message.


# Consequences of Session Concatenation

Use of session identifiers does not prevent an attacker from establishing two
concurrent sessions with different peers and forwarding signaling from those
peers to each other.  Concatenating two signaling sessions in this way creates
two signaling sessions, with two session identifiers, but only the TLS
connections from a single session are established as a result.  In doing so, the
attacker creates a situation where both peers believe that they are talking to
the attacker when they are talking to each other.

In the absence of any higher-level concept of peer identity, the use of session
identifiers does not prevent session concatenation if the attacker is able to
copy the session identifier from one signaling session to another.  This kind of
attack is prevented by systems that enable peer authentication such as WebRTC
identity {{!WEBRTC-SEC}} or SIP identity {{?SIP-ID}}.  However, session
concatenation remains possible at higher layers: an attacker can establish two
independent sessions and simply forward any data it receives from one into the
other.

Use of the `external_session_id` does not guarantee that the identity of the
peer at the TLS layer is the same as the identity of the signaling peer.  The
advantage an attacker gains by concatenating sessions is limited unless it is
assumed that signaling and TLS peers are the same.  If a secondary protocol uses
the signaling channel with the assumption that the signaling and TLS peers are
the same then that protocol is vulnerable to attack unless they also validate
the identity of peers at both layers.

It is important to note that multiple connections can be created within the same
signaling session.  An attacker might concatenate only part of a session,
choosing to terminate some connections (and optionally forward data) while
arranging to have peers interact directly for other connections.  It is even
possible to have different peers interact for each connection.  This means that
the actual identity of the peer for one connection might differ from the peer on
another connection.

Information extracted from a TLS connection therefore MUST NOT be used in a
secondary protocol outside of that connection if that protocol relies on the
signaling protocol having the same peers.  Similarly, security-sensitive
information from one TLS connection MUST NOT be used in other TLS connections
even if they are established as a result of the same signaling session.


# Security Considerations

This entire document contains security considerations.


# IANA Considerations

This document registers two extensions in the TLS "ExtensionType Values"
registry established in {{!TLS13}}:

* The `external_id_hash` extension defined in {{external_id_hash}} has been
  assigned a code point of TBD; it is recommended and is marked as "Encrypted"
  in TLS 1.3.

* The `external_session_id` extension defined in {{external_session_id}} has
  been assigned a code point of TBD; it is recommended and is marked as
  "Encrypted" in TLS 1.3.


--- back

# Acknowledgements

This problem would not have been discovered if it weren't for discussions with
Sam Scott, Hugo Krawczyk, and Richard Barnes.  A solution similar to the one
presented here was first proposed by Karthik Bhargavan who provided valuable
input on this document.  Thyla van der Merwe assisted with a formal model of the
solution.  Adam Roach and Paul E. Jones provided significant review and input.
