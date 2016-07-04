# DTLS-SRTP UKS Model

This directory contains a Tamarin model of the Unknown Key-Share in
DTLS-SRTP described in draft-thomson-dtls-srtp-suks. The message flow
here is:

~~~~
  O -> A: Offer  [CallId, ORandom, K_pub_O]  // over secure signaling channel 
  A -> O: Answer [CallId, ARandom, K_pub_A]  // over secure signaling channel
  A -> O: clienthello [Sign(K_priv_A, (ORandom, K_pub_O, ARandom, K_pub_A))
  O -> A: serverhello [Sign(K_priv_O, (ORandom, K_pub_O, ARandom, K_pub_A))
~~~~

Note that in RFC 5763 we don't send either the CallID or the randoms over the
signaling channel, but the CallID is implicit. In the UKS, the two ends of
the DTLS channel (as specified by conn-params = {crand, srand, cpub, spub}) have different
call-ids. We model the DTLS channel as counter-signatures on the connection
parameters.

The NoUKS lemma tests that when each end records success with the
output being: {call-id, conn-params}, that the call-ids are the same
on both sides.

This directory contains two models:

* rfc5763: the existing RFC 5763 protocol. This exhibits the UKS.
* draft-thomson: the existing RFC 5763 protocol but where the randoms are
  communicated in the signaling channel and checked against the DTLS
  channel. This does not exhibit the UKS.

These models share the same common core and message flow and are
wrappers around the same file (handshake.m4i). The only difference
is that the draft-thomson model sets a flag which causes the handshake
to check the random values on both sides.




