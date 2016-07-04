theory Suks
begin

builtins: hashing, symmetric-encryption, asymmetric-encryption, signing
functions: h/1, pk/1


/* This is a simple model capturing the essential features of DTLS-SRTP.
 *
 * The central server supplies a CallId to Offerer and Answerer,
 * each of whom have a long-term key pair.
 *
 * O -> A: Offer  [CallId, ORandom, K_pub_O]  // over secure signaling channel 
 * A -> O: Answer [CallId, ARandom, K_pub_A]  // over secure signaling channel
 * A -> O: clienthello [Sign(K_priv_A, (ORandom, K_pub_O, ARandom, K_pub_A))
 * O -> A: serverhello [Sign(K_priv_O, (ORandom, K_pub_O, ARandom, K_pub_A))
 *
 * The subtle point here is that in RFC 5763/5764, the randoms and the
 * CallId are *not* carried in the signaling, which allows for a UKS,
 * thus falsifying Lemma NoUKS.
 *
 */

rule SetupOfferer:
   [ Fr(~oPriv) ] --> [ !OffererKeyPair(~oPriv, pk(~oPriv)) ]

rule SetupAnswerer:
   [ Fr(~aPriv) ] --> [ !AnswererKeyPair(~aPriv, pk(~aPriv)) ]

rule InitiateCall:
   [ Fr(~callId) ] --[ Initiated(~callId) ]->
   [ OfferInitiated(~callId), AnswerInitiated(~callId) ]
   
rule Offeror_SendOffer:
   [ Fr(~orand), !OffererKeyPair(priv, opub), OfferInitiated(callId) ]
   --[ Offered(callId, opub) ]->
   [ Offer(callId, ~orand, opub),
     SavedOffer(callId, ~orand, opub),
     Out(~orand)]

rule Answerer_RecvOfferSendAnswer:
   let HsParams = <orand,opub,~arand,apub> in
   [ !AnswererKeyPair(priv, apub),
     AnswerInitiated(callId),
     Offer(callId, orand_s, opub),
     Fr(~arand),
     In(orand)
     ]
   --[
       ifdef(`randomsinsignaling',`Eq(orand_s,orand),')
       Answered(callId, opub, apub)
     ]->
   [
     Answer(callId, ~arand, apub),
     SavedAnswer(callId, orand, opub, ~arand, apub),
     Out(<'clienthello',
          HsParams,
          sign{<'clienthello', HsParams>}priv>)
   ]

rule Offerer_RecvAnswerAndClientHello:
   let HsParams = <orand,opub,arand,apub> in
   [ !OffererKeyPair(priv, opub),
     SavedOffer(callId, orand, opub), Answer(callId, arand_s, apub),
     In(<'clienthello',
          HsParams,
          signature>)]
   --[
       ifdef(`randomsinsignaling',`Eq(arand_s, arand),')
       Eq(verify(signature,
                 <'clienthello', HsParams>, apub), true),
       AnswerReceived(callId, opub, apub),
       OffererConnected(callId, opub, apub, orand, arand)
   ]->    
   [
     Out(<'serverhello',
          HsParams,
          sign{<'serverhello', HsParams>}priv>)

   ]

rule Answerer_RecvServerHello:
   let HsParams = <orand,opub,arand,apub> in
   [
     SavedAnswer(callId, orand, opub, arand, apub),
     In(<
         'serverhello',
         HsParams,
         signature
        >
       )
   ]
   --[
     Eq(verify(signature,
        <'serverhello', HsParams>, opub), true),
     AnswererConnected(callId, opub, apub, orand, arand)
   ]->
   [ 
   ]

/* Explicit equality checking */
axiom Eq_check_succeed: "All x y #i. Eq(x,y) @ i ==> x = y"
axiom Neq_check_succeed: "All x y #i. Neq(x,y) @ i ==> not (x = y)"

/* Don't be offerer and answerer for the same call. */
axiom One_role:
   " All O A C #i #j.
     Offered(C, O) @i & Answered(C, O, A) @j ==> not(O = A)"

lemma FullCall:
   exists-trace
   " Ex CI OP AP OR AR#j #k #l #m #n.
        Initiated(CI) @ #j &
        Offered(CI, OP) @ #k &
        Answered(CI, OP, AP) @ #l &
        AnswerReceived(CI, OP, AP) @ #m &
        OffererConnected(CI, OP, AP, OR, AR) @ #m &
        AnswererConnected(CI, OP, AP, OR, AR) @ #n &
        #j < #k &
        #k < #l &
        #l < #m &
        #m < #n
   "

lemma NoUKS:
   " All CIO CIA OP AP OR AR #i #j #m #n.
        Initiated(CIO) @ #i &
        Initiated(CIA) @ #j &
        OffererConnected(CIO, OP, AP, OR, AR) @ #m &
        AnswererConnected(CIA, OP, AP, OR, AR) @ #n ==>
        CIO = CIA
   "
    

end
