theory Suks
begin

builtins: hashing, symmetric-encryption, asymmetric-encryption, signing
functions: h/1, pk/1


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
     Offer(callId, orands, opub),
     Fr(~arand),
     In(orand)
     ]
   --[ Answered(callId, opub, apub) ]->
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
     SavedOffer(callId, orand, opub), Answer(callId, aranda, apub),
     In(<'clienthello',
          HsParams,
          signature>)]
   --[
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
