theory Suks
begin

builtins: hashing, symmetric-encryption, asymmetric-encryption, signing
functions: h/1, pk/1

rule Setup:
   [ Fr(~ltkA) ] --> [ KeyPair(~ltkA, pk(~ltkA)) ]

rule Offeror_SendOffer:
   [ Fr(~orand), KeyPair(priv, pub) ]
   --[ Offered(~orand, pub) ]->
   [ Offer(~orand, pub) ]

rule Answerer_RecvOfferSendAnswer:
   [ Fr(~arand), KeyPair(priv, pub), Offer(orand, opub) ]
   --[ Answered(orand, opub, ~arand, pub) ]->
   [ Answer(~arand, pub) ]

rule Offerer_RecvAnswerSendHs:
   [ Offer(orand, opub), Answer(arand, apub) ]
   --[ AnswerReceived(orand, arand, apub) ]->
   [ ]

/* Explicit equality checking */
axiom Eq_check_succeed: "All x y #i. Eq(x,y) @ i ==> x = y"
axiom Neq_check_succeed: "All x y #i. Neq(x,y) @ i ==> not (x = y)"


lemma FullCall:
   exists-trace
   " Ex OR OP AR AP #j #k #l.
        Offered(OR, OP) @ #j &
        Answered(OR, OP, AR, AP) @ #k &
        AnswerReceived(OR, AR, AP) @ #l &
        #j < #k &
        #k < #l
   "
/*
lemma FullCall:
   exists-trace
   " Ex OR OP AR AP #j #k #l.
        Offered(OR, OP) @ #j &
        Answered(OR, OP, AR, AP) @ #k &
        AnswerReceived(OP, AR) @ #l &
        #j < #k &
        #k < #l
   "
*/
end
