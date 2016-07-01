theory BasicChallengeResponse
begin

builtins: hashing, symmetric-encryption, asymmetric-encryption, signing
functions: h/1, pk/1

rule Setup:
   [ Fr(~ltkA) ] --> [ !Pk((~ltkA), pk(~ltkA)) ]

rule Offer:
   [ Fr(~orand), !Pk(priv, pub) ]
   --[ Offered(~orand, pub) ]->
   []


/* Explicit equality checking */
axiom Eq_check_succeed: "All x y #i. Eq(x,y) @ i ==> x = y"
axiom Neq_check_succeed: "All x y #i. Neq(x,y) @ i ==> not (x = y)"



end
