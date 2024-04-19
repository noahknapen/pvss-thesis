from hashlib import sha256
from time import time

p = 2^255 - 19
q = 2^252 + 27742317777372353535851937790883648493
Zq = Integers(q)
Zv = Integers(1)
Am = 486662          # Montgomery A-coefficient
Ar = int((Am+2)/4)   # reduced Montgomery coefficent
E = EllipticCurve(GF(p),[0,Am,0,1,0])
RP.<x> = PolynomialRing(Zq)
global_secret = 0

G = E.random_point() # generator 
while G.order() != q:
    G = E.random_point()

H = E.random_point() # generator 
while H.order() != q:
    H = E.random_point()

def xADD(P,Q,R): # points are of the form [X,Z]
        [XP,ZP] = [P[0],P[1]];
        [XQ,ZQ] = [Q[0],Q[1]];
        [XR,ZR] = [R[0],R[1]];

        V0 = XP + ZP
        V1 = XQ - ZQ
        V1 = V1 * V0
        V0 = XP - ZP
        V2 = XQ + ZQ
        V2 = V2 * V0
        V3 = V1 + V2
        V3 = V3^2
        V4 = V1 - V2
        V4 = V4^2
        Xp = ZR * V3
        Zp = XR * V4
        
        return [Xp,Zp]

def xDBL(P): # points are of the form [X,Z]
    [XP,ZP] = [P[0],P[1]]
    
    V1 = XP + ZP
    V1 = V1^2
    V2 = XP - ZP
    V2 = V2^2
    X2 = V1 * V2
    V1 = V1 - V2
    V3 = Ar * V1
    V3 = V3 + V2
    Z2 = V1 * V3
    
    return [X2,Z2]

def Montgomery_ladder(k,P): # points are of the form [X,Z]
    x0,x1 = P,xDBL(P)
    k = k.binary()
    l = len(k)
    for i in range(1,l):
        if k[i]=='0':
            x0,x1 = xDBL(x0),xADD(x0,x1,P)
        if k[i]=='1':
            x0,x1 = xADD(x0,x1,P),xDBL(x1)
    return x0,x1

def recover_y(P,Q,R):
    [XP,YP] = [P[0],P[1]] # P is an actual elliptic curve point in the form (X:Y:Z)
    [XQ,ZQ] = [Q[0],Q[1]]
    [XR,ZR] = [R[0],R[1]]
        
    V1 = XP * ZQ
    V2 = XQ + V1
    V3 = XQ - V1
    V3 = V3^2
    V3 = V3 * XR
    V1 = 2*Am*ZQ
    
    V2 = V2 + V1
    V4 = XP * XQ
    V4 = V4 + ZQ
    V2 = V2 * V4
    V1 = V1 * ZQ
    V2 = V2 - V1
    V2 = V2 * ZR
    
    Y  = V2 - V3
    V1 =  2 * YP
    V1 = V1 * ZQ
    V1 = V1 * ZR
    X  = V1 * XQ
    Z  = V1 * ZQ
    
    return E(X,Y,Z) #! The bug occurs here since X, Y, and Z are 0 in the bug-cases

def fast_multiply(k,P): # use montgomery ladder and y-recovery
    PM = [P[0],P[2]] # X-Z coordinates
    x0,x1 = Montgomery_ladder(Integer(k),PM)
    return recover_y(P,x0,x1)

class BulletinBoard:
    def verify_adapted_dleqs(self, encrypted_votes_and_proofs):
        for enc_vote_and_proof in encrypted_votes_and_proofs:
            C0 = self.commitments[0]
            U = enc_vote_and_proof[0]
            args = enc_vote_and_proof[1]
            a0 = args[0]
            b0 = args[1]
            a1 = args[2]
            b1 = args[3]
            c = args[4]
            d0 = args[5]
            r0 = args[6]
            d1 = args[7]
            r1 = args[8]

        if not (c == d0 + d1 and a0 == fast_multiply(r0, G) + fast_multiply(d0, C0) and b0 == fast_multiply(r0, H) + fast_multiply(d0, U) and a1 == fast_multiply(r1, G) + fast_multiply(d1, C0) and b1 == fast_multiply(r1, H) + fast_multiply(d1, U - H)):
            return False
        
        return True


class Party:
    def __init__(self, index, m, n):
        self.m = m # Number of voters (dealers)
        self.n = n # Number of talliers (parties)
        self.t = n//2-1
        self.index = index # Index is a number between 1 and n
        self.secret_key = Zq.random_element()
        self.public_key = fast_multiply(self.secret_key, H)
        self.public_keys = [0 for _ in range(self.n)]
        self.commitments = [0 for _ in range(self.t)]
        self.encrypted_shares = [0 for _ in range(self.n)]
        self.dealer_proofs = [0,0] #? Not needed to verify encrypted shares? Only the verification of the bulletin board regarding the vote?
        self.decrypted_share = 0
        self.share_proof = [0,0]
        self.decrypted_shares_and_proof = [0 for _ in range(self.n)]
        self.valid_decrypted_shares = [0 for _ in range(self.n)]
    
    def broadcast_public_key(self):
        return self.public_key

    def broadcast_decrypted_share_and_proof(self):
        return self.decrypted_share, self.share_proof 

    def store_public_keys(self, public_keys):
        self.public_keys = public_keys

    def store_commitments(self, commitments):
        self.commitments = commitments
    
    def store_encrypted_shares_and_proof(self, encrypted_shares_per_party, dealer_proofs):
        for m_i in range(len(encrypted_shares_per_party)):
            for n_i in range(len(encrypted_shares_per_party[m_i])):
                self.encrypted_shares[m_i] += encrypted_shares_per_party[m_i][n_i]

    def store_decrypted_shares_and_proofs(self, decrypted_shares_and_proof):
        self.decrypted_shares_and_proof = decrypted_shares_and_proof
   
    def store_encrypted_votes(self, encrypted_votes):
        self.encrypted_votes = encrypted_votes
    
    def verify_encrypted_shares(self):
        c = self.dealer_proof[0]
        r_list = self.dealer_proof[1]

        reconstructed_gen_evals = [0 for _ in range(self.n)]
        reconstructed_gen_eval_str = ""
        enc_eval_str = ""

        for i in range(self.n):
            enc_eval_str += str(self.encrypted_shares[i]) + str(",")
            for j in range(self.t):
                    reconstructed_gen_evals[i] += fast_multiply((i+1)^j, self.commitments[j])
                    
            reconstructed_gen_eval_str += str(reconstructed_gen_evals[i]) + str(",")
        
        enc_eval_str = enc_eval_str[:-1]
        reconstructed_gen_eval_str = reconstructed_gen_eval_str[:-1]
        
        reconstructed_a1_str = ""
        reconstructed_a2_str = ""

        for i in range(self.n):
            reconstructed_a1_str += str(fast_multiply(r_list[i], G) + fast_multiply(c, reconstructed_gen_evals[i])) + str(",")
            reconstructed_a2_str += str(fast_multiply(r_list[i], self.public_keys[i]) + fast_multiply(c, self.encrypted_shares[i])) + str(",")
        
        reconstructed_a1_str = reconstructed_a1_str[:-1]
        reconstructed_a2_str = reconstructed_a2_str[:-1]

        reconstructed_c = Integer(Zq(int(sha256(str(reconstructed_gen_eval_str + enc_eval_str + reconstructed_a1_str + reconstructed_a2_str).encode()).hexdigest(), 16)))

        return c == reconstructed_c

    def generate_decrypted_share(self):
        inv_priv_key = Integer(self.secret_key).inverse_mod(q)
        self.decrypted_share = fast_multiply(inv_priv_key, self.encrypted_shares[self.index-1])
    
    def dleq_share(self):
        # proof knowledge of a correct self.decrypted_share
        # DLEQ(H, y_i=self.public_key, X_i=self.decrypted_share, Y_i=encrypted_shares[i])
        pub_key_str = str(self.public_key)
        enc_share_str = str(self.encrypted_shares[self.index-1])
        
        w = Zq.random_element()
        a1_str = str(fast_multiply(w, H))
        a2_str = str(fast_multiply(w, self.decrypted_share))
        
        # cryptographic hash of y_i and Y_i, a1 and a2
        c = Integer(Zq(int(sha256(str(pub_key_str + enc_share_str + a1_str + a2_str).encode()).hexdigest(), 16)))
        r = w - c*self.secret_key
        
        self.share_proof = [c, r]
    
    def verify_decrypted_shares(self):
        for i in range(len(self.decrypted_shares_and_proof)):
            decrypted_share = self.decrypted_shares_and_proof[i][0]
            share_proof = self.decrypted_shares_and_proof[i][1]
            c = share_proof[0]
            r = share_proof[1]

            reconstructed_pub_key_str = str(self.public_keys[i])
            reconstructed_enc_share_str = str(self.encrypted_shares[i])
            reconstructed_a1_str = str(fast_multiply(r, H) + fast_multiply(c, self.public_keys[i]))
            reconstructed_a2_str = str(fast_multiply(r, decrypted_share) + fast_multiply(c, self.encrypted_shares[i]))

            reconstructed_c = Integer(Zq(int(sha256(str(reconstructed_pub_key_str + reconstructed_enc_share_str + reconstructed_a1_str + reconstructed_a2_str).encode()).hexdigest(), 16)))

            if c == reconstructed_c:
                self.valid_decrypted_shares[i] = decrypted_share

    def lambda_func(self, i):
        lambda_i = Zq(1)
        for j in range(1, self.t+1):
            if j != i:
                lambda_i *= Zq(j)/(Zq(j)-Zq(i))
        
        return lambda_i

    def reconstruct_secret(self):
        # From https://github.com/darkrenaissance/darkfi/blob/master/script/research/pvss/pvss.sage
        reconstructed_secret = E(0)
        counter = 0

        for i in range(len(self.valid_decrypted_shares)): # w.l.o.g. we take the first t+1 valid shares, but randomly chosen t+1 shares can also be chosen
            if self.valid_decrypted_shares[i] != 0:
                reconstructed_secret += fast_multiply(self.lambda_func(i+1), self.valid_decrypted_shares[i])
                counter += 1
            if counter == self.t: # t shares needed to reconstruct
                break

        self.secret = reconstructed_secret
    
    def generate_accumulated_encrypted_vote(self):
        acc_vote = E(0)

        for i in range(self.m):
            acc_vote += self.encrypted_votes[i]
        
        self.acc_vote = acc_vote

    def generate_accumulated_decrypted_vote(self):

        for vote_tryout in range(self.m+1):
            if self.acc_vote - self.secret == fast_multiply(vote_tryout, H):
                return vote_tryout
        
        return False

    def verification_stage(self, public_keys, commitments, encrypted_shares, dealer_proof):
        self.store_public_keys(public_keys)
        self.store_commitments(commitments)
        self.store_encrypted_shares_and_proof(encrypted_shares, dealer_proof)

        if self.verify_encrypted_shares():
            self.generate_decrypted_share()
            self.dleq_share()
            return self.broadcast_decrypted_share_and_proof()

    def reconstruction_stage(self, decrypted_shares_and_proofs):
        self.store_decrypted_shares_and_proofs(decrypted_shares_and_proofs)
        self.verify_decrypted_shares()
        return self.reconstruct_secret() 

class Dealer:
    def __init__(self, public_keys, n):
        self.public_keys = public_keys
        self.n = n
        self.t = n//2-1 # Honest majority setting
        self.commitments = [0 for _ in range(self.t)]
        self.f = 0
        self.encrypted_shares = [0 for _ in range(self.n)]
        self.proof = [0,0]
        self.vote = None
        self.encrypted_vote = 0
        self.vote_proof = None
    
    def share_stage(self):
        self.generate_polynomial()
        self.generate_commitments()
        self.generate_encrypted_evals()
        self.dleq_pol()
        self.generate_vote()
        self.dleq_vote()
        return [self.commitments, self.encrypted_shares, self.proof, self.vote, self.vote_proof]

    def broadcast_commitments(self):
        return self.commitments
    
    def broadcast_share_and_proof(self):
        return self.encrypted_shares, self.proof

    def broadcast_vote_and_proof(self):
        return self.encrypted_vote, self.vote_proof

    def generate_polynomial(self):
        f = RP.random_element(degree=self.t-1)
        global global_secret #! Only for testing purposes
        global_secret = f(x=0)
        self.f = f
    
    def generate_commitments(self):
        coefs = self.f.coefficients(sparse=False)
        for i in range(self.t):
            self.commitments[i] = fast_multiply(coefs[i], G)

    def generate_encrypted_evals(self):
        evals = [self.f(x=i) for i in range(1, self.n+1)]
        enc_evals = [0 for _ in range(self.n)]
        
        for i in range(self.n):
            enc_evals[i] = fast_multiply(evals[i], self.public_keys[i])

        self.encrypted_shares = enc_evals
    
    def dleq_pol(self):
        # proof knowledge of self.f[i]
        # DLEQ(g, generator_evals, public_keys, encrypted_shares)
        evals = [self.f(x=i) for i in range(1, self.n+1)]
        gen_eval_str = ""
        enc_eval_str = ""
        a1_str = ""
        a2_str = ""
        w_list = [0 for _ in range(self.n)]
        r_list = [0 for _ in range(self.n)]
        
        for i in range(self.n):
            w = Zq.random_element()
            w_list[i] = w
            gen_eval_str += str(fast_multiply(evals[i], G)) + str(",") #? Right way to compute X_i? Because two ways in paper
            enc_eval_str += str(self.encrypted_shares[i]) + str(",")
            a1_str += str(fast_multiply(w, G)) + str(",")
            a2_str += str(fast_multiply(w, self.public_keys[i])) + str(",")
        
        gen_eval_str = gen_eval_str[:-1]
        enc_eval_str = enc_eval_str[:-1]
        a1_str = a1_str[:-1]
        a2_str = a2_str[:-1]
        
        c = Integer(Zq(int(sha256(str(gen_eval_str + enc_eval_str + a1_str + a2_str).encode()).hexdigest(), 16)))

        for i in range(self.n):
            r_list[i] = w_list[i] - c*evals[i]
        
        self.proof = [c, r_list]

    def generate_vote(self):
        self.vote = Zv.random_element()
        s = self.f(x=0)
        self.encrypted_vote = fast_multiply(s+self.vote, H)

    # Proof for value U, showing that v element of 0 or 1 by showing: log_H(U) = log_G(G^global_secret) or log_H(U) = 1 + log_G(G^global_secret) 
    def dleq_vote(self):
        C0 = self.commitments[0]
        s = self.f(x=0)
        w = Zq.random_element()

        if self.vote == 0:
            a0 = fast_multiply(w, G)
            b0 = fast_multiply(w, H)

            r1 = Zq.random_element()
            d1 = Zq.random_element()
            a1 = fast_multiply(r1, G) + fast_multiply(d1, C0)
            b1 = fast_multiply(r1, H) + fast_multiply(d1, self.encrypted_vote - fast_multiply(1-self.vote, H))
        elif self.vote == 1:
            a1 = fast_multiply(w, G)
            b1 = fast_multiply(w, H)

            r0 = Zq.random_element()
            d0 = Zq.random_element()
            a0 = fast_multiply(r0, G) + fast_multiply(d0, C0)
            b0 = fast_multiply(r0, H) + fast_multiply(d0, self.encrypted_vote - fast_multiply(1-self.vote, H))
        
        c = Integer(Zq(int(sha256(str(C0) + str(U) + str(a0) + str(b0) + str(a1) + str(b1).encode()).hexdigest(), 16)))

        if self.vote == 0:
            d0 = c - d1
            r0 = w - s*d0
        elif self.vote == 1:
            d1 = c - d0
            r1 = w - s*d1
        
        self.vote_proof = [a0, b0, a1, b1, c, d0, r0, d1, r1]


m = 8 # Number of voters (dealers)
n = 8 # Number of talliers (parties)
public_keys = [0 for _ in range(m)]
parties = [0 for _ in range(n)]
dealers = [0 for _ in range(m)]
enc_shares = [0 for _ in range(m)]
enc_votes = [0 for _ in range(m)]
vote_proofs = [0 for _ in range(m)]

for i in range(1,n+1):
    p = Party(i, n)
    parties[i-1] = p
    public_keys[i-1] = p.broadcast_public_key()

for i in range(m):
    d = Dealer(public_keys, n)
    dealers[i] = d
    [commitments, encrypted_shares, dealer_proof, encrypted_vote, vote_proof] = d.share_stage()
    enc_shares[i] = encrypted_shares
    enc_votes[i] = encrypted_vote
    vote_proofs[i] = vote_proof

b = BulletinBoard()
b.verify_adapted_dleqs(enc_votes, vote_proofs)



# Distribution protocol with v element of {0,1} and s a random secret value and computing value U = g^(s+v)