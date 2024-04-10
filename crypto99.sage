from hashlib import sha256
from time import time

p = 2^255 - 19
q = 2^252 + 27742317777372353535851937790883648493
Zq = Integers(q)
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


class Party:
    def __init__(self, index, n):
        self.n = n
        self.t = n//2-1
        self.index = index # Index is a number between 1 and n
        self.secret_key = Zq.random_element()
        self.public_key = fast_multiply(self.secret_key, H)
        self.public_keys = [0 for _ in range(self.n)]
        self.commitments = [0 for _ in range(self.t)]
        self.encrypted_shares = [0 for _ in range(self.n)]
        self.dealer_proof = [0,0]
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
    
    def store_encrypted_shares_and_proof(self, encrypted_shares, dealer_proof):
        self.encrypted_shares = encrypted_shares # Assume shares are stored in order of party indices
        self.dealer_proof = dealer_proof

    def store_decrypted_shares_and_proofs(self, decrypted_shares_and_proof):
        self.decrypted_shares_and_proof = decrypted_shares_and_proof
    
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

        return reconstructed_secret

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
    
    def share_stage(self):
        self.generate_polynomial()
        self.generate_commitments()
        self.generate_encrypted_evals()
        self.dleq_pol()
        return [self.commitments, self.encrypted_shares, self.proof]

    def broadcast_commitments(self):
        return self.commitments
    
    def broadcast_share_and_proof(self):
        return self.encrypted_shares, self.proof

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

def benchmark_crypto99(n):
    public_keys = [0 for _ in range(n)]
    parties = [0 for _ in range(n)]
    decrypted_shares_and_proofs = [0 for _ in range(n)]

    total_Tparty_init = 0

    for i in range(1,n+1):
        temp_Tparty_init = time()
        p = Party(i, n)
        public_keys[i-1] = p.broadcast_public_key()
        parties[i-1] = p
        total_Tparty_init += time() - temp_Tparty_init

    avg_Tparty_init = total_Tparty_init/n
    
    Tdealer_init = time()
    dealer = Dealer(public_keys, n)
    Tdealer_init = time() - Tdealer_init

    Tdealer_pol_generation = time()
    dealer.generate_polynomial()
    Tdealer_pol_generation = time() - Tdealer_pol_generation

    Tdealer_commitments_generation = time()
    dealer.generate_commitments()
    Tdealer_commitments_generation = time() - Tdealer_commitments_generation
    
    Tdealer_comm = time()
    commitments = dealer.broadcast_commitments()
    Tdealer_comm = time() - Tdealer_comm

    Tdealer_encrypt_shares = time()
    dealer.generate_encrypted_evals()
    Tdealer_encrypt_shares = time() - Tdealer_encrypt_shares

    Tdealer_proof = time()
    dealer.dleq_pol()
    Tdealer_proof = time() - Tdealer_proof

    temp_Tdealer_comm = time()
    (enc_shares, pi_share) = dealer.broadcast_share_and_proof()
    Tdealer_comm += time() - temp_Tdealer_comm

    total_Tparty_comm = 0
    total_Tparty_verify = 0
    total_Tparty_decrypt_share = 0
    total_Tparty_proof = 0

    for i in range(n):
        p = parties[i]
        temp_Tparty_comm = time()
        p.store_public_keys(public_keys)
        p.store_commitments(commitments)
        p.store_encrypted_shares_and_proof(enc_shares, pi_share)
        total_Tparty_comm += time() - temp_Tparty_comm

        temp_Tparty_verify = time()
        party_verified = p.verify_encrypted_shares()
        total_Tparty_verify += time() - temp_Tparty_verify

        if party_verified:
            temp_Tparty_decrypt_share = time()
            p.generate_decrypted_share()
            total_Tparty_decrypt_share += time() - temp_Tparty_decrypt_share
            temp_Tparty_proof = time()
            p.dleq_share()
            total_Tparty_proof = time() - temp_Tparty_proof
            decrypted_shares_and_proofs[i] = p.broadcast_decrypted_share_and_proof()

    avg_Tparty_verify = total_Tparty_verify/n
    avg_Tparty_decrypt_share = total_Tparty_decrypt_share/n
    avg_Tparty_proof = total_Tparty_proof/n

    for i in range(n):
        p = parties[i]
        temp_Tparty_comm = time()
        p.store_decrypted_shares_and_proofs(decrypted_shares_and_proofs)
        total_Tparty_comm += time() - temp_Tparty_comm

    avg_Tparty_comm = total_Tparty_comm/n
    total_Tparty_verify_decrypted = 0
    
    for i in range(n):
        p = parties[i]
        temp_Tparty_verify_decrypted = time()
        p.verify_decrypted_shares()
        total_Tparty_verify_decrypted += time() - temp_Tparty_verify_decrypted
    
    avg_Tparty_verify_decrypted = total_Tparty_verify_decrypted/n

    total_Tparty_reconstruct = 0

    for i in range(n):
        p = parties[i]
        temp_Tparty_reconstruct = time()
        p.reconstruct_secret()
        total_Tparty_reconstruct += time() - temp_Tparty_reconstruct
    
    avg_Tparty_reconstruct = total_Tparty_reconstruct/n

    print("------------------------------dealer------------------------------")
    print("initialization time:                             ", Tdealer_init, " seconds")
    print("communication time:                              ", Tdealer_comm, " seconds")
    print("polynomial generation time:                      ", Tdealer_pol_generation, " seconds")
    print("commitments generation time:                     ", Tdealer_commitments_generation, " seconds")
    print("shares encryption time:                          ", Tdealer_encrypt_shares, " seconds")
    print("shares proof generation time:                    ", Tdealer_proof, " seconds")
    print("------------------------------party-------------------------------")
    print("average initialization time:                     ", avg_Tparty_init, " seconds")
    print("average communication time:                      ", avg_Tparty_comm, " seconds")
    print("average encrypted shares verification time:      ", avg_Tparty_verify, " seconds")
    print("average decrypted shares generation time:        ", avg_Tparty_decrypt_share, " seconds")
    print("average decrypted share proof generation time:   ", avg_Tparty_proof, " seconds")
    print("average decrypted shares verification time:      ", avg_Tparty_verify_decrypted, "seconds")
    print("average secret reconstruction time:              ", avg_Tparty_reconstruct, " seconds")
    print("--------------------------communication---------------------------")
    print("dealer + average party communication time:       ", Tdealer_comm+avg_Tparty_comm, "seconds")
    print("dealer + total time for ", n, " parties:         ", Tdealer_comm+total_Tparty_comm, " seconds")
    print("--------------------------sharing stage---------------------------")
    print("dealer side time:                                ", Tdealer_pol_generation+Tdealer_commitments_generation+Tdealer_encrypt_shares+Tdealer_proof+Tdealer_comm, " seconds")
    print("average party side time:                         ", avg_Tparty_comm, " seconds")
    print("total average time:                              ", Tdealer_pol_generation+Tdealer_encrypt_shares+Tdealer_proof+Tdealer_comm+avg_Tparty_comm, " seconds")
    print("total time for ", n, " parties:                  ", Tdealer_pol_generation+Tdealer_encrypt_shares+Tdealer_proof+Tdealer_comm+total_Tparty_comm, " seconds")
    print("------------------------verification stage------------------------")
    print("total average time:                              ", avg_Tparty_verify, " seconds")
    print("total time for ", n, " parties:                  ", total_Tparty_verify, " seconds")
    print("-----------------------reconstruction stage-----------------------")
    print("total average time:                              ", avg_Tparty_decrypt_share+avg_Tparty_proof+avg_Tparty_verify_decrypted+avg_Tparty_reconstruct, " seconds")
    print("total time for ", n, " parties:                  ", total_Tparty_decrypt_share+total_Tparty_proof+total_Tparty_verify_decrypted+total_Tparty_reconstruct, " seconds")
 

def test_crypto99(n):
    public_keys = [0 for _ in range(n)]
    parties = [0 for _ in range(n)]
    decrypted_shares_and_proofs = [0 for _ in range(n)]

    print("------------------------")
    print("Starting crypto99 PVSS tests")
    print("------------------------")

    for i in range(1,n+1):
        p = Party(i, n)
        public_keys[i-1] = p.broadcast_public_key()
        parties[i-1] = p

    print("------------------------------------------------------")
    print("Party generation and public key publication successful")
    print("------------------------------------------------------")

    dealer = Dealer(public_keys, n)
    dealer.generate_polynomial()
    dealer.generate_commitments()
    commitments = dealer.broadcast_commitments()
    dealer.generate_encrypted_evals()
    dealer.dleq_pol()
    (enc_shares, pi_share) = dealer.broadcast_share_and_proof()

    print("---------------------------------------------------------------------")
    print("Dealer generation and encrypted shares + proof publication successful")
    print("---------------------------------------------------------------------")

    for i in range(n):
        p = parties[i]
        p.store_public_keys(public_keys)
        p.store_commitments(commitments)
        p.store_encrypted_shares_and_proof(enc_shares, pi_share)

        assert p.verify_encrypted_shares()

    print("---------------------------------------------")
    print("Party encrypted share verification successful")
    print("---------------------------------------------")

    for i in range(n):
        p = parties[i]
        p.generate_decrypted_share()
        assert p.encrypted_shares[p.index-1] == fast_multiply(p.secret_key, p.decrypted_share)
        p.dleq_share()
        decrypted_shares_and_proofs[i] = p.broadcast_decrypted_share_and_proof()
        assert len(decrypted_shares_and_proofs[i]) == 2 and decrypted_shares_and_proofs[i][0] != 0 and decrypted_shares_and_proofs[i][1] != 0

            
    for i in range(n):
        p = parties[i]
        p.store_decrypted_shares_and_proofs(decrypted_shares_and_proofs)
        assert len(p.decrypted_shares_and_proof) == n
        for j in range(n):
            assert len(p.decrypted_shares_and_proof[j]) == 2 and p.decrypted_shares_and_proof[j][0] != 0 and p.decrypted_shares_and_proof[j][1] != 0

    print("---------------------------------------------")
    print("Party decrypted share distribution successful")
    print("---------------------------------------------")

    for i in range(n):
        p = parties[i]
        p.verify_decrypted_shares()
        assert len(p.valid_decrypted_shares) == n
        for j in range(n):
            assert p.valid_decrypted_shares[j] != 0

    print("---------------------------------------------")
    print("Party decrypted share verification successful")
    print("---------------------------------------------")

    for i in range(n):
        p = parties[i]
        reconstructed_secret = p.reconstruct_secret()
        generator_secret = fast_multiply(global_secret, H)
        assert generator_secret == reconstructed_secret

    print("--------------------------------------")
    print("Party secret reconstruction successful")
    print("--------------------------------------")

    print("All tests successful")

def crypto99_stages(n):
    public_keys = [0 for _ in range(n)]
    parties = [0 for _ in range(n)]
    decrypted_shares_and_proofs = [0 for _ in range(n)]

    for i in range(1,n+1):
        p = Party(i, n)
        public_keys[i-1] = p.broadcast_public_key()
        parties[i-1] = p
    
    dealer = Dealer(public_keys, n)
    total_time_dealer = time()
    [commitments, encrypted_shares, dealer_proof] = dealer.share_stage()
    total_time_dealer = time() - total_time_dealer

    total_time_party = time()

    for i in range(n):
        p = parties[i]
        decrypted_shares_and_proofs[i] = p.verification_stage(public_keys, commitments, encrypted_shares, dealer_proof)
    
    for i in range(n):
        p = parties[i]
        p.reconstruction_stage(decrypted_shares_and_proofs)
    
    total_time_party = time() - total_time_party

    print("Total time for dealer: ", total_time_dealer, " seconds")
    print("Total time for ", n, " parties: ", total_time_party, " seconds")
    print("Average time: ", total_time_dealer + total_time_party/n, " seconds")


#! Does not work for all values of n
n = 8 #! Uneven values or values under 6 do not work. After further experimentation, it seems that the code works for an uneven number and even number with the same floor division by 2, then it does not, and for the next even number it works again.
#benchmark_crypto99(n)
test_crypto99(n) 
#crypto99_stages(n)