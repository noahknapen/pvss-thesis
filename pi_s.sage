from hashlib import sha256
from time import time
#TODO: create measurements
# Stage 2: See applications of PVSS in the literature and implement other PVSS schemes

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
        self.index = index # Index is a number between 1 and n
        self.secret_key = Zq.random_element()
        self.public_key = fast_multiply(self.secret_key, G)
        self.public_keys = [0 for _ in range(self.n)]
        self.encrypted_shares = [0 for _ in range(self.n)]
        self.dealer_proof = [0,0]
        self.dec_share = 0
        self.share_proof = [0,0]
        self.decrypted_shares_and_proof = [0 for _ in range(self.n)]
        self.valid_decrypted_shares = [0 for _ in range(self.n)]
    
    def publish_public_key(self):
        return self.public_key

    def store_public_keys(self, public_keys):
        self.public_keys = public_keys
    
    def store_encrypted_shares_and_proof(self, encrypted_shares, dealer_proof):
        self.encrypted_shares = encrypted_shares # Assume shares are stored in order of party indices
        self.dealer_proof = dealer_proof
    
    def store_decrypted_shares_and_proofs(self, dec_shares_and_proofs):
        self.decrypted_shares_and_proof = dec_shares_and_proofs # Assume shares are stored in order of party indices

    def verify_encrypted_shares(self):    
        d = self.dealer_proof[0]
        z = self.dealer_proof[1]
        temp_d1, temp_d2 = "", ""

        for i in range(self.n):
            temp_d1 = temp_d1 + str(self.encrypted_shares[i])+str(",")
            numerator = fast_multiply(z(x=i+1), self.public_keys[i])
            denominator = fast_multiply(d, self.encrypted_shares[i])
            temp_d2 = temp_d2 + str(numerator - denominator)+str(",")
        
        temp_d1 = temp_d1[:-1]
        temp_d2 = temp_d2[:-1]
        reconstructed_d = Integer(Zq(int(sha256((str(temp_d1)+str(temp_d2)).encode()).hexdigest(),16)))

        return d == reconstructed_d
    
    def broadcast_decrypted_share_and_proof(self):
        return self.dec_share, self.share_proof
    
    def generate_decrypted_share(self):
        inv_priv_key = Integer(self.secret_key).inverse_mod(q)
        self.dec_share = fast_multiply(inv_priv_key, self.encrypted_shares[self.index-1])
    
    def nizk_proof_for_dleq(self):
        r = Zq.random_element()
        c1 = fast_multiply(r, G)
        c2 = fast_multiply(r, self.dec_share)

        d = str(self.public_key) + str(",")
        d += str(self.encrypted_shares[self.index-1]) + str(",")
        d += str(c1) + str(",")
        d += str(c2)

        d = Integer(Zq(int(sha256(str(d).encode()).hexdigest(),16)))
        z = r + d*self.secret_key

        self.share_proof = [d,z]

    def verify_decrypted_shares(self):
        for i in range(len(self.decrypted_shares_and_proof)):
            dec_share = self.decrypted_shares_and_proof[i][0]
            share_proof = self.decrypted_shares_and_proof[i][1]
            d = share_proof[0]
            z = share_proof[1]

            nominator1 = fast_multiply(z, G)
            nominator2 = fast_multiply(z, dec_share)

            denominator1 = fast_multiply(d, self.public_keys[i])
            denominator2 = fast_multiply(d, self.encrypted_shares[i])

            temp_d = str(self.public_keys[i]) + str(",")
            temp_d += str(self.encrypted_shares[i]) + str(",")
            temp_d += str(nominator1-denominator1) + str(",")
            temp_d += str(nominator2-denominator2)

            reconstructed_d = Integer(Zq(int(sha256(str(temp_d).encode()).hexdigest(),16)))

            if d == reconstructed_d:
                self.valid_decrypted_shares[i] = dec_share

    def lambda_func(self, i):
        lambda_i = Zq(1)
        for j in range(1, self.n//2+1):
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
            if counter == self.n//2: # t+1 shares needed to reconstruct
                break
        
        return reconstructed_secret

    def verification_stage(self, public_keys, encrypted_shares, dealer_proof):
        self.store_public_keys(public_keys)
        self.store_encrypted_shares_and_proof(encrypted_shares, dealer_proof)

        if (self.verify_encrypted_shares()):
            self.generate_decrypted_share()
            self.nizk_proof_for_dleq()
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
        self.f = 0
        self.encrypted_shares = [0 for _ in range(self.n)]
        self.proof = [0,0]

    def share_stage(self):
        self.generate_polynomial()
        self.encrypted_shares = self.generate_encrypted_evals(self.f)
        self.pi_pdl()
        return self.broadcast_share_and_proof()
    
    def broadcast_share_and_proof(self):
        return self.encrypted_shares, self.proof
    
    def generate_polynomial(self):
        f = RP.random_element(degree=self.t)
        global global_secret #! Only for testing purposes
        global_secret = f(x=0)
        self.f = f

    def generate_encrypted_evals(self, pol):
        evals = [pol(x=i) for i in range(1, self.n+1)]
        enc_evals = [0 for _ in range(self.n)]
        
        for i in range(self.n):
            enc_evals[i] = fast_multiply(evals[i], self.public_keys[i])

        return enc_evals
    
    def pi_pdl(self):
        r = RP.random_element(degree=self.t)
        enc_r_evals = self.generate_encrypted_evals(r)

        temp_d1, temp_d2 = "", ""

        for i in range(self.n):
            temp_d1 = temp_d1 + str(self.encrypted_shares[i])+str(",") #! This is not appended so only takes the last result!!!!
            temp_d2 = temp_d2 + str(enc_r_evals[i])+str(",")
        
        temp_d1 = temp_d1[:-1]
        temp_d2 = temp_d2[:-1]
        d = Integer(Zq(int(sha256((temp_d1+temp_d2).encode()).hexdigest(),16)))
        z = r + d*self.f

        self.proof = [d,z]


def benchmark_pi_s(n):
    public_keys = [0 for _ in range(n)]
    parties = [0 for _ in range(n)]
    decrypted_shares_and_proofs = [0 for _ in range(n)]

    total_Tparty_init = 0

    for i in range(1,n+1):
        temp_Tparty_init = time()
        p = Party(i, n)
        public_keys[i-1] = p.publish_public_key()
        parties[i-1] = p
        total_Tparty_init += time() - temp_Tparty_init

    avg_Tparty_init = total_Tparty_init/n
    
    Tdealer_init = time()
    dealer = Dealer(public_keys, n)
    Tdealer_init = time() - Tdealer_init

    #(enc_shares, pi_share) = dealer.share_stage()
    Tdealer_pol_generation = time()
    dealer.generate_polynomial()
    Tdealer_pol_generation = time() - Tdealer_pol_generation

    Tdealer_encrypt_shares = time()
    dealer.encrypted_shares = dealer.generate_encrypted_evals(dealer.f)
    Tdealer_encrypt_shares = time() - Tdealer_encrypt_shares

    Tdealer_proof = time()
    dealer.pi_pdl()
    Tdealer_proof = time() - Tdealer_proof

    Tdealer_comm = time()
    (enc_shares, pi_share) = dealer.broadcast_share_and_proof()
    Tdealer_comm = time() - Tdealer_comm


    total_Tparty_comm = 0
    total_Tparty_verify = 0
    total_Tparty_decrypt_share = 0
    total_Tparty_proof = 0

    for i in range(n):
        p = parties[i]
        temp_Tparty_comm = time()
        p.store_public_keys(public_keys)
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
            p.nizk_proof_for_dleq()
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
    print("dealer side time:                                ", Tdealer_pol_generation+Tdealer_encrypt_shares+Tdealer_proof+Tdealer_comm, " seconds")
    print("average party side time:                         ", avg_Tparty_comm, " seconds")
    print("total average time:                              ", Tdealer_pol_generation+Tdealer_encrypt_shares+Tdealer_proof+Tdealer_comm+avg_Tparty_comm, " seconds")
    print("total time for ", n, " parties:                  ", Tdealer_pol_generation+Tdealer_encrypt_shares+Tdealer_proof+Tdealer_comm+total_Tparty_comm, " seconds")
    print("------------------------verification stage------------------------")
    print("total average time:                              ", avg_Tparty_verify, " seconds")
    print("total time for ", n, " parties:                  ", total_Tparty_verify, " seconds")
    print("-----------------------reconstruction stage-----------------------")
    print("total average time:                              ", avg_Tparty_decrypt_share+avg_Tparty_proof+avg_Tparty_verify_decrypted+avg_Tparty_reconstruct, " seconds")
    print("total time for ", n, " parties:                  ", total_Tparty_decrypt_share+total_Tparty_proof+total_Tparty_verify_decrypted+total_Tparty_reconstruct, " seconds")
    

def test_pi_s(n):
    public_keys = [0 for _ in range(n)]
    parties = [0 for _ in range(n)]
    decrypted_shares_and_proofs = [0 for _ in range(n)]

    print("------------------------")
    print("Starting pi_s PVSS tests")
    print("------------------------")

    for i in range(1,n+1):
        p = Party(i, n)
        public_keys[i-1] = p.publish_public_key()
        parties[i-1] = p

    print("------------------------------------------------------")
    print("Party generation and public key publication successful")
    print("------------------------------------------------------")

    dealer = Dealer(public_keys, n)
    dealer.generate_polynomial()
    dealer.encrypted_shares = dealer.generate_encrypted_evals(dealer.f)
    dealer.pi_pdl()
    (enc_shares, pi_share) = dealer.broadcast_share_and_proof()

    print("---------------------------------------------------------------------")
    print("Dealer generation and encrypted shares + proof publication successful")
    print("---------------------------------------------------------------------")

    for i in range(n):
        p = parties[i]
        p.store_public_keys(public_keys)
        p.store_encrypted_shares_and_proof(enc_shares, pi_share)

        if p.verify_encrypted_shares():
            p.generate_decrypted_share()
            assert p.encrypted_shares[p.index-1] == fast_multiply(p.secret_key, p.dec_share)
            p.nizk_proof_for_dleq()
            decrypted_shares_and_proofs[i] = p.broadcast_decrypted_share_and_proof()
            assert len(decrypted_shares_and_proofs[i]) == 2

    print("---------------------------------------------")
    print("Party encrypted share verification successful")
    print("---------------------------------------------")
        
    for i in range(n):
        p = parties[i]
        p.store_decrypted_shares_and_proofs(decrypted_shares_and_proofs)
        assert len(p.decrypted_shares_and_proof) == n
        assert len(p.decrypted_shares_and_proof[0]) == 2

    print("---------------------------------------------")
    print("Party decrypted share distribution successful")
    print("---------------------------------------------")

    for i in range(n):
        p = parties[i]
        p.verify_decrypted_shares()
        assert len(p.valid_decrypted_shares) == n

    print("---------------------------------------------")
    print("Party decrypted share verification successful")
    print("---------------------------------------------")

    for i in range(n):
        p = parties[i]
        reconstructed_secret = p.reconstruct_secret()
        generator_secret = fast_multiply(global_secret, G)
        assert  generator_secret[0] == reconstructed_secret[0]

    print("--------------------------------------")
    print("Party secret reconstruction successful")
    print("--------------------------------------")

    print("All tests successful")


n = 10 #! Uneven values or values under 6 do not work. After further experimentation, it seems that the code works for an uneven number and even number with the same floor division by 2, then it does not, and for the next even number it works again.
benchmark_pi_s(n)
#test_pi_s(n)