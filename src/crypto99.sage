from hashlib import sha256
from time import time
import os

os.system('sage --preparse ../lib/GeneralPVSSEd25519.sage')
os.system('mv ../lib/GeneralPVSSEd25519.sage.py ./GeneralPVSSEd25519.py')

from GeneralPVSSEd25519 import *


class Party:
    def __init__(self, index, n):
        """The constructor of the Party class

        Class variables:
            n -- the number of parties
            t -- the threshold value for the number of malicious parties without loss of functionality
            index -- the index of the party
            secret_key -- the secret key of the party
            public_key -- the public key of the party
            public_keys -- the public keys of all parties, ordered by their index
            commitments -- the commitments of the dealer, ordered by their index
            encrypted_shares -- the encrypted shares of all parties, ordered by their index
            dealer_proof -- the proof received from the dealer for proving the correct encryption of the shares
            decrypted_share -- the decrypted share of the party
            share_proof -- the proof for the decrypted share for proving the correct decryption of the share
            decrypted_shares_and_proof -- the decrypted shares and proofs of all parties, ordered by their index
            valid_decrypted_shares -- the valid decrypted shares of all parties, ordered by their index
        """
        self.n = n
        self.t = (n-1)//2 #! Honest majority setting and only odd n values
        self.index = index # Index is a number between 1 and n
        self.secret_key = Zq.random_element()
        self.public_key = fast_multiply(self.secret_key, H)

    def verification_stage(self, public_keys, commitments, encrypted_shares, dealer_proof):
        #self.store_public_keys(public_keys)
        #self.store_commitments(commitments)
        #self.store_encrypted_shares_and_proof(encrypted_shares, dealer_proof)

        #if self.verify_encrypted_shares():
        #    self.generate_decrypted_share()
        #    self.dleq_share()
        #    return self.broadcast_decrypted_share_and_proof()

        self.generate_decrypted_share()
        self.dleq_share()
        return self.broadcast_decrypted_share_and_proof()

    def reconstruction_stage(self, decrypted_shares_and_proofs):
        self.store_decrypted_shares_and_proofs(decrypted_shares_and_proofs)
        self.verify_decrypted_shares()
        return self.reconstruct_secret()
    
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
            for j in range(self.t+1):
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
        self.valid_decrypted_shares = []

        for i in range(self.t+1):
            if i == self.index-1:
                self.valid_decrypted_shares.append(self.decrypted_share)
                continue

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
                self.valid_decrypted_shares.append(decrypted_share)
            else:
                self.valid_decrypted_shares.append(0)

    def lambda_func(self, i):
        lambda_i = Zq(1)
        for j in range(1, self.t+2):
            if j != i:
                lambda_i *= Zq(j)/(Zq(j)-Zq(i))
        
        return lambda_i

    def reconstruct_secret(self):
        # From https://github.com/darkrenaissance/darkfi/blob/master/script/research/pvss/pvss.sage
        reconstructed_secret = E(0)

        for i in range(len(self.valid_decrypted_shares)): # w.l.o.g. we take the first t+1 valid shares, but randomly chosen t+1 shares can also be chosen
            if self.valid_decrypted_shares[i] != 0:
                reconstructed_secret += fast_multiply(self.lambda_func(i+1), self.valid_decrypted_shares[i])

        return reconstructed_secret
 

class Dealer:
    def __init__(self, public_keys, n):
        """The constructor of the Dealer class

        Class variables:
            public_keys -- the public keys of all parties, ordered by their index
            n -- the number of parties
            t -- the threshold value for the number of malicious parties without loss of functionality
            commitments -- the commitments of the dealer, ordered by their index
            f -- the polynomial used for computing the shares
            encrypted_shares -- the encrypted shares of all parties, ordered by their index
            proof -- the proof for the encrypted shares for proving the correct encryption of the shares
        """
        self.public_keys = public_keys
        self.n = n
        self.t = (n-1)//2 #! Honest majority setting and only odd n values
    
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
        f = RP.random_element(degree=self.t)
        self.f = f
    
    def generate_commitments(self):
        coefs = self.f.coefficients(sparse=False)
        self.commitments = []

        for i in range(self.t+1):
            self.commitments.append(fast_multiply(coefs[i], G))

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
