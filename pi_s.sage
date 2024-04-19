from hashlib import sha256
from time import time
import os

os.system('sage --preparse GeneralPVSSEd25519.sage')
os.system('mv GeneralPVSSEd25519.sage.py GeneralPVSSEd25519.py')

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
        self.public_key = fast_multiply(self.secret_key, G)

    def verification_stage(self, public_keys, encrypted_shares, dealer_proof):
        self.store_public_keys(public_keys)
        self.store_encrypted_shares_and_proof(encrypted_shares, dealer_proof)

        if (self.verify_encrypted_shares()):
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
    
    def store_encrypted_shares_and_proof(self, encrypted_shares, dealer_proof):
        self.encrypted_shares = encrypted_shares # Assume shares are stored in order of party indices
        self.dealer_proof = dealer_proof
    
    def store_decrypted_shares_and_proofs(self, decrypted_shares_and_proofs):
        self.decrypted_shares_and_proof = decrypted_shares_and_proofs # Assume shares are stored in order of party indices

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
    
    def generate_decrypted_share(self):
        inv_priv_key = Integer(self.secret_key).inverse_mod(q)
        self.decrypted_share = fast_multiply(inv_priv_key, self.encrypted_shares[self.index-1])
    
    def dleq_share(self):
        r = Zq.random_element()
        c1 = fast_multiply(r, G)
        c2 = fast_multiply(r, self.decrypted_share)

        d = str(self.public_key) + str(",")
        d += str(self.encrypted_shares[self.index-1]) + str(",")
        d += str(c1) + str(",")
        d += str(c2)

        d = Integer(Zq(int(sha256(str(d).encode()).hexdigest(),16)))
        z = r + d*self.secret_key

        self.share_proof = [d,z]

    def verify_decrypted_shares(self):
        self.valid_decrypted_shares = []

        for i in range(self.t+1):
            if i == self.index-1:
                self.valid_decrypted_shares.append(self.decrypted_share)
                continue

            decrypted_share = self.decrypted_shares_and_proof[i][0]
            share_proof = self.decrypted_shares_and_proof[i][1]
            d = share_proof[0]
            z = share_proof[1]

            nominator1 = fast_multiply(z, G)
            nominator2 = fast_multiply(z, decrypted_share)

            denominator1 = fast_multiply(d, self.public_keys[i])
            denominator2 = fast_multiply(d, self.encrypted_shares[i])

            temp_d = str(self.public_keys[i]) + str(",")
            temp_d += str(self.encrypted_shares[i]) + str(",")
            temp_d += str(nominator1-denominator1) + str(",")
            temp_d += str(nominator2-denominator2)

            reconstructed_d = Integer(Zq(int(sha256(str(temp_d).encode()).hexdigest(),16)))

            if d == reconstructed_d:
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
            f -- the polynomial used for computing the shares
            encrypted_shares -- the encrypted shares of all parties, ordered by their index
            proof -- the proof for the encrypted shares for proving the correct encryption of the shares
        """
        self.public_keys = public_keys
        self.n = n
        self.t = (n-1)//2 #! Honest majority setting and only odd n values

    def share_stage(self):
        self.generate_polynomial()
        self.encrypted_shares = self.generate_encrypted_evals(self.f)
        self.dleq_pol()
        return self.broadcast_share_and_proof()
    
    def broadcast_share_and_proof(self):
        return self.encrypted_shares, self.proof
    
    def generate_polynomial(self):
        f = RP.random_element(degree=self.t)
        self.f = f

    def generate_encrypted_evals(self, pol):
        evals = [pol(x=i) for i in range(1, self.n+1)]
        enc_evals = [0 for _ in range(self.n)]
        
        for i in range(self.n):
            enc_evals[i] = fast_multiply(evals[i], self.public_keys[i])

        return enc_evals
    
    def dleq_pol(self):
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


def pi_s_stages(n):
    public_keys = [0 for _ in range(n)]
    parties = [0 for _ in range(n)]
    decrypted_shares_and_proofs = [0 for _ in range(n)]

    for i in range(1,n+1):
        p = Party(i, n)
        public_keys[i-1] = p.broadcast_public_key()
        parties[i-1] = p
    
    dealer = Dealer(public_keys, n)
    total_time_dealer = time()
    [encrypted_shares, dealer_proof] = dealer.share_stage()
    total_time_dealer = time() - total_time_dealer
    secret = fast_multiply(dealer.f(x=0), G)

    total_time_party_verification = time()

    for i in range(n):
        p = parties[i]
        decrypted_shares_and_proofs[i] = p.verification_stage(public_keys, encrypted_shares, dealer_proof)
    
    total_time_party_verification = time() - total_time_party_verification
    total_time_party_reconstruction = time()
    
    for i in range(n):
        p = parties[i]
        reconstructed_secret = p.reconstruction_stage(decrypted_shares_and_proofs)
        assert secret == reconstructed_secret
    
    total_time_party_reconstruction = time() - total_time_party_reconstruction

    print("Total time for dealer: ", total_time_dealer, " seconds")
    print("Total verification time for ", n, " parties: ", total_time_party_verification/n, " seconds") #TODO This includes ...
    print("Total reconstruction time for ", dealer.t+1, " parties: ", total_time_party_reconstruction/(dealer.t+1), " seconds") #TODO This includes ...

n = 33 #! n should be odd in majority honest setting
pi_s_stages(n)
