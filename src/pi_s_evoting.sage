from hashlib import sha256
from time import time
import os

os.system('sage --preparse ../lib/GeneralPVSSEd25519.sage')
os.system('mv ../lib/GeneralPVSSEd25519.sage.py ./GeneralPVSSEd25519.py')

from GeneralPVSSEd25519 import *

os.system('sage --preparse ../src/pi_s.sage')
os.system('mv ../src/pi_s.sage.py ./src_pi_s.py')

from src_pi_s import *

Zv = Integers(2)

class BulletinBoard:
    def verify_adapted_dleqs(self, C0, encrypted_vote, proof):
        a0 = proof[0]
        b0 = proof[1]
        a1 = proof[2]
        b1 = proof[3]
        c = proof[4]
        d0 = proof[5]
        r0 = proof[6]
        d1 = proof[7]
        r1 = proof[8]

        reconstructed_a0 = fast_multiply(r0, G) + fast_multiply(d0, C0)
        reconstructed_b0 = fast_multiply(r0, H) + fast_multiply(d0, encrypted_vote)
        reconstructed_a1 = fast_multiply(r1, G) + fast_multiply(d1, C0)
        reconstructed_b1 = fast_multiply(r1, H) + fast_multiply(d1, encrypted_vote - H)

        if not (c == d0 + d1 and a0 == reconstructed_a0 and b0 == reconstructed_b0 and a1 == reconstructed_a1 and b1 == reconstructed_b1):
            return False
        
        return True


class Tallier(Party):
    def __init__(self, index, m, n):
        super().__init__(index, n)
        self.m = m # Number of voters (dealers)
        self.n = n # Number of talliers (parties)
        self.t = (n-1)//2
        self.index = index # Index is a number between 1 and n
        self.secret_key = Zq.random_element()
        self.public_key = fast_multiply(self.secret_key, H)
        self.public_keys = [0 for _ in range(self.n)]
        self.encrypted_shares = [[0 for _ in range(self.n)] for _ in range(self.m)]
        self.dealer_proofs = [[0,0] for _ in range(self.m)]
        self.decrypted_share = 0
        self.share_proof = [0,0]
        self.decrypted_shares_and_proof = [0 for _ in range(self.n)]
        self.valid_decrypted_shares = [0 for _ in range(self.n)]
        self.h0s = [0 for _ in range(self.m)]

    def verification_stage(self, public_keys, encrypted_shares, dealer_proof, encrypted_votes):
        self.store_public_keys(public_keys)
        self.store_encrypted_shares_and_proof(encrypted_shares, dealer_proof)
        self.store_encrypted_votes(encrypted_votes)

        if self.verify_encrypted_shares():
            self.generate_accumulated_encrypted_shares()
            self.generate_decrypted_share()
            self.dleq_share()
            return self.broadcast_decrypted_share_and_proof()

    def reconstruction_stage(self, decrypted_shares_and_proofs):
        self.store_decrypted_shares_and_proofs(decrypted_shares_and_proofs)
        self.verify_decrypted_shares()
        secret = self.reconstruct_secret() 

        self.generate_accumulated_encrypted_vote()
        return self.reconstruct_accumulated_decrypted_vote(secret)

    def store_encrypted_shares_and_proofs(self, encrypted_shares_per_dealer, dealer_proofs_per_dealer):
        self.dealer_proofs = dealer_proofs_per_dealer
        self.encrypted_shares = encrypted_shares_per_dealer

    def store_decrypted_shares_and_proofs(self, decrypted_shares_and_proof):
        self.decrypted_shares_and_proof = decrypted_shares_and_proof
   
    def store_encrypted_votes(self, encrypted_votes):
        self.encrypted_votes = encrypted_votes
    
    def verify_encrypted_shares(self):
        for i in range(len(self.encrypted_shares)):
            h0 = self.encrypted_shares[i][0]
            self.encrypted_shares[i] = self.encrypted_shares[i][1:] #! h0 not longer necessary
            encrypted_shares = self.encrypted_shares[i]
            d = self.dealer_proofs[i][0]
            z = self.dealer_proofs[i][1]
            temp_d1, temp_d2 = str(h0) + ",", ""

            for i in range(self.n):
                temp_d1 = temp_d1 + str(encrypted_shares[i])+str(",")
                numerator = fast_multiply(z(x=i+1), self.public_keys[i]) 
                denominator = fast_multiply(d, self.encrypted_shares[i])
                temp_d2 = temp_d2 + str(numerator - denominator)+str(",") 
            
            temp_d1 = temp_d1[:-1]
            temp_d2 = temp_d2[:-1]
            reconstructed_d = Integer(Zq(int(sha256((str(temp_d1)+str(temp_d2)).encode()).hexdigest(),16)))

            return d == reconstructed_d 
        
    def generate_accumulated_encrypted_shares(self):
        acc_shares = [0 for _ in range(self.n)]
        for i in range(self.n):
            for j in range(self.m):
                acc_shares[i] += self.encrypted_shares[j][i]
        
        self.encrypted_shares = acc_shares

    def generate_accumulated_encrypted_vote(self):
        acc_vote = E(0)

        for i in range(self.m):
            acc_vote += self.encrypted_votes[i]
        
        self.acc_vote = acc_vote

    def reconstruct_accumulated_decrypted_vote(self, secret):

        for vote_tryout in range(self.m+1):
            if self.acc_vote - secret == fast_multiply(vote_tryout, H):
                return vote_tryout
        
        return "Failure"



class Voter(Dealer):
    """Adapt the system described in crypto99, but with the pi_s PVSS and thus without commitments"""
    def __init__(self, public_keys, n):
        super().__init__(public_keys, n)
        self.vote = None
        self.encrypted_vote = 0
        self.vote_proof = None
        self.temp_random_element = None
    
    def share_stage(self):
        self.generate_polynomial()
        self.encrypted_shares = self.generate_encrypted_evals(self.f)
        self.dleq_pol()
        self.generate_vote()
        self.dleq_vote()
        return [self.encrypted_shares, self.proof, self.encrypted_vote, self.vote_proof]
    
    def dleq_pol(self):
        K = E.random_point()
        while K.order() != q:
            K = E.random_point()

        self.encrypted_shares.insert(0, fast_multiply(self.f(x=0), K)) #? h0 could also be generated in dleq_vote, but I guess it is needed here to verify that it is also an evaluation of the same polynomial?

        r = RP.random_element(degree=self.t)
        self.temp_random_element = r(x=0)
        enc_r_evals = self.generate_encrypted_evals(r)

        temp_d1, temp_d2 = str(h0) + ",", ""

        for i in range(self.n):
            temp_d1 = temp_d1 + str(self.encrypted_shares[i])+str(",") #! This is not appended so only takes the last result!!!!
            temp_d2 = temp_d2 + str(enc_r_evals[i])+str(",")
        
        temp_d1 = temp_d1[:-1]
        temp_d2 = temp_d2[:-1]
        d = Integer(Zq(int(sha256((temp_d1+temp_d2).encode()).hexdigest(),16)))
        z = r + d*self.f

        self.proof = [d,z]

    def broadcast_vote_and_proof(self):
        return self.encrypted_vote, self.vote_proof

    def generate_vote(self):
        self.vote = Zq(Zv.random_element())
        s = self.f(x=0)
        self.encrypted_vote = fast_multiply(s+self.vote, H)

    # Proof for value U, showing that v element of 0 or 1 by showing: log_H(U) = log_G(G^global_secret) or log_H(U) = 1 + log_G(G^global_secret) 
    def dleq_vote(self):
        s = self.f(x=0)
        w = self.temp_random_element

        if self.vote == 0:
            a0 = fast_multiply(w, G)
            b0 = fast_multiply(w, H)

            r1 = Zq.random_element()
            d1 = Zq.random_element()
            a1 = fast_multiply(r1, G) + fast_multiply(d1, self.encrypted_shares[0])
            b1 = fast_multiply(r1, H) + fast_multiply(d1, self.encrypted_vote - fast_multiply(1, H))
        elif self.vote == 1:
            a1 = fast_multiply(w, G)
            b1 = fast_multiply(w, H)

            r0 = Zq.random_element()
            d0 = Zq.random_element()
            a0 = fast_multiply(r0, G) + fast_multiply(d0, self.encrypted_shares[0])
            b0 = fast_multiply(r0, H) + fast_multiply(d0, self.encrypted_vote)  #! fast_multiply(0, H) is not 1. Is that normal?
        
        c = Integer(Zq(int(sha256((str(self.encrypted_vote) + str(a0) + str(b0) + str(a1) + str(b1)).encode()).hexdigest(), 16)))

        if self.vote == 0:
            d0 = c - d1
            r0 = w - s*d0
        elif self.vote == 1:
            d1 = c - d0
            r1 = w - s*d1
        
        self.vote_proof = [a0, b0, a1, b1, c, d0, r0, d1, r1]