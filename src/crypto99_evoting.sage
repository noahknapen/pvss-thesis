from hashlib import sha256
from time import time
import os

os.system('sage --preparse ../lib/GeneralPVSSEd25519.sage')
os.system('mv ../lib/GeneralPVSSEd25519.sage.py ./GeneralPVSSEd25519.py')

from GeneralPVSSEd25519 import *

os.system('sage --preparse ../src/crypto99.sage')
os.system('mv ../src/crypto99.sage.py ./src_crypto99.py')

from src_crypto99 import *

Zv = Integers(2)

class BulletinBoard:
    def verify_adapted_dleqs(self, C0, encrypted_votes, proofs):
        for i in range(len(encrypted_votes)):
            U = encrypted_votes[i]
            args = proofs[i]
            a0 = args[0]
            b0 = args[1]
            a1 = args[2]
            b1 = args[3]
            c = args[4]
            d0 = args[5]
            r0 = args[6]
            d1 = args[7]
            r1 = args[8]

            reconstructed_a0 = fast_multiply(r0, G) + fast_multiply(d0, C0)
            reconstructed_b0 = fast_multiply(r0, H) + fast_multiply(d0, U)
            reconstructed_a1 = fast_multiply(r1, G) + fast_multiply(d1, C0)
            reconstructed_b1 = fast_multiply(r1, H) + fast_multiply(d1, U - H)

        #if not (c == d0 + d1 and a0 == reconstructed_a0 and b0 == reconstructed_b0 and a1 == reconstructed_a1 and b1 == reconstructed_b1):
        #    return False
        assert c == d0 + d1
        assert a0 == reconstructed_a0
        assert b0 == reconstructed_b0
        assert a1 == reconstructed_a1
        assert b1 == reconstructed_b1
        
        return True


class Tallier(Party):
    def __init__(self, index, m, n):
        super().__init__(index, n)
        self.m = m # Number of voters (dealers)
        self.n = n # Number of talliers (parties)
        self.t = n//2-1
        self.index = index # Index is a number between 1 and n
        self.secret_key = Zq.random_element()
        self.public_key = fast_multiply(self.secret_key, H)
        self.public_keys = [0 for _ in range(self.n)]
        self.commitments = [[0 for _ in range(self.t)] for _ in range(self.m)]
        self.encrypted_shares = [[0 for _ in range(self.n)] for _ in range(self.m)]
        self.dealer_proofs = [[0,0] for _ in range(self.m)]
        self.decrypted_share = 0
        self.share_proof = [0,0]
        self.decrypted_shares_and_proof = [0 for _ in range(self.n)]
        self.valid_decrypted_shares = [0 for _ in range(self.n)]

    def verification_stage(self, public_keys, commitments, encrypted_shares, dealer_proof, encrypted_votes):
        self.store_public_keys(public_keys)
        self.store_commitments(commitments)
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

    def store_encrypted_shares_and_proof(self, encrypted_shares_per_party, dealer_proofs):
        self.dealer_proofs = dealer_proofs
        self.encrypted_shares = encrypted_shares_per_party

    def store_decrypted_shares_and_proofs(self, decrypted_shares_and_proof):
        self.decrypted_shares_and_proof = decrypted_shares_and_proof
   
    def store_encrypted_votes(self, encrypted_votes):
        self.encrypted_votes = encrypted_votes
    
    def verify_encrypted_shares(self):
        for i in range(len(self.encrypted_shares)):
            encrypted_shares = self.encrypted_shares[i]
            commitments = self.commitments[i]
            c = self.dealer_proofs[i][0]
            r_list = self.dealer_proofs[i][1]

            reconstructed_gen_evals = [0 for _ in range(self.n)]
            reconstructed_gen_eval_str = ""
            enc_eval_str = ""

            for i in range(self.n):
                enc_eval_str += str(encrypted_shares[i]) + str(",")
                for j in range(self.t):
                        reconstructed_gen_evals[i] += fast_multiply((i+1)^j, commitments[j])
                        
                reconstructed_gen_eval_str += str(reconstructed_gen_evals[i]) + str(",")
            
            enc_eval_str = enc_eval_str[:-1]
            reconstructed_gen_eval_str = reconstructed_gen_eval_str[:-1]
            
            reconstructed_a1_str = ""
            reconstructed_a2_str = ""

            for i in range(self.n):
                reconstructed_a1_str += str(fast_multiply(r_list[i], G) + fast_multiply(c, reconstructed_gen_evals[i])) + str(",")
                reconstructed_a2_str += str(fast_multiply(r_list[i], self.public_keys[i]) + fast_multiply(c, encrypted_shares[i])) + str(",")
            
            reconstructed_a1_str = reconstructed_a1_str[:-1]
            reconstructed_a2_str = reconstructed_a2_str[:-1]

            reconstructed_c = Integer(Zq(int(sha256(str(reconstructed_gen_eval_str + enc_eval_str + reconstructed_a1_str + reconstructed_a2_str).encode()).hexdigest(), 16)))

            return c == reconstructed_c
        
    def generate_accumulated_encrypted_shares(self):
        self.acc_shares = [0 for _ in range(self.m)]
        for m_i in range(len(self.encrypted_shares)):
            for n_i in range(len(self.encrypted_shares[m_i])):
                self.acc_shares[m_i] += self.encrypted_shares[m_i][n_i]
        
        self.encrypted_shares = self.acc_shares


    def generate_accumulated_encrypted_vote(self):
        acc_vote = E(0)

        for i in range(self.m):
            acc_vote += self.encrypted_votes[i]
        
        self.acc_vote = acc_vote

    def reconstruct_accumulated_decrypted_vote(self, secret):

        for vote_tryout in range(self.m+1):
            if self.acc_vote - secret == fast_multiply(vote_tryout, H):
                return vote_tryout
        
        return False


class Voter(Dealer):
    def __init__(self, public_keys, n):
        super().__init__(public_keys, n)
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
        return [self.commitments, self.encrypted_shares, self.proof, self.encrypted_vote, self.vote_proof]

    def broadcast_vote_and_proof(self):
        return self.encrypted_vote, self.vote_proof

    def generate_vote(self):
        self.vote = Zq(Zv.random_element())
        s = self.f(x=0)
        self.encrypted_vote = fast_multiply(s+self.vote, H)

    # Proof for value U, showing that v element of 0 or 1 by showing: log_H(U) = log_G(G^global_secret) or log_H(U) = 1 + log_G(G^global_secret) 
    def dleq_vote(self):
        C0 = self.commitments[0]
        s = self.f(x=0)
        w = Zq.random_element()

        if self.vote == 0:
            print("vote is 0")
            a0 = fast_multiply(w, G)
            b0 = fast_multiply(w, H)

            r1 = Zq.random_element()
            d1 = Zq.random_element()
            a1 = fast_multiply(r1, G) + fast_multiply(d1, C0)
            b1 = fast_multiply(r1, H) + fast_multiply(d1, self.encrypted_vote - fast_multiply(1, H))
        elif self.vote == 1:
            print("vote is 1")
            a1 = fast_multiply(w, G)
            b1 = fast_multiply(w, H)

            r0 = Zq.random_element()
            d0 = Zq.random_element()
            a0 = fast_multiply(r0, G) + fast_multiply(d0, C0)
            b0 = fast_multiply(r0, H) + fast_multiply(d0, self.encrypted_vote)  #! fast_multiply(0, H) is not 1. Is that normal?
        
        c = Integer(Zq(int(sha256((str(C0) + str(self.encrypted_vote) + str(a0) + str(b0) + str(a1) + str(b1)).encode()).hexdigest(), 16)))

        if self.vote == 0:
            d0 = c - d1
            r0 = w - s*d0
        elif self.vote == 1:
            d1 = c - d0
            r1 = w - s*d1
        
        self.vote_proof = [a0, b0, a1, b1, c, d0, r0, d1, r1]
