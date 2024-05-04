import os

os.system('sage --preparse ../src/pi_s_evoting.sage')
os.system('mv ../src/pi_s_evoting.sage.py ./src_pi_s_evoting.py')

from src_pi_s_evoting import *

class Pi_sEvotingMetrics:
    def __init__(self, m, n):
        self.m = m
        self.n = n
        self.t = (n-1)//2

        public_keys = [0 for _ in range(n)]
        parties = [0 for _ in range(n)]
        dealers = [0 for _ in range(m)]
        secret_vote = 0
        enc_shares = [0 for _ in range(m)]
        dealer_proofs = [[0,0] for _ in range(m)]
        enc_votes = [0 for _ in range(m)]
        vote_proofs = [0 for _ in range(m)]
        dec_shares_and_proofs = [0 for _ in range(n)]
        b = BulletinBoard()

        for i in range(1,n+1):
            p = Tallier(i, m, n)
            parties[i-1] = p
            public_keys[i-1] = p.broadcast_public_key()
        
        self.casting_time = 0
        self.vote_verification_time = 0

        for i in range(m):
            d = Voter(public_keys, n)
            dealers[i] = d
            temp_time = time()
            [encrypted_shares, dealer_proof, encrypted_vote, vote_proof] = d.share_stage()
            self.casting_time += time() - temp_time
            secret_vote += d.vote
            enc_shares[i] = encrypted_shares
            dealer_proofs[i] = dealer_proof
            enc_votes[i] = encrypted_vote
            vote_proofs[i] = vote_proof

            temp_time2 = time()
            b.verify_adapted_dleqs(encrypted_shares[0], encrypted_vote, vote_proof)
            self.vote_verification_time += time() - temp_time2

        self.share_verification_time = 0
        
        for i in range(n):
            p = parties[i]
            temp_time = time()
            dec_shares_and_proofs[i] = p.verification_stage(public_keys, list(enc_shares), dealer_proofs, enc_votes)
            self.share_verification_time += time() - temp_time

        self.tally_reconstruction_time = 0
        
        for i in range(n):
            p = parties[i]
            temp_time = time()
            assert secret_vote == p.reconstruction_stage(dec_shares_and_proofs)
            self.tally_reconstruction_time += time() - temp_time

        print("Total time for ballot casting: ", self.casting_time, " seconds")
        print("Average vote verification time for ", self.m, " voters: ", self.vote_verification_time/m, " seconds")
        print("Average share verification time for ", self.n, " talliers: ", self.share_verification_time/n, " seconds")
        print("Average vote tallying time for ", self.t+1, " talliers: ", self.tally_reconstruction_time/(self.t+1), " seconds")
