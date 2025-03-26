import os

os.system('sage --preparse ../src/pi_s_evoting.sage')
os.system('mv ../src/pi_s_evoting.sage.py ./src_pi_s_evoting.py')

from src_pi_s_evoting import *

class Pi_sEvotingMetrics:
    def run( m, n):
        m = m
        n = n
        t = (n-1)//2

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
        
        vote_verification_time = 0

        for i in range(m):
            d = Voter(public_keys, n)
            dealers[i] = d
            if i == 0:
                temp_time = time()
                [encrypted_shares, dealer_proof, encrypted_vote, vote_proof] = d.share_stage()
                casting_time = time() - temp_time
            else:
                [encrypted_shares, dealer_proof, encrypted_vote, vote_proof] = d.share_stage()
            secret_vote += d.vote
            enc_shares[i] = encrypted_shares
            dealer_proofs[i] = dealer_proof
            enc_votes[i] = encrypted_vote
            vote_proofs[i] = vote_proof

            if i == 0:
                temp_time = time()
                b.verify_adapted_dleqs(encrypted_shares[0], encrypted_vote, vote_proof)
                vote_verification_time = time() - temp_time

        for i in range(n):
            p = parties[i]
            temp_time = time()
            p.store_public_keys(public_keys)
            p.store_encrypted_shares_and_proofs(list(enc_shares), dealer_proofs)
            p.store_encrypted_votes(enc_votes)
            if i == 0:
                temp_time = time()
                p.verify_encrypted_shares()
                share_verification_time = time() - temp_time

            dec_shares_and_proofs[i] = p.verification_stage(public_keys, list(enc_shares), dealer_proofs, enc_votes)
            

        tally_reconstruction_time = 0
        
        for i in range(n):
            p = parties[i]
            temp_time = time()
            reconstructed_secret = p.reconstruction_stage(dec_shares_and_proofs)
            print("secret: " + str(secret_vote))
            print("reconstructed secret: " + str(reconstructed_secret))
            assert secret_vote == reconstructed_secret
            tally_reconstruction_time += time() - temp_time
        
        return (casting_time, vote_verification_time+share_verification_time, tally_reconstruction_time) 

        #print("pi_s evoting---------------------------------------------------")
        #print("Total time for ballot casting: ", casting_time, " seconds")
        #print("Average vote verification time for ", m, " voters: ", vote_verification_time/m, " seconds")
        #print("Average share verification time for ", n, " talliers: ", share_verification_time/n, " seconds")
        #print("Average vote tallying time for ", t+1, " talliers: ", tally_reconstruction_time/(t+1), " seconds")
        #print("---------------------------------------------------------------")
