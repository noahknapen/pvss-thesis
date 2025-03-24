import os

os.system('sage --preparse ../src/crypto99_evoting.sage')
os.system('mv ../src/crypto99_evoting.sage.py ./src_crypto99_evoting.py')

from src_crypto99_evoting import *

class Crypto99EvotingMetrics:
    def __init__( m, n):
        m = m
        n = n
        t = (n-1)//2
        public_keys = [0 for _ in range(n)]
        parties = [0 for _ in range(n)]
        dealers = [0 for _ in range(m)]
        secret_vote = 0
        enc_shares = [0 for _ in range(m)]
        dealer_proofs = [[0,0] for _ in range(m)]
        commitments = [0 for _ in range(m)]
        enc_votes = [0 for _ in range(m)]
        vote_proofs = [0 for _ in range(m)]
        dec_shares_and_proofs = [0 for _ in range(n)]
        b = BulletinBoard()

        for i in range(1,n+1):
            p = Tallier(i, m, n)
            parties[i-1] = p
            public_keys[i-1] = p.broadcast_public_key()

        casting_time = 0
        vote_verification_time = 0

        for i in range(m):
            d = Voter(public_keys, n)
            dealers[i] = d
            temp_time = time()
            [temp_commitments, encrypted_shares, dealer_proof, encrypted_vote, vote_proof] = d.share_stage()
            casting_time += time() - temp_time
            secret_vote += d.vote
            enc_shares[i] = encrypted_shares
            dealer_proofs[i] = dealer_proof
            commitments[i] = temp_commitments
            enc_votes[i] = encrypted_vote
            vote_proofs[i] = vote_proof

            temp_time2 = time()
            b.verify_adapted_dleqs(temp_commitments[0], encrypted_vote, vote_proof)
            vote_verification_time += time() - temp_time2
        
        share_verification_time = 0

        for i in range(n):
            p = parties[i]
            temp_time = time()
            dec_shares_and_proofs[i] = p.verification_stage(public_keys, commitments, enc_shares, dealer_proofs, enc_votes)
            share_verification_time += time() - temp_time
        
        tally_reconstruction_time = 0

        for i in range(n):
            p = parties[i]
            temp_time = time()
            assert secret_vote == p.reconstruction_stage(dec_shares_and_proofs)
            tally_reconstruction_time += time() - temp_time

        print("Schoenmakers99 evoting-----------------------------------------")
        print("Total time for ballot casting: ", casting_time, " seconds")
        print("Average vote verification time for ", m, " voters: ", vote_verification_time/m, " seconds")
        print("Average share verification time for ", n, " talliers: ", share_verification_time/n, " seconds")
        print("Average vote tallying time for ", t+1, " talliers: ", tally_reconstruction_time/(t+1), " seconds")
        print("---------------------------------------------------------------")

# Crypto99EvotingMetrics(9, 9)