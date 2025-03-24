import os

os.system('sage --preparse ../src/crypto99.sage')
os.system('mv ../src/crypto99.sage.py ./src_crypto99.py')

from src_crypto99 import *

#############
# Variables #
#############

# n = 33 # Number of parties

#################
# Crypto99 PVSS #
#################

class Crypto99Metrics:
    def run(n):
        t = (n-1)//2
        public_keys = [0 for _ in range(n)]
        parties = [0 for _ in range(n)]
        decrypted_shares_and_proofs = [0 for _ in range(n)]

        for i in range(1,n+1):
            p = Party(i, n)
            public_keys[i-1] = p.broadcast_public_key()
            parties[i-1] = p

        dealer = Dealer(public_keys, n)
        temp_time = time()
        [commitments, encrypted_shares, dealer_proof] = dealer.share_stage()
        total_time_dealer = time() - temp_time
        secret = fast_multiply(dealer.f(x=0), H)

        for i in range(n):
            p = parties[i]
            p.store_public_keys(public_keys)
            p.store_commitments(commitments)
            p.store_encrypted_shares_and_proof(encrypted_shares, dealer_proof)
            if i == 0:
                temp_time = time()
                p.verify_encrypted_shares()
                total_time_party_verification = time() - temp_time
            decrypted_shares_and_proofs[i] = p.verification_stage(public_keys, commitments, encrypted_shares, dealer_proof)

        total_time_party_reconstruction = time()

        for i in range(n):
            p = parties[i]
            
            reconstructed_secret = p.reconstruction_stage(decrypted_shares_and_proofs)
            assert secret == reconstructed_secret

        total_time_party_reconstruction = time() - total_time_party_reconstruction

        return(total_time_dealer, total_time_party_verification)

        #print("Schoenmakers99-------------------------------------------------")
        #print("Total time for dealer: ", total_time_dealer, " seconds")
        #print("Average verification time for ", n, " parties: ", total_time_party_verification/n, " seconds")
        #print("Average reconstruction time for ", dealer.t+1, " parties: ", total_time_party_reconstruction/(dealer.t+1), " seconds")
        #print("---------------------------------------------------------------")


# metrics = Crypto99Metrics(n)