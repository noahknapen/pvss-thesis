import os

os.system('sage --preparse ../src/ACNS.sage')
os.system('mv ../src/ACNS.sage.py ./src_ACNS.py')

from src_ACNS import *

#############
# Variables #
#############

n = 33 # Number of parties #! n should be odd in majority honest setting

#############
# ACNS PVSS #
#############

class ACNSMetrics:
    def __init__(self, n):
        self.n = n
        self.t = (n-1)//2
        public_keys = [0 for _ in range(n)]
        parties = [0 for _ in range(n)]
        decrypted_shares_and_proofs = [0 for _ in range(n)]

        for i in range(1,n+1):
            p = Party(i, n)
            public_keys[i-1] = p.broadcast_public_key()
            parties[i-1] = p

        dealer = Dealer(public_keys, n)
        self.total_time_dealer = time()
        [commitments, encrypted_shares, dealer_proof] = dealer.share_stage()
        self.total_time_dealer = time() - self.total_time_dealer
        secret = fast_multiply(dealer.f(x=0), G)

        self.total_time_party_verification = time()

        for i in range(n):
            p = parties[i]
            decrypted_shares_and_proofs[i] = p.verification_stage(public_keys, commitments, encrypted_shares, dealer_proof)

        self.total_time_party_verification = time() - self.total_time_party_verification
        self.total_time_party_reconstruction = time()

        for i in range(n):
            p = parties[i]
            reconstructed_secret = p.reconstruction_stage(decrypted_shares_and_proofs)
            assert secret == reconstructed_secret

        self.total_time_party_reconstruction = time() - self.total_time_party_reconstruction

        print("ACNS-----------------------------------------------------------")
        print("Average time for dealer: ", self.total_time_dealer, " seconds")
        print("Average verification time for ", n, " parties: ", self.total_time_party_verification/n, " seconds") #TODO This includes ...
        print("Average reconstruction time for ", dealer.t+1, " parties: ", self.total_time_party_reconstruction/(dealer.t+1), " seconds") #TODO This includes ...
        print("---------------------------------------------------------------")

#metrics = ACNSMetrics(n)